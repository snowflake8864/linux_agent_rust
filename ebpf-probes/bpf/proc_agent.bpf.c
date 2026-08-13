#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ===== Maps (independent for proc_agent) =====

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u8);
} feature_switches SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u8);
} global_modes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} event_ringbuf SEC(".maps");

struct path_buffer {
    char buf[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buffer);
} path_scratch SEC(".maps");

struct proc_key {
    __u64 dev;
    __u64 inode;
};

struct proc_rule {
    __u8 action;
    __u8 mode;
    __u8 reserved[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct proc_key);
    __type(value, struct proc_rule);
} proc_rules SEC(".maps");

struct pattern_key {
    char pattern[32];
};

struct pattern_rule {
    __u8 action;
    __u8 mode;
    __u8 reserved[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct pattern_key);
    __type(value, struct pattern_rule);
} proc_patterns SEC(".maps");

// Agent PID: used by task_kill hook to allow the agent itself to send
// signals (e.g. to its own children) while blocking external kill signals.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} agent_pids SEC(".maps");

// Extensible protected PIDs: TGIDs that cannot be killed by external processes.
// Populated by userspace when self_protect_switch is on.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} protected_pids SEC(".maps");

// ===== Constants =====
#define EVENT_PROC 2
#define EVENT_PROC_UNKNOWN 3  // 不明进程
// Mode constants (match Rust: mode.as_u8() + 1)
// Rust: Monitor=0, Protect=1 -> +1 -> Monitor=1, Protect=2
#define MODE_MONITOR 1
#define MODE_PROTECT 2
#define ACTION_ALLOW 0
#define ACTION_DENY 1
#define FEATURE_PROC 1

#ifndef EPERM
#define EPERM 1
#endif

// ===== Helper Structures =====
struct unified_event {
    __u8 type;
    union {
        struct {
            __u32 pid;
            __u32 uid;
            __u8 blocked;
            char comm[16];
            char path[64];
        } monitor;
        char msg[89];
    };
};

// ===== Helper Functions =====

static __always_inline void send_monitor_event(__u8 type, const char *path, __u8 blocked) {
    struct unified_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->type = type;
    e->monitor.pid = bpf_get_current_pid_tgid() >> 32;
    e->monitor.uid = bpf_get_current_uid_gid();
    e->monitor.blocked = blocked;

    if (path) {
        __builtin_memcpy(e->monitor.path, path, sizeof(e->monitor.path));
    }

    bpf_get_current_comm(e->monitor.comm, sizeof(e->monitor.comm));
    bpf_ringbuf_submit(e, 0);
}

static __always_inline __u64 kernel_dev_to_user(dev_t kdev) {
    unsigned int major = (kdev >> 20) & 0xFFF;
    unsigned int minor = kdev & 0xFFFFF;
    if (minor < 256) {
        return ((__u64)major << 8) | minor;
    } else {
        return ((__u64)major << 20) | minor;
    }
}

static __always_inline int feature_enabled(__u32 feature_idx) {
    __u8 *enabled = bpf_map_lookup_elem(&feature_switches, &feature_idx);
    return enabled && *enabled;
}

static __always_inline __u8 resolve_mode(__u8 rule_mode, __u32 feature_idx) {
    if (rule_mode != 0) {
        return rule_mode;
    }
    __u8 *global = bpf_map_lookup_elem(&global_modes, &feature_idx);
    if (global && *global == MODE_PROTECT) {
        return MODE_PROTECT;
    }
    return MODE_MONITOR;
}

// Returns 1 if current process TGID matches the agent PID stored in
// agent_pids[0]. Used by task_kill to let the agent manage its own
// children while blocking external kill attempts.
static __always_inline int is_agent_process() {
    __u32 key = 0;
    __u32 *agent_pid = bpf_map_lookup_elem(&agent_pids, &key);
    if (!agent_pid || *agent_pid == 0) {
        return 0;
    }
    __u32 my_tgid = bpf_get_current_pid_tgid() >> 32;
    return my_tgid == *agent_pid ? 1 : 0;
}

// Returns 1 if the given TGID is in the protected_pids set.
// Self-protection is governed solely by the protected_pids map, populated by
// userspace when self_protect_switch is on and cleared when it is turned off.
// This makes the agent killable again once the server disables self-protect.
static __always_inline int is_protected_pid(__u32 tgid) {
    __u8 *entry = bpf_map_lookup_elem(&protected_pids, &tgid);
    return entry != NULL ? 1 : 0;
}

// ===== LSM Hooks =====

// Protect agent and designated processes from being killed by external processes.
// Signals 9 (SIGKILL), 15 (SIGTERM), 19 (SIGSTOP) are blocked for protected PIDs
// unless the sender is the agent process itself.
SEC("lsm/task_kill")
int BPF_PROG(enforce_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    // Only block destructive signals
    if (sig != 9 && sig != 15 && sig != 19) {
        return 0;
    }

    // Agent process can send any signal (needed to manage child processes)
    if (is_agent_process()) {
        return 0;
    }

    // Read target TGID
    __u32 target_tgid = BPF_CORE_READ(p, tgid);

    if (is_protected_pid(target_tgid)) {
        bpf_printk("[PROC] task_kill BLOCKED: sig=%d target_tgid=%u", sig, target_tgid);
        return -EPERM;
    }

    return 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(enforce_bprm_check_security, struct linux_binprm *bprm) {
    if (!feature_enabled(FEATURE_PROC)) {
        return 0;
    }

    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *buf = scratch->buf;
    __builtin_memset(buf, 0, 256);

    if (bpf_probe_read_kernel_str(buf, 256, bprm->filename) < 0) return 0;

    // Get the file's inode for proc_rules lookup
    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file) return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) return 0;

    struct proc_key key;
    dev_t kdev = BPF_CORE_READ(inode, i_sb, s_dev);
    key.dev = kernel_dev_to_user(kdev);
    key.inode = BPF_CORE_READ(inode, i_ino);

    // Try inode-based rule first
    struct proc_rule *rule = bpf_map_lookup_elem(&proc_rules, &key);

    // Fallback to pattern-based rules
    if (!rule) {
        struct pattern_key pkey = {};
        __builtin_memcpy(pkey.pattern, buf, sizeof(pkey.pattern));
        struct pattern_rule *prule = bpf_map_lookup_elem(&proc_patterns, &pkey);
        if (prule) {
            __u8 effective_mode = resolve_mode(prule->mode, FEATURE_PROC);
            if (effective_mode == MODE_PROTECT && prule->action == ACTION_DENY) {
                bpf_printk("[PROC] BLOCKED (pattern): %s", buf);
                send_monitor_event(EVENT_PROC, buf, 1);
                return -EPERM;
            }
            send_monitor_event(EVENT_PROC, buf, 0);
            return 0;
        }
    }

    // Check basename pattern
    if (!rule) {
        const char *last_slash = NULL;
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            if (buf[i] == '/') last_slash = &buf[i];
            if (buf[i] == '\0') break;
        }
        if (last_slash) {
            struct pattern_key pkey = {};
            __builtin_memcpy(pkey.pattern, last_slash + 1, sizeof(pkey.pattern));
            struct pattern_rule *prule = bpf_map_lookup_elem(&proc_patterns, &pkey);
            if (prule) {
                __u8 effective_mode = resolve_mode(prule->mode, FEATURE_PROC);
                if (effective_mode == MODE_PROTECT && prule->action == ACTION_DENY) {
                    bpf_printk("[PROC] BLOCKED (basename): %s", buf);
                    send_monitor_event(EVENT_PROC, buf, 1);
                    return -EPERM;
                }
                send_monitor_event(EVENT_PROC, buf, 0);
                return 0;
            }
        }
    }

    if (rule) {
        // 命中规则：区分白/黑名单
        if (rule->action == ACTION_ALLOW) {
            // 白名单 → 放行，不产生事件
            return 0;
        }
        // blacklist (ACTION_DENY)
        __u8 effective_mode = resolve_mode(rule->mode, FEATURE_PROC);
        if (effective_mode == MODE_PROTECT) {
            bpf_printk("[PROC] BLOCKED(black): %s", buf);
            send_monitor_event(EVENT_PROC, buf, 1);
            return -EPERM;
        }
        bpf_printk("[PROC] MONITOR(black): %s", buf);
        send_monitor_event(EVENT_PROC, buf, 0);
        return 0;
    }

    // unknown process - use global_modes
    {
        __u8 effective_mode = resolve_mode(0, FEATURE_PROC);
        if (effective_mode == MODE_PROTECT) {
            bpf_printk("[PROC] BLOCKED(unknown): %s", buf);
            send_monitor_event(EVENT_PROC_UNKNOWN, buf, 1);
            return -EPERM;
        }
        // monitor: silent, only ringbuf
        send_monitor_event(EVENT_PROC_UNKNOWN, buf, 0);
    }

    return 0;
}
