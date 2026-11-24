#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ===== Maps (independent for file_agent) =====

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

struct event_meta {
    __u32 parent_dev;
    __u8 has_full;
    __u8 _pad[3];
    __u64 parent_ino;
};

struct path_buffer {
    char buf[256];
    char full[256];
    struct event_meta meta;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buffer);
} path_scratch SEC(".maps");

struct dir_key {
    __u64 dev;
    __u64 inode;
};

struct dir_policy {
    __u8 ops_mask;
    __u8 action;
    __u8 mode;
    __u8 recursive;
    __u8 filter_type;
    __u8 suffix_count;
    __u8 reserved[2];
    __u8 suffixes[8][8];
    __u8 exact_filename[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dir_key);
    __type(value, struct dir_policy);
} dir_policies SEC(".maps");

// Agent PID allowlist: when self_protect_switch is on, agent's own
// file operations (e.g. writing config/net_info.ini) should not be
// blocked by the self-protection dir_policy entries.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} agent_pids SEC(".maps");

// 自保专用目录保护规则值：与 DPI dir_policies（防篡改/勒索）完全独立。
// whole_dir=1 表示保护整个目录子树；否则按 prefixes[] 匹配叶子文件名前缀。
struct self_protect_rule {
    __u8 whole_dir;
    __u8 prefix_count;
    char prefixes[2][16];   // 如 "osec." / "agent_manager."
};

// 自保专用目录保护表：write_self_protection 在自保开启时填充、关闭时清空。
// 不依赖 file_switch，也不与 dir_policies 混用。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct dir_key);
    __type(value, struct self_protect_rule);
} self_protect_dirs SEC(".maps");

// ===== 勒索防护（exiport / lesuo） =====
// 与 dir_policies 的目录 inode 策略不同，勒索防护是“全局文件后缀”规则，
// 对应驱动 dpi 的 type=1（lesuo）+ action=3（include file）。
#define MAX_EXTORT_RULES 32
#define MAX_EXTORT_SUFFIX 16

// 全局后缀表：key 为“最后一个 '.' 之后、右侧补 0 到 16 字节”的后缀，
// value 为规则索引（信任位图位号）。BPF 里只做一次 hash 查找，避免遍历规则表。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[MAX_EXTORT_SUFFIX]);
    __type(value, __u32);
} extort_suffixes SEC(".maps");

// 目录型勒索规则：规则目录及其子目录（用户态预展开）的 inode → 规则索引。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dir_key);
    __type(value, __u32);
} extort_dirs SEC(".maps");

// [0]=启用(EXTORTION_SWITCH), [1]=拦截模式(EXTORTION_PROTECT)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u8);
} extort_switches SEC(".maps");

// 勒索信任进程：key 为进程可执行文件 (dev,inode)，value 为允许的规则索引位图。
// 由用户态把 TPNC 中的 MD5 翻译成 inode 后写入；驱动侧是 find_true_process(md5, tpnc, 99)。
struct extort_proc_key {
    __u32 dev;
    __u64 inode;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct extort_proc_key);
    __type(value, __u32);
} extort_trusted SEC(".maps");

// ===== Constants =====
#define EVENT_FILE 1
#define EVENT_SELF_PROTECT 4
#define EVENT_EXTORT 5
// Mode constants (match Rust: mode.as_u8() + 1)
// Rust: Monitor=0, Protect=1 -> +1 -> Monitor=1, Protect=2
#define MODE_MONITOR 1
#define MODE_PROTECT 2
#define ACTION_ALLOW 0
#define ACTION_DENY 1
#define FEATURE_FILE 0
#define FILTER_NONE 0
#define FILTER_SUFFIX 1
#define FILTER_EXCLUDE_SUFFIX 2
#define FILTER_EXACT_MATCH 3

#ifndef O_CREAT
#define O_CREAT       0x40
#define O_RDONLY      0x00
#define O_WRONLY      0x01
#define O_RDWR        0x02
#define O_ACCMODE     0x03
#define O_TRUNC       0x200
#endif

#ifndef S_IFMT
#define S_IFMT        0xF000
#define S_IFDIR       0x4000
#endif

#ifndef EPERM
#define EPERM 1
#endif

#define OP_READ    1
#define OP_WRITE   2
#define OP_MODIFY  4
#define OP_CREATE  8
#define OP_DELETE  16
#define OP_RENAME  32

// include/linux/fs.h: set on file->f_mode by lookup_open() when this open
// actually created the file. Stable across kernels (4.19-6.12: 1 << 20).
#ifndef FMODE_CREATED
#define FMODE_CREATED 0x100000
#endif

// ===== Helper Structures =====
struct unified_event {
    __u8 type;      // EVENT_FILE(1)
    __u8 op_type;   // OP_READ|OP_WRITE|OP_CREATE|OP_DELETE bitmask
    __u8 blocked;   // 1=拦截, 0=监控
    __u8 _pad;      // 对齐到 32bit
    __u32 pid;
    __u32 uid;
    __u32 parent_dev;   // 父目录 dev（用户态编码），用于 userspace 补全路径
    __u32 _pad2;
    __u64 parent_ino;   // 父目录 inode
    __u32 exe_dev;      // 当前进程可执行文件 dev
    __u32 _pad3;
    __u64 exe_ino;      // 当前进程可执行文件 inode（用于上报进程 MD5）
    char comm[16];
    char path[256];
};

// ===== Helper Functions =====

static __noinline void send_monitor_event_impl(__u8 type, const char *path, __u8 blocked,
                                              __u8 op_type, const struct event_meta *meta);

static __always_inline void send_monitor_event(struct path_buffer *scratch, __u8 type,
                                               const char *path, __u8 blocked, __u8 op_type,
                                               __u32 parent_dev, __u64 parent_ino) {
    scratch->meta.parent_dev = parent_dev;
    scratch->meta.parent_ino = parent_ino;
    send_monitor_event_impl(type, path, blocked, op_type, &scratch->meta);
}

static __always_inline __u64 kernel_dev_to_user(dev_t kdev);

static __noinline void send_monitor_event_impl(__u8 type, const char *path, __u8 blocked,
                                              __u8 op_type, const struct event_meta *meta) {
    struct unified_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->type = type;
    e->op_type = op_type;
    e->blocked = blocked;
    e->_pad = 0;
    e->_pad2 = 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->parent_dev = meta ? meta->parent_dev : 0;
    e->parent_ino = meta ? meta->parent_ino : 0;
    e->exe_dev = 0;
    e->exe_ino = 0;
    e->_pad3 = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct file *exe = BPF_CORE_READ(task, mm, exe_file);
        if (exe) {
            struct inode *exe_inode = BPF_CORE_READ(exe, f_inode);
            if (exe_inode) {
                dev_t exe_kdev = BPF_CORE_READ(exe_inode, i_sb, s_dev);
                e->exe_dev = (__u32)kernel_dev_to_user(exe_kdev);
                e->exe_ino = BPF_CORE_READ(exe_inode, i_ino);
            }
        }
    }

    if (path) {
        // 单次 helper copy，避免 256B memcpy 在每个调用点展开导致 verifier 膨胀。
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
    }

    bpf_get_current_comm(e->comm, sizeof(e->comm));
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

// Returns 1 if current process TGID matches the agent PID stored in
// agent_pids[0]. This allows the agent to bypass self-protection
// dir_policy rules when accessing its own files.
static __always_inline int is_agent_process() {
    __u32 key = 0;
    __u32 *agent_pid = bpf_map_lookup_elem(&agent_pids, &key);
    if (!agent_pid || *agent_pid == 0) {
        return 0;
    }
    __u32 my_tgid = bpf_get_current_pid_tgid() >> 32;
    return my_tgid == *agent_pid ? 1 : 0;
}

// 自保专用检查：从叶子 dentry 向上遍历父目录，命中 self_protect_dirs 则返回 1。
// 与 DPI dir_policies 完全独立，不依赖 file_switch。
static __always_inline int is_self_protect_violation(struct dentry *dentry, const char *leaf) {
    struct dentry *cur = BPF_CORE_READ(dentry, d_parent);
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (!cur) break;
        struct inode *inode = BPF_CORE_READ(cur, d_inode);
        if (inode) {
            struct dir_key key;
            dev_t kdev = BPF_CORE_READ(inode, i_sb, s_dev);
            key.dev = kernel_dev_to_user(kdev);
            key.inode = BPF_CORE_READ(inode, i_ino);

            struct self_protect_rule *rule = bpf_map_lookup_elem(&self_protect_dirs, &key);
            if (rule) {
                if (rule->whole_dir) {
                    return 1;
                }
                if (i == 0) {
                    #pragma unroll
                    for (int p = 0; p < 2; p++) {
                        if (p >= rule->prefix_count) break;
                        int match = 1;
                        #pragma unroll
                        for (int j = 0; j < 16; j++) {
                            char pc = rule->prefixes[p][j];
                            char lc = leaf[j];
                            if (pc == '\0') break;               // 前缀完全匹配
                            if (lc == '\0' || lc != pc) { match = 0; break; }
                        }
                        if (match) return 1;
                    }
                }
            }
        }
        cur = BPF_CORE_READ(cur, d_parent);
    }
    return 0;
}

static __always_inline __u8 resolve_mode(__u8 rule_mode, __u32 feature_idx) {
    // rule_mode: 0=use global, 1=monitor, 2=protect
    // Returns: MODE_MONITOR (1) or MODE_PROTECT (2)
    if (rule_mode == 2) {
        return MODE_PROTECT;  // 2
    }
    if (rule_mode == 1) {
        return MODE_MONITOR;  // 1
    }
    // rule_mode == 0, use global mode
    __u8 *global = bpf_map_lookup_elem(&global_modes, &feature_idx);
    if (global && *global == MODE_PROTECT) {
        return MODE_PROTECT;
    }
    return MODE_MONITOR;
}

// Optimized suffix check - inline simple version
static __always_inline int check_suffix(const char *filename, const struct dir_policy *policy) {
    if (policy->filter_type == FILTER_NONE || policy->suffix_count == 0) {
        return 1;
    }
    
    // Find extension (last '.')
    int dot_pos = -1;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (filename[i] == '\0') break;
        if (filename[i] == '.') dot_pos = i;
    }
    
    if (dot_pos < 0) {
        return policy->filter_type == FILTER_EXCLUDE_SUFFIX ? 1 : 0;
    }
    
    // Simple extension compare (max 4 chars)
    char *ext = (char *)filename + dot_pos + 1;
    
    #pragma unroll
    for (int j = 0; j < 4; j++) {
        if (j >= policy->suffix_count) break;
        int match = 1;
        #pragma unroll
        for (int k = 0; k < 4; k++) {
            char e = ext[k];
            char s = policy->suffixes[j][k];
            if (e != s) { match = 0; break; }
            if (e == '\0' || s == '\0') break;
        }
        if (match) {
            return policy->filter_type == FILTER_SUFFIX ? 1 : 0;
        }
    }
    
    return policy->filter_type == FILTER_SUFFIX ? 0 : 1;
}

// Exact filename match check
static __always_inline int check_exact_match(const char *filename, const struct dir_policy *policy) {
    if (policy->filter_type != FILTER_EXACT_MATCH) {
        return 1;
    }
    
    int match = 1;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        char p = policy->exact_filename[i];
        char f = filename[i];
        // If both end at the same position, it's a match
        if (p == '\0' && f == '\0') {
            match = 1;
            break;
        }
        // If one ends but the other doesn't, no match
        if (p == '\0' || f == '\0') {
            match = 0;
            break;
        }
        // If characters differ, no match
        if (p != f) {
            match = 0;
            break;
        }
    }
    return match;
}

// ===== 勒索防护 helpers =====

static __always_inline int extort_enabled(void) {
    __u32 key = 0;
    __u8 *v = bpf_map_lookup_elem(&extort_switches, &key);
    return v && *v;
}

static __always_inline int extort_protect_mode(void) {
    __u32 key = 1;
    __u8 *v = bpf_map_lookup_elem(&extort_switches, &key);
    return v && *v;
}

// 当前进程可执行文件是否在勒索信任进程表中，且允许 rule_idx 这个后缀规则。
static __always_inline int is_extort_trusted(__u32 rule_idx) {
    if (rule_idx >= MAX_EXTORT_RULES) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct file *exe = BPF_CORE_READ(task, mm, exe_file);
    if (!exe) return 0;
    struct inode *inode = BPF_CORE_READ(exe, f_inode);
    if (!inode) return 0;

    struct extort_proc_key key;
    dev_t kdev = BPF_CORE_READ(inode, i_sb, s_dev);
    key.dev = (__u32)kernel_dev_to_user(kdev);
    key.inode = BPF_CORE_READ(inode, i_ino);

    __u32 *mask = bpf_map_lookup_elem(&extort_trusted, &key);
    if (!mask) return 0;
    return (*mask & (1u << rule_idx)) != 0;
}

// 叶子文件名后缀匹配：与 check_suffix 相同的正向扫描方式（verifier 友好）。
static __always_inline int extort_suffix_match(const char *filename, __u32 *matched_idx) {
    int dot_pos = -1;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (filename[i] == '\0') break;
        if (filename[i] == '.') dot_pos = i;
    }
    if (dot_pos < 0) return 0;

    char *ext = (char *)filename + dot_pos + 1;
    int ext_len = 0;
    #pragma unroll
    for (int j = 0; j < MAX_EXTORT_SUFFIX; j++) {
        if (ext[j] == '\0') break;
        ext_len++;
    }
    if (ext_len <= 0 || ext_len > MAX_EXTORT_SUFFIX) return 0;
    if (ext_len == MAX_EXTORT_SUFFIX && ext[MAX_EXTORT_SUFFIX] != '\0') return 0;

    char key[MAX_EXTORT_SUFFIX];
    #pragma unroll
    for (int j = 0; j < MAX_EXTORT_SUFFIX; j++) {
        key[j] = j < ext_len ? ext[j] : 0;
    }

    __u32 *idx = bpf_map_lookup_elem(&extort_suffixes, key);
    if (!idx) return 0;
    *matched_idx = *idx;
    return 1;
}

// 勒索防护检查：命中受保护后缀且当前进程不受信任时，
// protect 模式返回 -EPERM，monitor 模式只上报。目录本身不参与后缀匹配。
static __noinline int extort_check_impl(struct path_buffer *scratch, struct dentry *dentry,
                                       __u8 op_type) {
    const char *filename = scratch->buf;
    const char *fullpath = scratch->meta.has_full ? scratch->full : 0;
    __u32 parent_dev = scratch->meta.parent_dev;
    __u64 parent_ino = scratch->meta.parent_ino;

    if (!extort_enabled()) return 0;

    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    __u32 idx = 0;
    int matched = 0;

    if (inode) {
        umode_t mode = BPF_CORE_READ(inode, i_mode);
        if ((mode & S_IFMT) != S_IFDIR) {
            matched = extort_suffix_match(filename, &idx);
        }
    }

    if (!matched && parent_ino != 0) {
        struct dir_key pk;
        pk.dev = parent_dev;
        pk.inode = parent_ino;
        __u32 *v = bpf_map_lookup_elem(&extort_dirs, &pk);
        if (v) { idx = *v; matched = 1; }
    }
    if (!matched && inode) {
        struct dir_key tk;
        dev_t tkdev = BPF_CORE_READ(inode, i_sb, s_dev);
        tk.dev = kernel_dev_to_user(tkdev);
        tk.inode = BPF_CORE_READ(inode, i_ino);
        __u32 *v = bpf_map_lookup_elem(&extort_dirs, &tk);
        if (v) { idx = *v; matched = 1; }
    }

    if (!matched) return 0;
    if (is_extort_trusted(idx)) return 0;

    __u8 protect = extort_protect_mode();
    send_monitor_event(scratch, EVENT_EXTORT, fullpath ? fullpath : filename,
                       protect ? 1 : 0, op_type, parent_dev, parent_ino);
    return protect ? -EPERM : 0;
}

static __always_inline int extort_check(struct path_buffer *scratch, struct dentry *dentry,
                                       const char *filename, const char *fullpath, __u8 op_type,
                                       __u32 parent_dev, __u64 parent_ino) {
    scratch->meta.parent_dev = parent_dev;
    scratch->meta.parent_ino = parent_ino;
    scratch->meta.has_full = fullpath ? 1 : 0;
    return extort_check_impl(scratch, dentry, op_type);
}

// Look up the dir policy for a rename source/destination and return it
// only when the rule protects rename and the leaf name matches its filters.
static __always_inline struct dir_policy *rename_lookup_policy(struct inode *dir, const char *filename) {
    if (!dir) return 0;
    struct dir_key key;
    dev_t kdev = BPF_CORE_READ(dir, i_sb, s_dev);
    key.dev = kernel_dev_to_user(kdev);
    key.inode = BPF_CORE_READ(dir, i_ino);
    struct dir_policy *policy = bpf_map_lookup_elem(&dir_policies, &key);
    if (!policy) return 0;
    if (!(policy->ops_mask & OP_RENAME)) return 0;
    if (!check_exact_match(filename, policy)) return 0;
    if (!check_suffix(filename, policy)) return 0;
    return policy;
}

// ===== LSM Hooks =====

SEC("lsm.s/file_open")
int BPF_PROG(enforce_file_open, struct file *file) {
    if (is_agent_process()) {
        return 0;
    }

    __u32 flags = BPF_CORE_READ(file, f_flags);
    __u32 acc_mode = flags & O_ACCMODE;
    __u8 op_type = 0;
    
    if (acc_mode == O_RDONLY) op_type = OP_READ;
    else if (acc_mode == O_WRONLY) op_type = OP_WRITE;
    else if (acc_mode == O_RDWR) op_type = OP_READ | OP_WRITE;
    
    if (op_type == 0) return 0;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) return 0;

    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
    if (!parent) return 0;
    struct inode *parent_inode = BPF_CORE_READ(parent, d_inode);
    if (!parent_inode) return 0;

    struct dir_key key;
    dev_t kdev = BPF_CORE_READ(parent_inode, i_sb, s_dev);
    key.dev = kernel_dev_to_user(kdev);
    key.inode = BPF_CORE_READ(parent_inode, i_ino);
    __u32 parent_dev = (__u32)key.dev;
    __u64 parent_ino = key.inode;

    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;
    
    char *filename = scratch->buf;
    __builtin_memset(filename, 0, 64);
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(filename, 64, name_ptr);

    // 命中后再生成全路径；bpf_d_path 失败时回退到叶子名。
    char *fullpath = scratch->full;
    long plen = bpf_d_path(&file->f_path, fullpath, sizeof(scratch->full));
    if (plen <= 0) fullpath = 0;

    // ★ 自保专用检查：写操作命中自保目录则拦截（独立于 file_switch）
    if (op_type & OP_WRITE) {
        if (is_self_protect_violation(dentry, filename)) {
            bpf_printk("file_open: SELF_PROTECT BLOCK filename=%s", filename);
            send_monitor_event(scratch, EVENT_SELF_PROTECT, filename, 1, op_type, 0, 0);
            return -EPERM;
        }
    }

    // 勒索防护独立于 file_switch，由 EXTORTION_SWITCH / EXTORTION_PROTECT 控制。
    {
        int er = extort_check(scratch, dentry, filename, fullpath, op_type, parent_dev, parent_ino);
        if (er) return er;
    }

    if (!feature_enabled(FEATURE_FILE)) {
        return 0;
    }

    struct dir_policy *policy = bpf_map_lookup_elem(&dir_policies, &key);
    if (!policy) return 0;
    // Mirror the driver's file_audit_kernel() for touch/create: a real create
    // (FMODE_CREATED) is FILE_CREATE and is matched against protect_rw bit4,
    // i.e. OP_CREATE. Without that bit the driver does not alert either.
    if (BPF_CORE_READ(file, f_mode) & FMODE_CREATED)
        op_type = OP_CREATE;
    if (!(policy->ops_mask & op_type)) return 0;
    
    if (!check_exact_match(filename, policy)) return 0;
    
    if (!check_suffix(filename, policy)) return 0;
    
    __u8 effective_mode = resolve_mode(policy->mode, FEATURE_FILE);
    bpf_printk("file_open: effective_mode=%u action=%u op_type=%u", effective_mode, policy->action, op_type);

    if (effective_mode == MODE_PROTECT && policy->action == ACTION_DENY) {
        bpf_printk("file_open: BLOCK filename=%s op_type=%u", filename, op_type);
        send_monitor_event(scratch, EVENT_FILE, fullpath ? fullpath : filename, 1, op_type, parent_dev, parent_ino);
        return -EPERM;
    }

    bpf_printk("file_open: MONITOR filename=%s op_type=%u", filename, op_type);
    send_monitor_event(scratch, EVENT_FILE, fullpath ? fullpath : filename, 0, op_type, parent_dev, parent_ino);
    return 0;
}

SEC("lsm.s/inode_create")
int BPF_PROG(enforce_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    if (is_agent_process()) {
        return 0;
    }

    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) {
        bpf_printk("inode_create: no scratch buffer");
        return 0;
    }

    char *filename = scratch->buf;
    __builtin_memset(filename, 0, 64);
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(filename, 64, name_ptr);

    __u32 parent_dev = (__u32)kernel_dev_to_user(BPF_CORE_READ(dir, i_sb, s_dev));
    __u64 parent_ino = BPF_CORE_READ(dir, i_ino);

    // ★ 自保专用检查（独立于 file_switch）
    if (is_self_protect_violation(dentry, filename)) {
        bpf_printk("inode_create: SELF_PROTECT BLOCK filename=%s", filename);
        send_monitor_event(scratch, EVENT_SELF_PROTECT, filename, 1, OP_CREATE, 0, 0);
        return -EPERM;
    }

    if (!feature_enabled(FEATURE_FILE)) {
        return 0;
    }

    struct dir_key parent_key;
    dev_t kdev = BPF_CORE_READ(dir, i_sb, s_dev);
    parent_key.dev = kernel_dev_to_user(kdev);
    parent_key.inode = BPF_CORE_READ(dir, i_ino);

    struct dir_policy *policy = bpf_map_lookup_elem(&dir_policies, &parent_key);
    if (!policy) {
        return 0;
    }
    
    bpf_printk("inode_create: found policy, ops_mask=%u OP_CREATE=%u", policy->ops_mask, OP_CREATE);
    
    if (!(policy->ops_mask & OP_CREATE)) {
        bpf_printk("inode_create: OP_CREATE not in ops_mask");
        return 0;
    }
    
    if (!check_exact_match(filename, policy)) {
        bpf_printk("inode_create: exact match check failed");
        return 0;
    }
    
    if (!check_suffix(filename, policy)) {
        bpf_printk("inode_create: suffix check failed");
        return 0;
    }
    
    __u8 effective_mode = resolve_mode(policy->mode, FEATURE_FILE);
    
    if (effective_mode == MODE_PROTECT && policy->action == ACTION_DENY) {
        bpf_printk("inode_create: BLOCK filename=%s", filename);
        send_monitor_event(scratch, EVENT_FILE, filename, 1, OP_CREATE, parent_dev, parent_ino);
        return -EPERM;
    }

    // A successful create via open() is always followed by
    // security_file_open(), which reports it as CREATE via FMODE_CREATED.
    // Avoid a duplicate CREATE here; only blocking is reported above.
    // mkdir/mknod have no file_open follow-up and keep their own hooks.
    bpf_printk("inode_create: MONITOR filename=%s (reported by file_open)", filename);
    return 0;
}

SEC("lsm.s/inode_unlink")
int BPF_PROG(enforce_inode_unlink, struct inode *dir, struct dentry *dentry) {
    if (is_agent_process()) return 0;

    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *filename = scratch->buf;
    __builtin_memset(filename, 0, 64);
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(filename, 64, name_ptr);

    __u32 parent_dev = (__u32)kernel_dev_to_user(BPF_CORE_READ(dir, i_sb, s_dev));
    __u64 parent_ino = BPF_CORE_READ(dir, i_ino);

    // ★ 自保专用检查（独立于 file_switch）
    if (is_self_protect_violation(dentry, filename)) {
        bpf_printk("inode_unlink: SELF_PROTECT BLOCK filename=%s", filename);
        send_monitor_event(scratch, EVENT_SELF_PROTECT, filename, 1, OP_DELETE, 0, 0);
        return -EPERM;
    }

    {
        int er = extort_check(scratch, dentry, filename, 0, OP_DELETE, parent_dev, parent_ino);
        if (er) return er;
    }

    if (!feature_enabled(FEATURE_FILE)) return 0;

    struct dir_key key;
    dev_t kdev = BPF_CORE_READ(dir, i_sb, s_dev);
    key.dev = kernel_dev_to_user(kdev);
    key.inode = BPF_CORE_READ(dir, i_ino);

    struct dir_policy *policy = bpf_map_lookup_elem(&dir_policies, &key);
    if (!policy) return 0;
    
    if (!(policy->ops_mask & OP_DELETE)) return 0;
    
    if (!check_exact_match(filename, policy)) return 0;
    
    if (!check_suffix(filename, policy)) return 0;
    
    __u8 effective_mode = resolve_mode(policy->mode, FEATURE_FILE);
    bpf_printk("inode_create: effective_mode=%u action=%u", effective_mode, policy->action);
    
    if (effective_mode == MODE_PROTECT && policy->action == ACTION_DENY) {
        send_monitor_event(scratch, EVENT_FILE, filename, 1, OP_DELETE, parent_dev, parent_ino);
        return -EPERM;
    }

    send_monitor_event(scratch, EVENT_FILE, filename, 0, OP_DELETE, parent_dev, parent_ino);
    return 0;
}

SEC("lsm.s/inode_rename")
int BPF_PROG(enforce_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry) {
    if (is_agent_process()) return 0;

    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *filename = scratch->buf;

    __u32 old_pdev = (__u32)kernel_dev_to_user(BPF_CORE_READ(old_dir, i_sb, s_dev));
    __u64 old_pino = BPF_CORE_READ(old_dir, i_ino);
    __u32 new_pdev = (__u32)kernel_dev_to_user(BPF_CORE_READ(new_dir, i_sb, s_dev));
    __u64 new_pino = BPF_CORE_READ(new_dir, i_ino);

    // Source: moving a protected file out of a protected dir / subtree.
    __builtin_memset(filename, 0, 64);
    bpf_probe_read_kernel_str(filename, 64, BPF_CORE_READ(old_dentry, d_name.name));
    if (is_self_protect_violation(old_dentry, filename)) {
        bpf_printk("inode_rename: SELF_PROTECT BLOCK src=%s", filename);
        send_monitor_event(scratch, EVENT_SELF_PROTECT, filename, 1, OP_RENAME, 0, 0);
        return -EPERM;
    }

    // Destination: moving a file into a protected dir / subtree.
    __builtin_memset(filename, 0, 64);
    bpf_probe_read_kernel_str(filename, 64, BPF_CORE_READ(new_dentry, d_name.name));
    if (is_self_protect_violation(new_dentry, filename)) {
        bpf_printk("inode_rename: SELF_PROTECT BLOCK dst=%s", filename);
        send_monitor_event(scratch, EVENT_SELF_PROTECT, filename, 1, OP_RENAME, 0, 0);
        return -EPERM;
    }

    if (!feature_enabled(FEATURE_FILE)) return 0;

    int old_match = 0;
    int new_match = 0;

    // Source parent policy: deny here blocks moving the file away.
    __builtin_memset(filename, 0, 64);
    bpf_probe_read_kernel_str(filename, 64, BPF_CORE_READ(old_dentry, d_name.name));
    struct dir_policy *policy = rename_lookup_policy(old_dir, filename);
    if (policy) {
        __u8 effective_mode = resolve_mode(policy->mode, FEATURE_FILE);
        if (effective_mode == MODE_PROTECT && policy->action == ACTION_DENY) {
            bpf_printk("inode_rename: BLOCK src=%s", filename);
            send_monitor_event(scratch, EVENT_FILE, filename, 1, OP_RENAME, old_pdev, old_pino);
            return -EPERM;
        }
        old_match = 1;
    }

    // Destination parent policy: deny here blocks moving the file in.
    __builtin_memset(filename, 0, 64);
    bpf_probe_read_kernel_str(filename, 64, BPF_CORE_READ(new_dentry, d_name.name));
    policy = rename_lookup_policy(new_dir, filename);
    if (policy) {
        __u8 effective_mode = resolve_mode(policy->mode, FEATURE_FILE);
        if (effective_mode == MODE_PROTECT && policy->action == ACTION_DENY) {
            bpf_printk("inode_rename: BLOCK dst=%s", filename);
            send_monitor_event(scratch, EVENT_FILE, filename, 1, OP_RENAME, new_pdev, new_pino);
            return -EPERM;
        }
        new_match = 1;
    }

    if (old_match) {
        __builtin_memset(filename, 0, 64);
        bpf_probe_read_kernel_str(filename, 64, BPF_CORE_READ(old_dentry, d_name.name));
        bpf_printk("inode_rename: MONITOR src=%s", filename);
        send_monitor_event(scratch, EVENT_FILE, filename, 0, OP_RENAME, old_pdev, old_pino);
    } else if (new_match) {
        bpf_printk("inode_rename: MONITOR dst=%s", filename);
        send_monitor_event(scratch, EVENT_FILE, filename, 0, OP_RENAME, new_pdev, new_pino);
    }

    return 0;
}

SEC("lsm.s/inode_mkdir")
int BPF_PROG(enforce_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode) {
    if (is_agent_process()) {
        return 0;
    }

    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *filename = scratch->buf;
    __builtin_memset(filename, 0, 64);
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(filename, 64, name_ptr);

    __u32 parent_dev = (__u32)kernel_dev_to_user(BPF_CORE_READ(dir, i_sb, s_dev));
    __u64 parent_ino = BPF_CORE_READ(dir, i_ino);

    // ★ 自保专用检查（独立于 file_switch）
    if (is_self_protect_violation(dentry, filename)) {
        bpf_printk("inode_mkdir: SELF_PROTECT BLOCK filename=%s", filename);
        send_monitor_event(scratch, EVENT_SELF_PROTECT, filename, 1, OP_CREATE, 0, 0);
        return -EPERM;
    }

    if (!feature_enabled(FEATURE_FILE)) {
        return 0;
    }

    struct dir_key parent_key;
    dev_t kdev = BPF_CORE_READ(dir, i_sb, s_dev);
    parent_key.dev = kernel_dev_to_user(kdev);
    parent_key.inode = BPF_CORE_READ(dir, i_ino);

    struct dir_policy *policy = bpf_map_lookup_elem(&dir_policies, &parent_key);
    if (!policy) {
        return 0;
    }
    
    if (!(policy->ops_mask & OP_CREATE)) {
        bpf_printk("inode_mkdir: OP_CREATE not in ops_mask");
        return 0;
    }
    
    __u8 effective_mode = resolve_mode(policy->mode, FEATURE_FILE);
    bpf_printk("inode_mkdir: effective_mode=%u action=%u", effective_mode, policy->action);
    
    if (effective_mode == MODE_PROTECT && policy->action == ACTION_DENY) {
        bpf_printk("inode_mkdir: BLOCKING");
        send_monitor_event(scratch, EVENT_FILE, filename, 1, OP_CREATE, parent_dev, parent_ino);
        return -EPERM;
    }

    send_monitor_event(scratch, EVENT_FILE, filename, 0, OP_CREATE, parent_dev, parent_ino);
    return 0;
}
