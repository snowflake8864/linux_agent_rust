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

struct path_buffer {
    char buf[256];
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

// ===== Constants =====
#define EVENT_FILE 1
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

// ===== LSM Hooks =====

SEC("lsm.s/file_open")
int BPF_PROG(enforce_file_open, struct file *file) {
    if (!feature_enabled(FEATURE_FILE)) {
        return 0;
    }
    
    __u32 flags = BPF_CORE_READ(file, f_flags);
    __u32 acc_mode = flags & O_ACCMODE;
    __u8 op_type = 0;
    
    if (acc_mode == O_RDONLY) op_type = OP_READ;
    else if (acc_mode == O_WRONLY) op_type = OP_WRITE;
    else if (acc_mode == O_RDWR) op_type = OP_READ | OP_WRITE;
    
    if (op_type == 0) return 0;
    
    if ((flags & O_CREAT) && (flags & O_TRUNC)) {
        op_type |= OP_CREATE;
    }
    
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
    
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;
    
    char *filename = scratch->buf;
    __builtin_memset(filename, 0, 64);
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(filename, 64, name_ptr);
    
    struct dir_policy *policy = bpf_map_lookup_elem(&dir_policies, &key);
    if (!policy) return 0;
    
    if (!(policy->ops_mask & op_type)) return 0;
    
    if (!check_exact_match(filename, policy)) return 0;
    
    if (!check_suffix(filename, policy)) return 0;
    
    __u8 effective_mode = resolve_mode(policy->mode, FEATURE_FILE);
    bpf_printk("inode_create: effective_mode=%u action=%u", effective_mode, policy->action);
    
    struct inode *file_inode = BPF_CORE_READ(file, f_path.dentry->d_inode);
    if (file_inode && policy->recursive) {
        umode_t file_mode = BPF_CORE_READ(file_inode, i_mode);
        if ((file_mode & S_IFMT) == S_IFDIR) {
            struct dir_key new_key;
            dev_t new_kdev = BPF_CORE_READ(file_inode, i_sb, s_dev);
            new_key.dev = kernel_dev_to_user(new_kdev);
            new_key.inode = BPF_CORE_READ(file_inode, i_ino);
            
            struct dir_policy *existing = bpf_map_lookup_elem(&dir_policies, &new_key);
            if (!existing) {
                bpf_map_update_elem(&dir_policies, &new_key, policy, BPF_ANY);
            }
        }
    }
    
    if (effective_mode == MODE_PROTECT && policy->action == ACTION_DENY) {
        send_monitor_event(EVENT_FILE, filename, 1);
        return -EPERM;
    }
    
    send_monitor_event(EVENT_FILE, filename, 0);
    return 0;
}

SEC("lsm.s/inode_create")
int BPF_PROG(enforce_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    if (!feature_enabled(FEATURE_FILE)) {
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
    
    struct inode *new_inode = BPF_CORE_READ(dentry, d_inode);
    if (policy->recursive && new_inode) {
        struct dir_key new_key;
        dev_t new_kdev = BPF_CORE_READ(new_inode, i_sb, s_dev);
        new_key.dev = kernel_dev_to_user(new_kdev);
        new_key.inode = BPF_CORE_READ(new_inode, i_ino);
        
        struct dir_policy *existing = bpf_map_lookup_elem(&dir_policies, &new_key);
        if (!existing) {
            bpf_map_update_elem(&dir_policies, &new_key, policy, BPF_ANY);
        }
    }
    
    __u8 effective_mode = resolve_mode(policy->mode, FEATURE_FILE);
    
    if (effective_mode == MODE_PROTECT && policy->action == ACTION_DENY) {
        send_monitor_event(EVENT_FILE, filename, 1);
        return -EPERM;
    }
    
    send_monitor_event(EVENT_FILE, filename, 0);
    return 0;
}

SEC("lsm.s/inode_unlink")
int BPF_PROG(enforce_inode_unlink, struct inode *dir, struct dentry *dentry) {
    if (!feature_enabled(FEATURE_FILE)) return 0;
    
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;
    
    char *filename = scratch->buf;
    __builtin_memset(filename, 0, 64);
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(filename, 64, name_ptr);
    
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
        send_monitor_event(EVENT_FILE, filename, 1);
        return -EPERM;
    }
    
    send_monitor_event(EVENT_FILE, filename, 0);
    return 0;
}

SEC("lsm.s/inode_mkdir")
int BPF_PROG(enforce_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode) {
    if (!feature_enabled(FEATURE_FILE)) {
        return 0;
    }
    
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;
    
    char *filename = scratch->buf;
    __builtin_memset(filename, 0, 64);
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(filename, 64, name_ptr);
    
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
        send_monitor_event(EVENT_FILE, filename, 1);
        return -EPERM;
    }
    
    send_monitor_event(EVENT_FILE, filename, 0);
    return 0;
}
