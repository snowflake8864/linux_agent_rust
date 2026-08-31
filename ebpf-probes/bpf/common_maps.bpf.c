#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Dummy program to ensure BTF is generated
SEC("tp/syscalls/sys_enter_nanosleep")
int dummy_prog(void *ctx)
{
    return 0;
}

// ===== Constants =====
// Mode constants (match Rust: mode.as_u8() + 1)
// Rust: Monitor=0, Protect=1 -> +1 -> Monitor=1, Protect=2
#define MODE_MONITOR 1
#define MODE_PROTECT 2

#define ACTION_ALLOW 0
#define ACTION_DENY 1

#define FILTER_NONE 0
#define FILTER_SUFFIX 1
#define FILTER_EXCLUDE_SUFFIX 2

// Operation flags
#define OP_READ    1
#define OP_WRITE   2
#define OP_MODIFY  4
#define OP_CREATE  8
#define OP_DELETE  16
#define OP_RENAME  32
#define OP_EXECUTE 64

// ===== Shared Event Structure =====
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
        struct {
            __u8 protocol;
            __u8 tcp_flags_set;
            __u32 src_ip;
            __u32 dst_ip;
            __u16 src_port;
            __u16 dst_port;
            __u8 padding[2];
        } network;
        char msg[89];
    };
};

// ===== Maps =====

// Event ring buffer (shared by all modules)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} event_ringbuf SEC(".maps");

// Feature switches: 0=disabled, 1=enabled (index: 0=file, 1=proc, 2=net)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u8);
} feature_switches SEC(".maps");

// Global modes: 0=Monitor, 1=Protect (index: 0=file, 1=proc, 2=net)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u8);
} global_modes SEC(".maps");

// Scratch buffer for path construction
struct path_buffer {
    char buf[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buffer);
} path_scratch SEC(".maps");

// ===== File Control Maps =====

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
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dir_key);
    __type(value, struct dir_policy);
} dir_policies SEC(".maps");

// ===== Process Control Maps =====

struct proc_key {
    __u32 dev;
    __u64 inode;
} __attribute__((packed));

struct proc_rule {
    __u8 action_mode;  // bit0=action(0=allow,1=deny), bit1-2=mode(0=inherit,1=monitor,2=protect)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct proc_key);
    __type(value, struct proc_rule);
} proc_rules SEC(".maps");

// Pattern-based rules for process (fallback)
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

// ===== Network Control Maps =====

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} block_rules SEC(".maps");

struct pkt_mod_key {
    __u8 protocol;
    __u8 direction;
    __u8 padding[2];
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
} __attribute__((packed));

struct pkt_mod_value {
    __u8 tcp_flags_enable;
    __u8 tcp_set_ecn_echo;
    __u8 tcp_set_cwr;
    __u8 tcp_set_reserved;
    __u8 tcp_flags_mask;
    __u8 tcp_flags_value;
    __u8 reserved_bits_mask;
    __u8 reserved_bits_value;
    __u8 port_mod_enable;
    __u16 new_src_port;
    __u16 new_dst_port;
    __u8 ip_mod_enable;
    __u32 new_src_ip;
    __u32 new_dst_ip;
    __u32 allowed_ip;
    __u32 allowed_mask;
    __u8 padding[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct pkt_mod_key);
    __type(value, struct pkt_mod_value);
} pkt_mod_rules SEC(".maps");

struct reverse_key {
    __u32 target_ip;
    __u32 client_ip;
    __u16 target_port;
    __u16 client_port;
} __attribute__((packed));

struct reverse_value {
    __u32 local_ip;
    __u16 local_port;
    __u32 client_ip;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct reverse_key);
    __type(value, struct reverse_value);
} reverse_rules SEC(".maps");
