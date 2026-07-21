// Network-only BPF agent for modular mode
// Contains XDP + TC programs for packet forwarding and modification

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// TC action codes
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#endif

char LICENSE[] SEC("license") = "GPL";

// Checksum replacement helpers
static __always_inline void csum_replace2(__u16 *csum, __u16 old_val, __u16 new_val) {
    __u32 new_csum = *csum;
    new_csum = ~new_csum & 0xFFFF;
    new_csum += ~old_val & 0xFFFF;
    new_csum += new_val;
    new_csum = (new_csum >> 16) + (new_csum & 0xFFFF);
    new_csum += (new_csum >> 16);
    *csum = ~new_csum & 0xFFFF;
}

static __always_inline void csum_replace4(__u16 *csum, __u32 old_val, __u32 new_val) {
    csum_replace2(csum, old_val & 0xFFFF, new_val & 0xFFFF);
    csum_replace2(csum, old_val >> 16, new_val >> 16);
}

// Event types
#define EVENT_NET 3

// Event structure for ring buffer
struct pkt_event {
    __u8 type;
    __u8 protocol;
    __u8 tcp_flags_set;
    __u8 padding1;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Block rules map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} block_rules SEC(".maps");

// Packet modification key
struct pkt_mod_key {
    __u8 protocol;    // 6=TCP, 17=UDP, 0=any
    __u8 direction;   // 0=any, 1=ingress, 2=egress
    __u8 padding[2];
    __u32 dst_ip;     // Network byte order, 0 = any
    __u16 src_port;   // Network byte order, 0 = any
    __u16 dst_port;   // Network byte order, 0 = any
} __attribute__((packed));

// Packet modification value
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
} __attribute__((packed));

// Packet modification rules map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct pkt_mod_key);
    __type(value, struct pkt_mod_value);
} pkt_mod_rules SEC(".maps");

// Reverse mapping for return traffic
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
    __u16 client_port;
    __u16 padding;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct reverse_key);
    __type(value, struct reverse_value);
} reverse_rules SEC(".maps");

// Event ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} pkt_events SEC(".maps");

// Debug counter array
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} debug_stats SEC(".maps");

// Helper: send network event
static __always_inline void send_network_event(__u8 protocol, __u32 src_ip, __u32 dst_ip, 
                                                __u16 src_port, __u16 dst_port, __u8 flags) {
    struct pkt_event *e = bpf_ringbuf_reserve(&pkt_events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_NET;
        e->protocol = protocol;
        e->src_ip = src_ip;
        e->dst_ip = dst_ip;
        e->src_port = src_port;
        e->dst_port = dst_port;
        e->tcp_flags_set = flags;
        bpf_ringbuf_submit(e, 0);
    }
}

// Helper: find rule with wildcards (for XDP ingress)
static __always_inline struct pkt_mod_value *find_net_rule(__u8 protocol, __u8 direction,
                                                            __u32 dst_ip, __u16 src_port, __u16 dst_port) {
    struct pkt_mod_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.protocol = protocol;
    key.direction = direction;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;

    // 1. Exact match (all fields)
    struct pkt_mod_value *rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 2. Wildcard src_port
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 3. Wildcard dst_port
    key.src_port = src_port;
    key.dst_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 4. Wildcard src_port + dst_port
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 5. Wildcard dst_ip (restore ports)
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.dst_ip = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 6. Wildcard dst_ip + src_port
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 7. Wildcard dst_ip + dst_port
    key.src_port = src_port;
    key.dst_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 8. Wildcard dst_ip + src_port + dst_port (match any packet with same protocol+direction)
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 9. Any direction + wildcard everything
    key.direction = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    return NULL;
}

// XDP program for ingress packet processing
SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Debug: count packets reaching XDP
    __u32 k0 = 0;
    __u64 *c0 = bpf_map_lookup_elem(&debug_stats, &k0);
    if (c0) (*c0)++;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u8 protocol = ip->protocol;
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // Debug: count IP packets
    __u32 k1 = 1;
    __u64 *c1 = bpf_map_lookup_elem(&debug_stats, &k1);
    if (c1) (*c1)++;

    if (protocol != 6 && protocol != 17) return XDP_PASS;

    // Debug: count TCP/UDP
    __u32 k2 = 2;
    __u64 *c2 = bpf_map_lookup_elem(&debug_stats, &k2);
    if (c2) (*c2)++;

    __u16 src_port = 0, dst_port = 0;
    void *l4_hdr = (void *)ip + (ip->ihl * 4);

    if (protocol == 6) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
        
        // Debug: count TCP SYN to dst_port 30002 (12917)
        if (dst_port == 12917) {
            __u32 k11 = 11;
            __u64 *c11 = bpf_map_lookup_elem(&debug_stats, &k11);
            if (c11) (*c11)++;
        }
    } else {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // 1. Check block rules
    __u16 block_key = bpf_ntohs(dst_port);
    __u8 *blocked = bpf_map_lookup_elem(&block_rules, &block_key);
    if (blocked && *blocked) {
        // Debug: count blocked
        __u32 k3 = 3;
        __u64 *c3 = bpf_map_lookup_elem(&debug_stats, &k3);
        if (c3) (*c3)++;
        bpf_printk("[NET XDP] BLOCKED: %pI4 -> %pI4",
                   &src_ip, &dst_ip);
        bpf_printk("[NET XDP]   sport=%u dport=%u proto=%u",
                   bpf_ntohs(src_port), bpf_ntohs(dst_port), protocol);
        send_network_event(protocol, src_ip, dst_ip, src_port, dst_port, 0x80);
        return XDP_DROP;
    }

    // 2. Try find mod rule (Ingress = 1)
    struct pkt_mod_value *rule = find_net_rule(protocol, 1, dst_ip, src_port, dst_port);
    if (!rule) {
        // Debug: count no rule found
        __u32 k4 = 4;
        __u64 *c4 = bpf_map_lookup_elem(&debug_stats, &k4);
        if (c4) (*c4)++;
        // Try handle reverse traffic
        struct reverse_key r_key;
        __builtin_memset(&r_key, 0, sizeof(r_key));
        r_key.target_ip = src_ip;
        r_key.target_port = src_port;
        r_key.client_ip = dst_ip;
        r_key.client_port = dst_port;

        struct reverse_value *r_val = bpf_map_lookup_elem(&reverse_rules, &r_key);
        if (r_val) {
            bpf_printk("[NET XDP] REV NAT: %pI4 -> %pI4", &src_ip, &dst_ip);
            bpf_printk("[NET XDP]   sport=%u dport=%u",
                       bpf_ntohs(src_port), bpf_ntohs(dst_port));
            bpf_printk("[NET XDP]   => local %pI4:%u client %pI4",
                       &r_val->local_ip, bpf_ntohs(r_val->local_port), &r_val->client_ip);
            // Reverse mapping found - translate and pass
            if (protocol == 6) {
                struct tcphdr *tcp = l4_hdr;
                if ((void *)(tcp + 1) > data_end) return XDP_PASS;
                // Translate Source: target -> local
                csum_replace4(&tcp->check, src_ip, r_val->local_ip);
                csum_replace2(&tcp->check, src_port, r_val->local_port);
                tcp->source = r_val->local_port;
                // Translate Destination: agent -> client
                csum_replace4(&tcp->check, dst_ip, r_val->client_ip);
            } else {
                struct udphdr *udp = l4_hdr;
                if ((void *)(udp + 1) > data_end) return XDP_PASS;
                if (udp->check) {
                    csum_replace4(&udp->check, src_ip, r_val->local_ip);
                    csum_replace2(&udp->check, src_port, r_val->local_port);
                    csum_replace4(&udp->check, dst_ip, r_val->client_ip);
                }
                udp->source = r_val->local_port;
            }
            csum_replace4(&ip->check, src_ip, r_val->local_ip);
            ip->saddr = r_val->local_ip;
            csum_replace4(&ip->check, dst_ip, r_val->client_ip);
            ip->daddr = r_val->client_ip;
            return XDP_PASS;
        }
        return XDP_PASS;
    }

    // Debug: count mod rule found
    __u32 k5 = 5;
    __u64 *c5 = bpf_map_lookup_elem(&debug_stats, &k5);
    if (c5) (*c5)++;

    bpf_printk("[NET XDP] MOD RULE: %pI4 -> %pI4", &src_ip, &dst_ip);
    bpf_printk("[NET XDP]   sport=%u dport=%u proto=%u",
               bpf_ntohs(src_port), bpf_ntohs(dst_port), protocol);
    bpf_printk("[NET XDP]   flags_en=%u port_mod=%u",
               rule->tcp_flags_enable, rule->port_mod_enable);

    // 3. Mod rule hit: Forward + SNAT
    __u32 target_ip = dst_ip;
    if (rule->ip_mod_enable && rule->new_dst_ip != 0) {
        target_ip = rule->new_dst_ip;
        // Debug: count IP modified (remote forward)
        __u32 k7 = 7;
        __u64 *c7 = bpf_map_lookup_elem(&debug_stats, &k7);
        if (c7) (*c7)++;
    }
    __u16 target_port = rule->port_mod_enable ? rule->new_dst_port : dst_port;

    // Determine SNAT IP
    __u32 new_src_ip = src_ip;
    if (rule->ip_mod_enable && rule->new_dst_ip != 0) {
        new_src_ip = dst_ip; // SNAT to local IP
    }

    // Store reverse mapping
    struct reverse_key rev_k;
    __builtin_memset(&rev_k, 0, sizeof(rev_k));
    rev_k.target_ip = target_ip;
    rev_k.target_port = target_port;
    rev_k.client_ip = new_src_ip;
    rev_k.client_port = src_port;

    struct reverse_value rev_v;
    __builtin_memset(&rev_v, 0, sizeof(rev_v));
    rev_v.local_ip = dst_ip;
    rev_v.local_port = dst_port;
    rev_v.client_ip = src_ip;
    rev_v.client_port = src_port;

    bpf_map_update_elem(&reverse_rules, &rev_k, &rev_v, BPF_ANY);

    // Apply modifications
    if (protocol == 6) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        
        // === TCP flags modification ===
        if (rule->tcp_flags_enable) {
            __u8 *flags_byte = (__u8 *)tcp + 13;
            __u8 old_flags = *flags_byte;
            __u8 new_flags = old_flags;
            
            // Set ECE flag if enabled
            if (rule->tcp_set_ecn_echo) {
                new_flags |= (1 << 6); // ECE bit (0x40)
            }
            // Set CWR flag if enabled
            if (rule->tcp_set_cwr) {
                new_flags |= (1 << 7); // CWR bit (0x80)
            }

            // Apply mask/value for flags if provided
            if (rule->tcp_flags_mask) {
                new_flags = (new_flags & ~rule->tcp_flags_mask) |
                            (rule->tcp_flags_value & rule->tcp_flags_mask);
            }

            // Update flags and checksum if changed
            if (old_flags != new_flags) {
                bpf_printk("[NET XDP] TCP MOD: %pI4 -> %pI4", &src_ip, &dst_ip);
                bpf_printk("[NET XDP]   sport=%u dport=%u old=0x%x",
                           bpf_ntohs(src_port), bpf_ntohs(dst_port), old_flags);
                bpf_printk("[NET XDP]   new=0x%x", new_flags);
                csum_replace2(&tcp->check, old_flags, new_flags);
                *flags_byte = new_flags;
            }

            // Handle reserved bits (byte 12)
            if (rule->tcp_set_reserved) {
                __u8 *reserved_byte = (__u8 *)tcp + 12;
                *reserved_byte = (*reserved_byte & 0xF0) | 0x0F;
            } else if (rule->reserved_bits_mask) {
                __u8 *reserved_byte = (__u8 *)tcp + 12;
                __u8 old_res = *reserved_byte;
                __u8 new_res = (old_res & (~rule->reserved_bits_mask | 0xF0)) |
                              (rule->reserved_bits_value & rule->reserved_bits_mask & 0x0F);
                if (old_res != new_res) {
                    *reserved_byte = new_res;
                }
            }
        }

        // DNAT
        if (target_ip != dst_ip) {
            csum_replace4(&tcp->check, dst_ip, target_ip);
        }
        if (target_port != dst_port) {
            csum_replace2(&tcp->check, dst_port, target_port);
            tcp->dest = target_port;
        }
        // SNAT
        if (new_src_ip != src_ip) {
            csum_replace4(&tcp->check, src_ip, new_src_ip);
        }
    } else {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        if (udp->check) {
            if (target_ip != dst_ip) csum_replace4(&udp->check, dst_ip, target_ip);
            if (target_port != dst_port) csum_replace2(&udp->check, dst_port, target_port);
            if (new_src_ip != src_ip) csum_replace4(&udp->check, src_ip, new_src_ip);
        }
        udp->dest = target_port;
    }

    // Update IP header
    if (target_ip != dst_ip) {
        csum_replace4(&ip->check, dst_ip, target_ip);
        ip->daddr = target_ip;
    }
    if (new_src_ip != src_ip) {
        csum_replace4(&ip->check, src_ip, new_src_ip);
        ip->saddr = new_src_ip;
    }

    // Debug: count forwarded (XDP_PASS)
    __u32 k6 = 6;
    __u64 *c6 = bpf_map_lookup_elem(&debug_stats, &k6);
    if (c6) (*c6)++;

    send_network_event(protocol, src_ip, dst_ip, src_port, dst_port, 0x40);
    return XDP_PASS;
}

// TC classifier for egress (return traffic)
SEC("classifier")
int tc_packet_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u8 protocol = ip->protocol;
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 src_port = 0, dst_port = 0;
    void *l4 = (void *)ip + (ip->ihl * 4);

    if (protocol == 6) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (protocol == 17) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        src_port = udp->source;
        dst_port = udp->dest;
    } else {
        return TC_ACT_OK;
    }

    // Check reverse mapping for return traffic
    struct reverse_key r_key;
    __builtin_memset(&r_key, 0, sizeof(r_key));
    r_key.target_ip = src_ip;
    r_key.target_port = src_port;
    r_key.client_ip = dst_ip;
    r_key.client_port = dst_port;

    struct reverse_value *r_val = bpf_map_lookup_elem(&reverse_rules, &r_key);
    if (r_val) {
        bpf_printk("[NET TC] REV NAT: %pI4 -> %pI4", &src_ip, &dst_ip);
        bpf_printk("[NET TC]   sport=%u dport=%u",
                   bpf_ntohs(src_port), bpf_ntohs(dst_port));
        bpf_printk("[NET TC]   => local %pI4:%u client %pI4",
                   &r_val->local_ip, bpf_ntohs(r_val->local_port), &r_val->client_ip);
        // Translate source: target -> local
        // Translate destination: agent -> client
        if (protocol == 6) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
            // DNAT: change destination from agent IP to client IP
            csum_replace4(&tcp->check, dst_ip, r_val->client_ip);
            csum_replace2(&tcp->check, dst_port, r_val->client_port);
            tcp->dest = r_val->client_port;
            // SNAT: change source from target IP to local IP
            csum_replace4(&tcp->check, src_ip, r_val->local_ip);
            csum_replace2(&tcp->check, src_port, r_val->local_port);
            tcp->source = r_val->local_port;
        } else {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
            if (udp->check) {
                csum_replace4(&udp->check, dst_ip, r_val->client_ip);
                csum_replace2(&udp->check, dst_port, r_val->client_port);
                csum_replace4(&udp->check, src_ip, r_val->local_ip);
                csum_replace2(&udp->check, src_port, r_val->local_port);
            }
            udp->dest = r_val->client_port;
            udp->source = r_val->local_port;
        }
        // Update IP header
        csum_replace4(&ip->check, dst_ip, r_val->client_ip);
        ip->daddr = r_val->client_ip;
        csum_replace4(&ip->check, src_ip, r_val->local_ip);
        ip->saddr = r_val->local_ip;
    }

    // === Apply packet modification rules for egress traffic ===
    // Find rule for egress direction (direction=2)
    struct pkt_mod_value *rule = find_net_rule(protocol, 2, dst_ip, src_port, dst_port);
    if (!rule) {
        // Try direction=0 (any)
        rule = find_net_rule(protocol, 0, dst_ip, src_port, dst_port);
    }

    if (rule && protocol == 6) {
        bpf_printk("[NET TC] EGRESS: %pI4 -> %pI4", &src_ip, &dst_ip);
        bpf_printk("[NET TC]   sport=%u dport=%u proto=%u",
                   bpf_ntohs(src_port), bpf_ntohs(dst_port), protocol);
        bpf_printk("[NET TC]   flags_en=%u port_mod=%u",
                   rule->tcp_flags_enable, rule->port_mod_enable);
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        // === TCP flags modification ===
        if (rule->tcp_flags_enable) {
            __u8 *flags_byte = (__u8 *)tcp + 13;
            __u8 old_flags = *flags_byte;
            __u8 new_flags = old_flags;
            
            // Set ECE flag if enabled
            if (rule->tcp_set_ecn_echo) {
                new_flags |= (1 << 6); // ECE bit (0x40)
            }
            // Set CWR flag if enabled
            if (rule->tcp_set_cwr) {
                new_flags |= (1 << 7); // CWR bit (0x80)
            }
            
            // Apply mask/value for flags if provided
            if (rule->tcp_flags_mask) {
                new_flags = (new_flags & ~rule->tcp_flags_mask) |
                            (rule->tcp_flags_value & rule->tcp_flags_mask);
            }
            
            // Update flags and checksum if changed
            if (old_flags != new_flags) {
                bpf_printk("[NET TC] TCP MOD: %pI4 -> %pI4", &src_ip, &dst_ip);
                bpf_printk("[NET TC]   sport=%u dport=%u old=0x%x",
                           bpf_ntohs(src_port), bpf_ntohs(dst_port), old_flags);
                bpf_printk("[NET TC]   new=0x%x", new_flags);
                csum_replace2(&tcp->check, old_flags, new_flags);
                *flags_byte = new_flags;
            }

            // Handle reserved bits (byte 12)
            if (rule->tcp_set_reserved) {
                __u8 *reserved_byte = (__u8 *)tcp + 12;
                *reserved_byte = (*reserved_byte & 0xF0) | 0x0F;
            } else if (rule->reserved_bits_mask) {
                __u8 *reserved_byte = (__u8 *)tcp + 12;
                __u8 old_res = *reserved_byte;
                __u8 new_res = (old_res & (~rule->reserved_bits_mask | 0xF0)) |
                              (rule->reserved_bits_value & rule->reserved_bits_mask & 0x0F);
                if (old_res != new_res) {
                    *reserved_byte = new_res;
                }
            }
        }
    }

    return TC_ACT_OK;
}

// Cgroup hook for local connect() interception
SEC("cgroup/connect4")
int enforce_connect4(struct bpf_sock_addr *ctx) {
    if (ctx->family != 2) return 1; // AF_INET

    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = ctx->user_port;
    __u8 protocol = (ctx->type == 1) ? 6 : 17; // SOCK_STREAM -> TCP

    // Match rules (direction=0 any, or direction=2 egress, or direction=1 ingress)
    struct pkt_mod_value *rule = find_net_rule(protocol, 0, dst_ip, 0, dst_port);
    if (!rule) {
        rule = find_net_rule(protocol, 2, dst_ip, 0, dst_port);
    }
    if (!rule) {
        rule = find_net_rule(protocol, 1, dst_ip, 0, dst_port);
    }

    if (rule) {
        bpf_printk("[NET CGROUP] CONNECT REDIRECT: dst=%pI4:%u proto=%u",
                   &dst_ip, bpf_ntohs(dst_port), protocol);
        bpf_printk("[NET CGROUP]   port_mod=%u ip_mod=%u",
                   rule->port_mod_enable, rule->ip_mod_enable);
        if (rule->port_mod_enable && rule->new_dst_port) {
            ctx->user_port = rule->new_dst_port;
        }
        if (rule->ip_mod_enable && rule->new_dst_ip) {
            ctx->user_ip4 = rule->new_dst_ip;
        }
    }

    return 1;
}
