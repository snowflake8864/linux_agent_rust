// DNS 审计（独立 BPF 对象，tc ingress）
// 只解析 UDP source port 53 的 DNS 响应：question 域名 + answer 中的 A 记录 IP。
// 进程信息留空（由用户态填）。独立于 net_agent，加载失败不影响主网络功能。
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#define EVENT_DNS 6

// DNS 审计开关（syslog_dns_switch / DNS_SWITCH）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dns_switch SEC(".maps");

// DNS 审计事件：域名 + 解析出的 IP（每个 4 字节，网络序）
struct dns_event {
    __u8 type;        // EVENT_DNS
    __u8 family;      // 2=AF_INET
    __u8 ip_cnt;      // 0~12
    __u8 _pad;
    char domain[64];  // 点分域名（零初始化，天然 NUL 结尾）
    __u8 ips[4];      // 单条 A 记录 IP（网络序）
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} dns_events SEC(".maps");

// 事件构造缓冲：map value 允许有界变量偏移写入（栈不允许），避免 unroll 爆栈。
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_event);
} dns_scratch SEC(".maps");

// 解析 DNS 响应。用 bpf_skb_load_bytes 按整数偏移读包，避免变量偏移指针访问。
static __always_inline void dns_parse_and_report(struct __sk_buff *skb,
                                                  __u32 payload_off, __u32 payload_len)
{
    if (payload_len < 12) return;

    __u16 flags = 0, qd = 0, ancount = 0;
    bpf_skb_load_bytes(skb, payload_off + 2, &flags, 2);
    flags = bpf_ntohs(flags);
    if (!(flags & 0x8000)) return;               // 只处理响应
    bpf_skb_load_bytes(skb, payload_off + 4, &qd, 2);
    if (bpf_ntohs(qd) == 0) return;

    __u32 zero = 0;
    struct dns_event *ev = bpf_map_lookup_elem(&dns_scratch, &zero);
    if (!ev) return;
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->type = EVENT_DNS;
    ev->family = 2;                              // AF_INET

    // question name 的原始 label 字节拷入事件；点分转换交给用户态。
    // 注意：bpf_skb_load_bytes 的 len 必须是常量，且不能超过包剩余长度，
    // 否则短响应（如 youku 仅 58 字节）会整条失败。按剩余长度分档拷贝。
    {
        __u32 avail = payload_len - 12;
        if (avail >= 64) {
            if (bpf_skb_load_bytes(skb, payload_off + 12, ev->domain, 64) < 0) return;
        } else if (avail >= 48) {
            if (bpf_skb_load_bytes(skb, payload_off + 12, ev->domain, 48) < 0) return;
        } else if (avail >= 32) {
            if (bpf_skb_load_bytes(skb, payload_off + 12, ev->domain, 32) < 0) return;
        } else if (avail >= 16) {
            if (bpf_skb_load_bytes(skb, payload_off + 12, ev->domain, 16) < 0) return;
        } else if (avail >= 8) {
            if (bpf_skb_load_bytes(skb, payload_off + 12, ev->domain, 8) < 0) return;
        } else {
            return;
        }
    }

    // 推进 off 越过 question name（只读整数，不写内存）
    __u32 qoff = 12;
    for (int lab = 0; lab < 8; lab++) {
        __u8 llen = 0;
        if (qoff + 1 > payload_len) return;
        if (bpf_skb_load_bytes(skb, payload_off + qoff, &llen, 1) < 0) return;
        if (llen == 0) break;                     // 结尾 0 不推进：qtype 紧随其后
        if (llen > 32) return;
        qoff += 1 + llen;
    }
    __u32 off = qoff + 1 + 4;                     // 跳过结尾 0 + qtype/qclass
    if (off + 12 > payload_len) return;

    bpf_skb_load_bytes(skb, payload_off + 6, &ancount, 2);
    ancount = bpf_ntohs(ancount);

    // answer：只取第一条 A 记录（name=0xc00c、type=A、dlen=4）。
    // 不循环，避免 verifier 状态爆炸；多 A 记录场景只报首条。
    if (off + 12 <= payload_len) {
        __u16 name = 0, rtype = 0, dlen = 0;
        bpf_skb_load_bytes(skb, payload_off + off, &name, 2); off += 2;
        bpf_skb_load_bytes(skb, payload_off + off, &rtype, 2); off += 2;
        off += 2;                                // class
        off += 4;                                // ttl
        bpf_skb_load_bytes(skb, payload_off + off, &dlen, 2); off += 2;
        name = bpf_ntohs(name);
        rtype = bpf_ntohs(rtype);
        dlen = bpf_ntohs(dlen);
        if (name == 0xc00c && rtype == 1 && dlen == 4 && off + 4 <= payload_len) {
            struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
            if (e) {
                __builtin_memcpy(e, ev, sizeof(*ev));
                bpf_skb_load_bytes(skb, payload_off + off, e->ips, 4);
                e->ip_cnt = 1;
                bpf_ringbuf_submit(e, 0);
            }
        }
    }

}

SEC("classifier")
int dns_tc_ingress(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u32 *sw = bpf_map_lookup_elem(&dns_switch, &key);
    if (!sw || *sw == 0) return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
    if (udp->source != bpf_htons(53)) return TC_ACT_OK;   // DNS 响应

    __u32 payload_off = (__u32)((void *)udp + sizeof(*udp) - data);
    __u32 payload_len = skb->len - payload_off;
    dns_parse_and_report(skb, payload_off, payload_len);
    return TC_ACT_OK;
}