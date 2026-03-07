// v3.0/c2_promisc.bpf.c — Wire-speed promiscuous parser (IPv4 + IPv6)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct flow_key {
    __u8  saddr[16];
    __u8  daddr[16];
    __u16 sport;
    __u16 dport;
    __u8  proto;
} __attribute__((packed));

struct flow_event {
    __u64 ts;
    struct flow_key key;
    __u32 pkt_len;
    __u32 payload_hash;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

static __always_inline __u32 safe_hash(const void *data, __u32 len) {
    const __u8 *p = data;
    __u32 h = 0xdeadbeef;
    __u32 i = 0;
    for (; i < len && i < 64; i++) {
        if ((void *)(p + i + 1) > (void *)data + len) break;
        h = (h ^ p[i]) * 0x01000193;
    }
    return h;
}

SEC("xdp")
int xdp_c2_promisc(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // === PARANOID BOUNDS CHECKS ===
    if (data + sizeof(struct ethhdr) > data_end) return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct flow_key key = {};
    __u32 payload_offset = 0;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return XDP_PASS;
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return XDP_PASS;

        __u32 ihl = ip->ihl * 4;
        if (data + sizeof(struct ethhdr) + ihl + 4 > data_end) return XDP_PASS;

        key.proto = ip->protocol;
        __builtin_memcpy(&key.saddr[12], &ip->saddr, 4);
        __builtin_memcpy(&key.daddr[12], &ip->daddr, 4);

        void *trans = (void *)ip + ihl;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = trans;
            if ((void *)(tcp + 1) > data_end) return XDP_PASS;
            key.sport = bpf_ntohs(tcp->source);
            key.dport = bpf_ntohs(tcp->dest);
            payload_offset = sizeof(struct ethhdr) + ihl + sizeof(struct tcphdr);
        } else {
            struct udphdr *udp = trans;
            if ((void *)(udp + 1) > data_end) return XDP_PASS;
            key.sport = bpf_ntohs(udp->source);
            key.dport = bpf_ntohs(udp->dest);
            payload_offset = sizeof(struct ethhdr) + ihl + sizeof(struct udphdr);
        }
    } else {  // IPv6
        if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) return XDP_PASS;
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);

        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP) return XDP_PASS;

        key.proto = ip6->nexthdr;
        __builtin_memcpy(key.saddr, &ip6->saddr, 16);
        __builtin_memcpy(key.daddr, &ip6->daddr, 16);

        void *trans = (void *)ip6 + sizeof(struct ipv6hdr);
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = trans;
            if ((void *)(tcp + 1) > data_end) return XDP_PASS;
            key.sport = bpf_ntohs(tcp->source);
            key.dport = bpf_ntohs(tcp->dest);
            payload_offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr);
        } else {
            struct udphdr *udp = trans;
            if ((void *)(udp + 1) > data_end) return XDP_PASS;
            key.sport = bpf_ntohs(udp->source);
            key.dport = bpf_ntohs(udp->dest);
            payload_offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
        }
    }

    // === EMIT EVENT WITH FULL ERROR SAFETY ===
    struct flow_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return XDP_PASS;

    e->ts = bpf_ktime_get_ns();
    e->key = key;
    e->pkt_len = bpf_ntohs(eth->h_proto == bpf_htons(ETH_P_IP) ?
                           ((struct iphdr *)(eth + 1))->tot_len : 0);  // IPv6 length handled in user-space

    // Safe payload hash
    void *payload = data + payload_offset;
    __u32 sample_len = (void *)data_end - payload < 64 ? (void *)data_end - payload : 64;
    if (sample_len > 0 && payload + sample_len <= data_end)
        e->payload_hash = safe_hash(payload, sample_len);

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";