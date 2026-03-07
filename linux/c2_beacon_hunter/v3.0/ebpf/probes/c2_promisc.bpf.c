// v3.0/c2_promisc.bpf.c
// Wire-speed promiscuous parser (IPv4 + IPv6)
// In-Kernel Flow State Tracking
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

struct flow_state {
    __u64 first_ts;
    __u64 last_ts;
    __u32 pkt_count;
    __u64 sum_interval;
    __u64 sum_sq_interval;
    __u32 payload_hash;
    __u32 total_bytes;
};

struct aggregated_event {
    __u64 ts;
    struct flow_key key;
    __u32 pkt_count;
    __u32 total_bytes;
    __u32 payload_hash;
    __u64 avg_interval_ns;
    __u32 cv;                // scaled x10000
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flow_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

static __always_inline __u32 safe_hash(const void *data, __u32 len) {
    const __u8 *p = data;
    __u32 h = 0xdeadbeef;
    for (__u32 i = 0; i < len && i < 64; i++) {
        if ((void *)(p + i + 1) > (void *)data + len) break;
        h = (h ^ p[i]) * 0x01000193;
    }
    return h;
}

SEC("xdp")
int xdp_c2_promisc(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data + sizeof(struct ethhdr) > data_end) return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct flow_key key = {};
    __u64 now = bpf_ktime_get_ns();
    __u32 payload_offset = 0;

    // === IPv4 + IPv6 parsing with paramount bounds checking ===
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
    } else { // IPv6
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

    // === In-Kernel Aggregation (Epic 2) ===
    struct flow_state *state = bpf_map_lookup_elem(&flow_state_map, &key);
    struct flow_state new_state = {};

    if (state) {
        __u64 interval = now - state->last_ts;
        new_state.first_ts = state->first_ts;
        new_state.pkt_count = state->pkt_count + 1;
        new_state.sum_interval = state->sum_interval + interval;
        new_state.sum_sq_interval = state->sum_sq_interval + interval * interval;
        new_state.total_bytes = state->total_bytes + (bpf_ntohs(eth->h_proto == bpf_htons(ETH_P_IP) ?
            ((struct iphdr *)(eth + 1))->tot_len : 0));
        new_state.payload_hash = state->payload_hash;
    } else {
        new_state.first_ts = now;
        new_state.pkt_count = 1;
        new_state.sum_interval = 0;
        new_state.sum_sq_interval = 0;
        new_state.total_bytes = 0;
    }
    new_state.last_ts = now;

    bpf_map_update_elem(&flow_state_map, &key, &new_state, BPF_ANY);

    // Emit aggregated event (rate-limited)
    if (new_state.pkt_count % 8 == 0 || new_state.pkt_count == 1) {
        struct aggregated_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->ts = now;
            e->key = key;
            e->pkt_count = new_state.pkt_count;
            e->total_bytes = new_state.total_bytes;
            e->payload_hash = new_state.payload_hash;
            e->avg_interval_ns = new_state.pkt_count > 1 ? new_state.sum_interval / (new_state.pkt_count - 1) : 0;

            __u64 variance = 0;
            if (new_state.pkt_count > 2) {
                __u64 mean = e->avg_interval_ns;
                variance = (new_state.sum_sq_interval / (new_state.pkt_count - 1)) - (mean * mean);
            }
            e->cv = variance > 0 ? (variance * 10000) / (e->avg_interval_ns * e->avg_interval_ns + 1) : 0;

            bpf_ringbuf_submit(e, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";