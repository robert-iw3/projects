// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_DNS_LEN 64
#define PAYLOAD_SAMPLE_SIZE 64

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ==============================================================================
// eBPF-Friendly Shannon Entropy Lookup Table
// Since eBPF bans floats, this table holds (x * log2(x) * 100) for x in 0..64
// H * 100 = 600 - (sum_xlogx / 64)
// ==============================================================================
static const u32 xlogx[65] = {
    0, 0, 200, 475, 800, 1160, 1550, 1965, 2400, 2852, 3321, 3805,
    4301, 4810, 5329, 5859, 6400, 6950, 7509, 8078, 8655, 9240, 9834, 10435,
    11045, 11660, 12283, 12913, 13549, 14192, 14840, 15494, 16155, 16821,
    17492, 18169, 18850, 19537, 20228, 20924, 21624, 22329, 23038, 23751,
    24468, 25189, 25914, 26643, 27376, 28112, 28853, 29597, 30345, 31096,
    31851, 32609, 33370, 34135, 34903, 35674, 36449, 37226, 38006, 38789, 39575
};

struct event_t {
    u32 pid;
    u32 type; // 1 = UDP_DNS, 2 = TCP_ENTROPY
    u32 dst_ip;
    u16 dst_port;
    char comm[16];
    char dns_query[MAX_DNS_LEN];
    u32 payload_entropy; // Scaled by 100 (e.g., 795 = 7.95)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Story 3.1: In-Kernel DNS Parser
static __always_inline void parse_dns_query(void *payload, char *out) {
    // DNS Headers are exactly 12 bytes long. The query string starts at offset 12.
    int offset = 12;

    // Pragma unroll is mandatory because eBPF bans unbounded loops
    #pragma unroll
    for (int i = 0; i < MAX_DNS_LEN - 1; i++) {
        u8 c;
        if (bpf_probe_read_user(&c, 1, payload + offset) != 0) break;
        if (c == 0) {
            out[i] = '\0';
            break;
        }
        // Convert DNS length-prefix bytes to human-readable dots
        if (c < 32 || c > 126) out[i] = '.';
        else out[i] = c;
        offset++;
    }
    out[MAX_DNS_LEN - 1] = '\0';
}

// Story 3.2: In-Kernel Fast Shannon Entropy
static __always_inline u32 calc_entropy(void *payload) {
    u8 buf[PAYLOAD_SAMPLE_SIZE];
    if (bpf_probe_read_user(&buf, sizeof(buf), payload) != 0) return 0;

    u32 counts[256] = {0};

    #pragma unroll
    for (int i = 0; i < PAYLOAD_SAMPLE_SIZE; i++) {
        counts[buf[i]]++;
    }

    u32 sum_xlogx = 0;
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        u32 c = counts[i];
        if (c > 0 && c <= 64) {
            sum_xlogx += xlogx[c];
        }
    }

    // Calculate integer scaled entropy
    u32 entropy = 600 - (sum_xlogx / 64);
    return entropy;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (bpf_ntohs(dport) == 53) {
        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) return 0;

        e->type = 1; // UDP_DNS
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        e->dst_port = 53;

        // Safely extract the memory address of the UDP payload buffer
        struct iovec iov;
        bpf_probe_read_kernel(&iov, sizeof(iov), (void *)BPF_CORE_READ(msg, msg_iter.__iov));
        parse_dns_query(iov.iov_base, e->dns_query);

        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (size < PAYLOAD_SAMPLE_SIZE) return 0;

    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u16 port = bpf_ntohs(dport);

    // Only target common outbound web ports where C2 usually hides
    if (port != 80 && port != 443 && port != 8080 && port != 8443) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 2; // TCP_ENTROPY
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dst_port = port;

    // Safely extract the memory address of the TCP payload buffer
    struct iovec iov;
    bpf_probe_read_kernel(&iov, sizeof(iov), (void *)BPF_CORE_READ(msg, msg_iter.__iov));
    e->payload_entropy = calc_entropy(iov.iov_base);

    bpf_ringbuf_submit(e, 0);
    return 0;
}