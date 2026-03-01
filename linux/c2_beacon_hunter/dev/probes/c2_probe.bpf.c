// c2_probe.bpf.c - CO-RE probe for v2.7
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[16];
    u32 type;           // 1=exec, 2=connect, 3=send, 4=recv, 5=memfd
    u32 packet_size;
    u32 is_outbound;
    u32 saddr;          // Source IPv4 address
    u32 daddr;          // Destination IPv4 address
    u16 dport;          // Destination Port
    u64 interval_ns;    // Time since last network event for this PID
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Hash map to track connection intervals
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // PID
    __type(value, u64); // Last seen timestamp
} last_seen_ts SEC(".maps");

static __always_inline void calculate_interval(struct data_t *data) {
    u64 *last_ts = bpf_map_lookup_elem(&last_seen_ts, &data->pid);
    if (last_ts) {
        data->interval_ns = data->ts - *last_ts;
    } else {
        data->interval_ns = 0;
    }
    bpf_map_update_elem(&last_seen_ts, &data->pid, &data->ts, BPF_ANY);
}

SEC("kprobe/sys_execve")
int trace_exec(struct pt_regs *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 1;
    data->interval_ns = 0;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 2;
    data->is_outbound = 1;

    bpf_probe_read_kernel(&data->saddr, sizeof(data->saddr), &sk->__sk_common.skc_rcv_saddr);  // Source IP
    bpf_probe_read_kernel(&data->daddr, sizeof(data->daddr), &sk->__sk_common.skc_daddr); // Destination IP
    bpf_probe_read_kernel(&data->dport, sizeof(data->dport), &sk->__sk_common.skc_dport); // Destination Port (network byte order)

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kretprobe/sys_sendmsg")
int trace_sendmsg_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;

    if (data->pid < 100) {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 3;
    data->is_outbound = 1;
    data->packet_size = ret;

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kretprobe/sys_recvmsg")
int trace_recvmsg_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;

    if (data->pid < 100) {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 4;
    data->packet_size = ret;

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/sys_memfd_create")
int trace_memfd(struct pt_regs *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 5;
    data->interval_ns = 0;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";