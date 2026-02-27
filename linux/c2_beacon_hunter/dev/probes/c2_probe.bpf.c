// c2_probe.bpf.c - Optimized CO-RE probe for v2.7
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
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB ring buffer for high throughput
} events SEC(".maps");

SEC("kprobe/sys_execve")
int trace_exec(struct pt_regs *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 1;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/sys_connect")
int trace_connect(struct pt_regs *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 2;
    data->is_outbound = 1;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/sys_sendmsg")
int trace_sendmsg(struct pt_regs *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 3;
    data->is_outbound = 1;
    data->packet_size = PT_REGS_PARM3(ctx);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/sys_recvmsg")
int trace_recvmsg(struct pt_regs *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 4;
    data->packet_size = PT_REGS_PARM3(ctx);
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
    bpf_ringbuf_submit(data, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";