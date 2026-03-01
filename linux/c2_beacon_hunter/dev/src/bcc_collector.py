#!/usr/bin/env python3
"""
bcc_collector.py - BCC backend
"""

from ebpf_collector_base import EBPFCollectorBase
from bcc import BPF
import time
from datetime import datetime

class BCCCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.bpf = None

    def load_probes(self):
        try:
            bpf_text = """
            #include <uapi/linux/ptrace.h>
            #include <linux/sched.h>

            struct data_t {
                u32 pid;
                u64 ts;
                char comm[16];
                u32 type;
                u32 packet_size;
                u32 is_outbound;
            };

            BPF_PERF_OUTPUT(events);

            int trace_exec(struct pt_regs *ctx) {
                struct data_t data = {};
                data.pid = bpf_get_current_pid_tgid() >> 32;
                data.ts = bpf_ktime_get_ns();
                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                data.type = 1;
                events.perf_submit(ctx, &data, sizeof(data));
                return 0;
            }

            int trace_connect(struct pt_regs *ctx) {
                struct data_t data = {};
                data.pid = bpf_get_current_pid_tgid() >> 32;
                data.ts = bpf_ktime_get_ns();
                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                data.type = 2;
                data.is_outbound = 1;
                events.perf_submit(ctx, &data, sizeof(data));
                return 0;
            }

            int trace_sendmsg(struct pt_regs *ctx) {
                struct data_t data = {};
                data.pid = bpf_get_current_pid_tgid() >> 32;
                data.ts = bpf_ktime_get_ns();
                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                data.type = 3;
                data.is_outbound = 1;
                data.packet_size = PT_REGS_PARM3(ctx);
                events.perf_submit(ctx, &data, sizeof(data));
                return 0;
            }

            int trace_recvmsg(struct pt_regs *ctx) {
                struct data_t data = {};
                data.pid = bpf_get_current_pid_tgid() >> 32;
                data.ts = bpf_ktime_get_ns();
                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                data.type = 4;
                data.packet_size = PT_REGS_PARM3(ctx);
                events.perf_submit(ctx, &data, sizeof(data));
                return 0;
            }

            int trace_memfd(struct pt_regs *ctx) {
                struct data_t data = {};
                data.pid = bpf_get_current_pid_tgid() >> 32;
                data.ts = bpf_ktime_get_ns();
                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                data.type = 5;
                events.perf_submit(ctx, &data, sizeof(data));
                return 0;
            }
            """

            self.bpf = BPF(text=bpf_text)
            self.bpf.attach_kprobe(event="__x64_sys_execve", fn_name="trace_exec")
            self.bpf.attach_kprobe(event="__x64_sys_connect", fn_name="trace_connect")
            self.bpf.attach_kprobe(event="__x64_sys_sendmsg", fn_name="trace_sendmsg")
            self.bpf.attach_kprobe(event="__x64_sys_recvmsg", fn_name="trace_recvmsg")
            self.bpf.attach_kprobe(event="__x64_sys_memfd_create", fn_name="trace_memfd")

            print(f"[{datetime.now()}] BCC probes loaded successfully")
            return True
        except Exception as e:
            print(f"Failed to load BCC probes: {e}")
            return False

    def process_event(self, cpu, data, size):
        try:
            event = self.bpf["events"].event(data)
            process_name = event.comm.decode('utf-8', errors='ignore').strip()

            if event.type == 1:
                self.record_flow(process_name, "0.0.0.0")
            elif event.type == 2:
                self.record_flow(process_name, "0.0.0.0", outbound_ratio=1.0)
            elif event.type == 3:
                self.record_flow(process_name, "0.0.0.0", outbound_ratio=1.0, packet_size_mean=event.packet_size)
            elif event.type == 4:
                self.record_flow(process_name, "0.0.0.0", packet_size_mean=event.packet_size)
            elif event.type == 5:
                self.record_flow(process_name, "0.0.0.0")
        except Exception as e:
            print(f"Event processing error: {e}")

    def run(self):
        if not self.load_probes():
            return
        self.bpf["events"].open_perf_buffer(self.process_event)
        self.running = True
        print(f"[{datetime.now()}] BCC collector running (optimized)")

        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"BCC poll error: {e}")

    def stop(self):
        self.running = False
        print("BCC collector stopped.")


if __name__ == "__main__":
    collector = BCCCollector()
    try:
        collector.run()
    except KeyboardInterrupt:
        collector.stop()