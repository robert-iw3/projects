#!/usr/bin/env python3
"""
libbpf_collector.py - eBPF Collector (libbpf + CO-RE)
"""

from ebpf_collector_base import EBPFCollectorBase
import time
from datetime import datetime
from pathlib import Path
import ctypes
import struct

class EventData(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ts", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("type", ctypes.c_uint32),
        ("packet_size", ctypes.c_uint32),
        ("is_outbound", ctypes.c_uint32),
        ("saddr", ctypes.c_uint32),    # New: source addr
        ("daddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("interval_ns", ctypes.c_uint64)
    ]

class LibBPFCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.bpf = None
        self.obj = None
        self.ringbuf = None

    def load_probes(self):
        try:
            probe_path = Path("../probes/c2_probe.bpf.o")
            if not probe_path.exists():
                print(f"Error: {probe_path} not found. Compile the C probe first.")
                return False

            # Load libbpf (assumes libbpf-python installed)
            import libbpf
            self.obj = libbpf.bpf_object_open(str(probe_path))
            if not self.obj:
                print("Failed to open BPF object")
                return False

            libbpf.bpf_object_load(self.obj)
            print(f"[{datetime.now()}] libbpf + CO-RE probe loaded successfully")

            # Attach all probes
            for prog_fd in libbpf.bpf_object_programs(self.obj):
                libbpf.bpf_program_attach(prog_fd)

            # Open ring buffer for events
            self.ringbuf = libbpf.bpf_map_lookup_elem(self.obj, b"events")
            return True
        except Exception as e:
            print(f"libbpf load failed: {e}")
            return False

    def _process_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
        process_name = event.comm.decode('utf-8', 'replace').strip('\x00')

        saddr = ".".join([str((event.saddr >> i) & 0xff) for i in [24, 16, 8, 0]])
        daddr = ".".join([str((event.daddr >> i) & 0xff) for i in [24, 16, 8, 0]])
        dport = event.dport

        interval_sec = event.interval_ns / 1_000_000_000.0

        # MITRE mapping logic
        mitre_tactic = "Unknown"
        if event.type in [3, 4]:
            mitre_tactic = "C2_Beaconing"
        elif event.type == 5:
            mitre_tactic = "Process_Injection"
        elif event.type == 2:
            mitre_tactic = "Data_Exfiltration"

        self.record_flow(
            process_name=process_name,
            dst_ip=daddr,
            interval=interval_sec,
            outbound_ratio=float(event.is_outbound),
            packet_size_mean=event.packet_size,
            packet_size_std=0,  # Can be expanded
            packet_size_min=event.packet_size,
            packet_size_max=event.packet_size,
            mitre_tactic=mitre_tactic
        )

    def run(self):
        if not self.load_probes():
            return
        self.running = True
        print(f"[{datetime.now()}] libbpf collector running (CO-RE mode)")

        while self.running:
            try:
                time.sleep(0.01)
            except KeyboardInterrupt:
                break

    def stop(self):
        self.running = False
        if self.obj:
            libbpf.bpf_object_close(self.obj)
        print("libbpf collector stopped.")


if __name__ == "__main__":
    collector = LibBPFCollector()
    try:
        collector.run()
    except KeyboardInterrupt:
        collector.stop()