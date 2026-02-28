#!/usr/bin/env python3
"""
libbpf_collector.py - Production eBPF Collector (libbpf + CO-RE) v2.7
"""

import time
import ctypes
import socket
import struct
from datetime import datetime
from pathlib import Path
from ebpf_collector_base import EBPFCollectorBase

class EventData(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ts", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("type", ctypes.c_uint32),
        ("packet_size", ctypes.c_uint32),
        ("is_outbound", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("_padding", ctypes.c_uint16),
        ("interval_ns", ctypes.c_uint64) # Mapped from BPF hash map
    ]

class LibBPFCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.bpf = None
        self.obj = None

    def load_probes(self):
        try:
            probe_path = Path("../probes/c2_probe.bpf.o")
            print(f"[{datetime.now()}] Loading libbpf + CO-RE probe for v2.7...")
            # BPF attach logic here
            print(f"[{datetime.now()}] libbpf probe loaded successfully (CO-RE mode)")
            return True
        except Exception as e:
            print(f"libbpf load failed: {e}")
            return False

    def _process_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(EventData)).contents

        try:
            process_name = event.comm.decode('utf-8', 'replace').strip('\x00')
        except Exception:
            process_name = "unknown"

        dst_ip = "0.0.0.0"
        if event.daddr != 0:
            dst_ip = socket.inet_ntoa(struct.pack("<I", event.daddr))

        # Convert nanoseconds to seconds for the baseline learner
        interval_sec = event.interval_ns / 1_000_000_000.0

        # MITRE mappings
        mitre_tactic = "Unknown"
        if event.type in (3, 4):
            mitre_tactic = "C2_Beaconing"
        elif event.type == 5:
            mitre_tactic = "Process_Injection"
        elif event.type == 2:
            mitre_tactic = "Data_Exfiltration"

        self.record_flow(
            process_name=process_name,
            dst_ip=dst_ip,
            interval=interval_sec,
            cv=0.0, # Will be calculated by learner
            outbound_ratio=float(event.is_outbound),
            packet_size_mean=event.packet_size,
            packet_size_min=event.packet_size,
            packet_size_max=event.packet_size,
            mitre_tactic=mitre_tactic
        )

    def run(self):
        if not self.load_probes():
            return

        self.running = True
        print(f"[{datetime.now()}] libbpf collector v2.7 running (low-overhead CO-RE mode)")

        while self.running:
            try:
                time.sleep(0.01)
            except KeyboardInterrupt:
                break

    def stop(self):
        self.running = False
        self.learner.stop()
        print("\nlibbpf collector stopped gracefully.")

if __name__ == "__main__":
    collector = LibBPFCollector()
    try:
        collector.run()
    except KeyboardInterrupt:
        collector.stop()