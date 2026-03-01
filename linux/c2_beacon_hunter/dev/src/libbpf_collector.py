#!/usr/bin/env python3
"""
libbpf_collector.py - eBPF Collector (C-Loader Subprocess Mode)

This module implements the LibBPFCollector class, which uses a native C loader to run a CO-RE eBPF program.
The collector spawns the C loader as a subprocess, which loads the eBPF program and captures events related
to process execution, network connections, and memory file descriptor creation.
The C loader outputs captured events in JSON format to stdout, which the Python collector reads and processes
to record flows for baseline learning.
This approach allows us to leverage the performance and compatibility benefits of libbpf and CO-RE while
maintaining the flexibility of Python for data processing and integration with the baseline learner.
"""

from ebpf_collector_base import EBPFCollectorBase
import time
import subprocess
import json
import threading
from datetime import datetime
from pathlib import Path

class LibBPFCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.process = None
        self.loader_path = None
        self.probe_path = None

    def load_probes(self):
        # Locate the compiled C binary
        loader_paths = [
            Path("probes/c2_loader"),
            Path("../probes/c2_loader"),
            Path("/app/dev/probes/c2_loader")
        ]
        self.loader_path = next((p for p in loader_paths if p.exists()), None)

        # Locate the BPF object file
        probe_paths = [
            Path("probes/c2_probe.bpf.o"),
            Path("../probes/c2_probe.bpf.o"),
            Path("/app/dev/probes/c2_probe.bpf.o")
        ]
        self.probe_path = next((p for p in probe_paths if p.exists()), None)

        if not self.loader_path or not self.probe_path:
            print("Error: c2_loader binary or c2_probe.bpf.o not found. Build them first.")
            return False
        return True

    def process_stdout(self):
        # Read the stdout stream line by line as the C program outputs JSON
        while self.running and self.process.poll() is None:
            line = self.process.stdout.readline()
            if not line:
                continue

            line = line.strip()
            # Ignore standard C debugging outputs, only parse JSON dictionaries
            if not line.startswith('{'):
                print(f"[C-Loader] {line}")
                continue

            try:
                event = json.loads(line)

                # Extract the PID sent by the C-Loader
                pid = event.get("pid", 0)

                process_name = event.get("comm", "unknown")
                event_type = event.get("type", 0)
                is_outbound = event.get("is_outbound", 0)
                packet_size = event.get("packet_size", 0)
                interval_ns = event.get("interval_ns", 0)
                daddr_int = event.get("daddr", 0)

                # Format destination IP address
                daddr = ".".join([str((daddr_int >> i) & 0xff) for i in [0, 8, 16, 24]])
                interval_sec = interval_ns / 1_000_000_000.0

                # MITRE mapping logic
                mitre_tactic = "Unknown"
                if event_type in [3, 4]:
                    mitre_tactic = "C2_Beaconing"
                elif event_type == 5:
                    mitre_tactic = "Process_Injection"
                elif event_type == 2:
                    mitre_tactic = "Data_Exfiltration"

                self.record_flow(
                    process_name=process_name,
                    dst_ip=daddr,
                    interval=interval_sec,
                    outbound_ratio=float(is_outbound),
                    packet_size_mean=packet_size,
                    packet_size_std=0.0,
                    packet_size_min=packet_size,
                    packet_size_max=packet_size,
                    mitre_tactic=mitre_tactic,
                    pid=pid  # NEW: Pass to base class
                )
            except json.JSONDecodeError:
                print(f"[C-Loader] Non-JSON Output: {line}")
            except Exception as e:
                print(f"Event processing error: {e}")

    def run(self):
        if not self.load_probes():
            return

        self.running = True
        print(f"[{datetime.now()}] libbpf collector running (Native C-Loader mode)")

        try:
            # Spawn the C loader, passing the probe path as an argument
            self.process = subprocess.Popen(
                [str(self.loader_path), str(self.probe_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # Start a thread to read stdout continuously
            reader_thread = threading.Thread(target=self.process_stdout, daemon=True)
            reader_thread.start()

            # Main loop just keeps the collector alive
            while self.running and self.process.poll() is None:
                time.sleep(1)

            if self.process.poll() is not None:
                err = self.process.stderr.read()
                print(f"C-Loader exited unexpectedly with code {self.process.returncode}. Stderr: {err}")

        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print(f"C-loader execution error: {e}")

    def stop(self):
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()