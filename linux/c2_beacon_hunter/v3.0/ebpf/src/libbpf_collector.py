#!/usr/bin/env python3
"""
libbpf_collector.py - eBPF Collector (C-Loader Subprocess Mode) - v3.0

Supports:
- mode = host      → original v2.8.2 behaviour (kprobes + process context)
- mode = promisc   → new wire-speed XDP parser with in-kernel aggregation (IPv4 + IPv6, 5-tuple flow tracking)
"""

import os
import time
import subprocess
import json
import threading
from datetime import datetime
from pathlib import Path
import configparser
from ebpf_collector_base import EBPFCollectorBase


class LibBPFCollector(EBPFCollectorBase):
    def __init__(self):
        super().__init__()
        self.process = None
        self.loader_path = None
        self.target_interface = os.environ.get("TARGET_INTERFACE", "wlo1")
        self.event_count = 0
        self.running = False

        self.mode = "host"
        self.capture_loopback = True
        try:
            parser = configparser.ConfigParser()
            config_files = ['config.ini', 'v3.0/config.ini', '/app/config.ini', '/app/ebpf/config_dev.ini']
            parsed = parser.read(config_files)
            if parser.has_section('general'):
                self.mode = parser.get('general', 'mode', fallback='host').strip().lower()
            if parser.has_section('ebpf'):
                self.capture_loopback = parser.getboolean('ebpf', 'capture_loopback', fallback=True)
            print(f"[LibBPF v3.0] Mode: {self.mode.upper()} | Loopback capture: {'ENABLED' if self.capture_loopback else 'DISABLED'}")
        except Exception as e:
            print(f"[ERROR] Config parsing failed: {e} — defaulting to host mode")

    def _is_loopback(self, ip: str) -> bool:
        if not ip:
            return True
        ip = ip.strip().lower()
        if ip in ("", "0.0.0.0", "127.0.0.1", "::1", "::"):
            return True
        if ip.startswith(("127.", "169.254.", "fe80::")):
            return True
        return False

    def load_probes(self):
        loader_name = "c2_promisc_loader" if self.mode == "promisc" else "c2_loader"
        search_paths = [
            Path(loader_name),
            Path(f"probes/{loader_name}"),
            Path(f"../probes/{loader_name}"),
            Path(f"/app/ebpf/probes/{loader_name}"),
            Path(f"v3.0/{loader_name}")
        ]

        for p in search_paths:
            if p.exists() and os.access(p, os.X_OK):
                self.loader_path = p
                print(f"[LibBPF] Using loader: {self.loader_path}")
                return True

        print(f"[CRITICAL ERROR] {loader_name} binary not found. Build it first with 'make' in v3.0/")
        return False

    def process_stdout(self):
        print(f"[Collector] Listening for events from {self.mode.upper()} loader on {self.target_interface}...")

        while self.running and self.process and self.process.poll() is None:
            try:
                line = self.process.stdout.readline()
                if not line:
                    continue
                line = line.strip()

                if not line.startswith('{'):
                    if line and any(k in line for k in ["XDP", "SUCCESS", "initialized", "PROMISC", "attached"]):
                        print(f"[C-Loader] {line}")
                    continue

                event = json.loads(line)
                self.event_count += 1

                dst_ip = event.get("dst_ip", "0.0.0.0")

                if not self.capture_loopback and self._is_loopback(dst_ip):
                    if self.event_count % 100 == 0:
                        print(f"[LOOPBACK SKIP #{self.event_count}] → {dst_ip}")
                    continue

                if self.mode == "promisc":
                    pkt_count = event.get("pkt_count", 1)
                    total_bytes = event.get("total_bytes", 0)
                    avg_interval_sec = event.get("avg_interval_ns", 0) / 1_000_000_000.0
                    cv = event.get("cv", 0) / 10000.0

                    print(f"[EVENT #{self.event_count:03d} AGGREGATED] → {dst_ip} | count={pkt_count} | avg_int={avg_interval_sec:.3f}s | cv={cv:.4f}")

                    self.record_flow(
                        process_name="network_flow",
                        dst_ip=dst_ip,
                        interval=avg_interval_sec,
                        cv=cv,
                        entropy=0.0,
                        packet_size_mean=total_bytes // max(pkt_count, 1),
                        packet_size_std=0.0,
                        packet_size_min=0,
                        packet_size_max=total_bytes,
                        mitre_tactic="C2_Beaconing",
                        pid=0
                    )
                    continue

                pid = event.get("pid", 0)
                process_name = event.get("comm", "unknown")
                raw_type = event.get("type", "unknown")
                packet_size = event.get("packet_size", 0)
                interval_ns = event.get("interval_ns", 0)
                interval_sec = interval_ns / 1_000_000_000.0
                entropy = event.get("entropy", 0.0)

                etype = str(raw_type).lower()

                if self.event_count <= 30 or self.event_count % 50 == 0:
                    print(f"[EVENT #{self.event_count:03d}] {etype.upper():<12} | "
                          f"PID:{pid:<6} | {process_name:<12} → {dst_ip} | "
                          f"entropy={entropy:.3f} | size={packet_size}")

                mitre_tactic = "Unknown"
                if etype in ["send", "3", "recv", "4", "dns", "6"] or etype == "tcp_payload":
                    mitre_tactic = "C2_Beaconing"
                elif etype in ["memfd", "5"]:
                    mitre_tactic = "Process_Injection"
                elif etype in ["connect", "2"]:
                    mitre_tactic = "Data_Exfiltration"
                elif etype in ["exec", "1"]:
                    mitre_tactic = "Execution"

                if etype == "tcp_payload" and entropy > 0.7:
                    mitre_tactic = "C2_Beaconing"

                self.record_flow(
                    process_name=process_name,
                    dst_ip=dst_ip,
                    interval=interval_sec,
                    entropy=entropy,
                    packet_size_mean=packet_size,
                    packet_size_std=0.0,
                    packet_size_min=packet_size,
                    packet_size_max=packet_size,
                    mitre_tactic=mitre_tactic,
                    pid=pid
                )

            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"[ERROR] process_stdout failed: {e}")

    def run(self):
        if not self.load_probes():
            return

        self.running = True
        print(f"[{datetime.now()}] libbpf collector running in {self.mode.upper()} mode on {self.target_interface}")

        try:
            self.process = subprocess.Popen(
                [str(self.loader_path), self.target_interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            threading.Thread(target=self.process_stdout, daemon=True).start()

            while self.running and self.process.poll() is None:
                time.sleep(1)

        except Exception as e:
            print(f"[CRITICAL] Loader startup failed: {e}")

    def stop(self):
        self.running = False
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception as e:
                print(f"[WARNING] Cleanup error: {e}")
        print("[LibBPF] Collector stopped.")


from collector_factory import register_collector
register_collector("libbpf", LibBPFCollector)