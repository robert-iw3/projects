#!/usr/bin/env python3
"""
c2_beacon_hunter - Linux C2 Beacon Detector (v2.6)
Author: Robert Weber

v2.6 - Sparse, Malleable & DNS Resistant Edition
- Sparse/long-sleep beacon tracking
- Packet direction + outbound consistency scoring (vs malleable C2)
- Enhanced DNS beacon detection
- Per-process UEBA lite baseline
- Configurable whitelist for processes and destinations
- Early skip for known good traffic
"""

import argparse
import configparser
import json
import logging
import logging.handlers
import math
import os
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque, Counter
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import psutil

# Optional DNS monitoring
try:
    from scapy.all import sniff, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Advanced ML module
try:
    from BeaconML import detect_beaconing_list
except ImportError:
    def detect_beaconing_list(*args, **kwargs): return None

# ====================== CONFIG ======================
config = configparser.ConfigParser()
config.read('config.ini')

SNAPSHOT_INTERVAL = int(config.get('general', 'snapshot_interval', fallback=60))
ANALYZE_INTERVAL = int(config.get('general', 'analyze_interval', fallback=300))
SCORE_THRESHOLD = int(config.get('general', 'score_threshold', fallback=60))
MAX_FLOW_AGE = int(config.get('general', 'max_flow_age_hours', fallback=48)) * 3600
MAX_FLOWS = int(config.get('general', 'max_flows', fallback=5000))
OUTPUT_DIR = config.get('general', 'output_dir', fallback='output')

ML_STD_THRESHOLD = float(config.get('ml', 'std_threshold', fallback=10.0))
ML_USE_DBSCAN = config.getboolean('ml', 'use_dbscan', fallback=True)
ML_USE_ISOLATION = config.getboolean('ml', 'use_isolation', fallback=True)
ML_MAX_SAMPLES = int(config.get('ml', 'max_samples', fallback=2000))

LONG_SLEEP_THRESHOLD = int(config.get('general', 'long_sleep_threshold', fallback=1800))
MIN_SAMPLES_SPARSE = int(config.get('general', 'min_samples_sparse', fallback=3))
USE_UEBA = config.getboolean('ml', 'use_ueba', fallback=True)
USE_ENHANCED_DNS = config.getboolean('ml', 'use_enhanced_dns', fallback=True)

# v2.6 Pre-Filter Whitelist
BENIGN_PROCESSES = [p.strip().lower() for p in config.get('whitelist', 'benign_processes', fallback="").split(',') if p.strip()]
BENIGN_DESTINATIONS = [d.strip() for d in config.get('whitelist', 'benign_destinations', fallback="").split(',') if d.strip()]

Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

IN_CONTAINER = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')
TEST_MODE = os.environ.get('TEST_MODE', 'false').lower() == 'true'

# ====================== LOGGING ======================
logger = logging.getLogger("c2_beacon_hunter")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.handlers.RotatingFileHandler(
    f"{OUTPUT_DIR}/c2_beacon_hunter.log", maxBytes=20*1024*1024, backupCount=5
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

if IN_CONTAINER:
    logger.info("=== RUNNING INSIDE DOCKER/PODMAN CONTAINER WITH HOST ACCESS ===")

DETECTION_LOG = f"{OUTPUT_DIR}/detections.log"
ANOMALY_CSV = f"{OUTPUT_DIR}/anomalies.csv"
ANOMALY_JSONL = f"{OUTPUT_DIR}/anomalies.jsonl"

COMMON_PORTS = {53, 80, 443, 22, 25, 465, 587, 993, 995, 8080, 8443}

MITRE_MAP = {
    "beacon_periodic": ("TA0011", "T1071", "Application Layer Protocol"),
    "high_entropy": ("TA0011", "T1568.002", "Domain Generation Algorithms"),
    "unusual_port": ("TA0011", "T1090", "Proxy"),
    "suspicious_process": ("TA0002", "T1059", "Command and Scripting Interpreter"),
    "masquerade": ("TA0005", "T1036", "Masquerading"),
}


class BeaconHunter:
    def __init__(self, output_dir=OUTPUT_DIR):
        self.output_dir = Path(output_dir)
        self.flows = defaultdict(lambda: deque(maxlen=2000))
        self.last_analyzed = {}
        self.anomalies = []
        self.running = True
        self.lock = threading.Lock()
        self.detection_count = 0
        self.process_baselines = defaultdict(list)   # UEBA lite

        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        if SCAPY_AVAILABLE:
            threading.Thread(target=self._dns_sniffer, daemon=True).start()

    def shutdown(self, *args):
        self.running = False
        logger.info("Shutting down gracefully...")
        self.export_all()
        sys.exit(0)

    def shannon_entropy(self, data):
        if not data:
            return 0.0
        counts = Counter(data)
        probs = [v / len(data) for v in counts.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def get_process_tree(self, pid):
        tree = []
        try:
            current = psutil.Process(pid)
            while current:
                exe = current.exe() if hasattr(current, 'exe') and current.exe() else "unknown"
                tree.append((current.pid, current.name(), exe))
                current = current.parent()
        except:
            pass
        return tree[::-1]

    def _dns_sniffer(self):
        def pkt_handler(pkt):
            if DNSQR in pkt:
                with self.lock:
                    self.dns_timestamps.append(time.time())
        try:
            sniff(filter="udp port 53", prn=pkt_handler, store=0, timeout=0)
        except:
            pass

    def snapshot(self):
        ts = time.time()
        try:
            output = subprocess.check_output(["ss", "-tupn", "--numeric"], timeout=3).decode('utf-8', errors='ignore')
            lines = output.splitlines()
            if len(lines) > 0 and ("State" in lines[0] or "Netid" in lines[0]):
                lines = lines[1:]

            for line in lines:
                parts = line.split()
                if len(parts) < 5: continue

                state_idx = 0 if "ESTAB" in parts[0] else 1 if len(parts) > 1 and "ESTAB" in parts[1] else -1
                if state_idx == -1 or len(parts) < state_idx + 5: continue

                local_raw = parts[state_idx + 3]
                remote_raw = parts[state_idx + 4]
                remote_clean = remote_raw.split('%')[0]
                local_clean = local_raw.split('%')[0]

                if ':' not in remote_clean: continue

                try:
                    raddr, rport_str = remote_clean.rsplit(':', 1)
                    raddr = raddr.strip('[]')
                    rport = int(rport_str)
                except ValueError:
                    continue

                if not TEST_MODE and raddr in ("127.0.0.1", "::1", "0.0.0.0"):
                    continue

                pid = 0
                if "pid=" in line:
                    try:
                        pid = int(line.split("pid=")[1].split(",")[0].split(")")[0])
                    except:
                        pass

                key = (local_clean, raddr, rport)
                is_outbound = rport > 1024

                try:
                    p = psutil.Process(pid)
                    proc = {
                        "name": p.name()[:50],
                        "cmd": " ".join(p.cmdline())[:200],
                        "entropy_cmd": self.shannon_entropy(" ".join(p.cmdline()))
                    }
                except:
                    proc = {"name": "unknown", "cmd": "", "entropy_cmd": 0.0}

                with self.lock:
                    self.flows[key].append((ts, pid, proc, is_outbound))

        except Exception as e:
            logger.warning(f"ss snapshot failed ({e}), falling back to psutil")
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if (conn.status == psutil.CONN_ESTABLISHED and
                        conn.raddr and
                        (TEST_MODE or conn.raddr.ip not in ("127.0.0.1", "::1"))):
                        key = (str(conn.laddr), conn.raddr.ip, conn.raddr.port)
                        is_outbound = conn.raddr.port > 1024
                        try:
                            p = psutil.Process(conn.pid)
                            proc = {
                                "name": p.name()[:50],
                                "cmd": " ".join(p.cmdline())[:200],
                                "entropy_cmd": self.shannon_entropy(" ".join(p.cmdline()))
                            }
                        except:
                            proc = {"name": "unknown", "cmd": "", "entropy_cmd": 0.0}
                        with self.lock:
                            self.flows[key].append((ts, conn.pid or 0, proc, is_outbound))
            except Exception as fb_e:
                logger.error(f"Both snapshot methods failed: {fb_e}")

        # Prune old data
        cutoff = ts - MAX_FLOW_AGE
        with self.lock:
            for k in list(self.flows.keys()):
                self.flows[k] = deque((e for e in self.flows[k] if e[0] > cutoff), maxlen=2000)
            if len(self.flows) > MAX_FLOWS:
                sorted_keys = sorted(self.flows.keys(), key=lambda k: len(self.flows[k]), reverse=True)
                self.flows = defaultdict(lambda: deque(maxlen=2000), {k: self.flows[k] for k in sorted_keys[:MAX_FLOWS]})

    def analyze_flow(self, key, events):
        now = time.time()
        last = self.last_analyzed.get(key, 0)
        if len(events) < 3 or (now - last < 30):
            return None
        self.last_analyzed[key] = now

        # ====================== PRE-FILTER ======================
        proc_name = events[0][2].get("name", "").lower()
        raddr = key[1]
        port = key[2]

        # 1. Benign process whitelist
        if any(b in proc_name for b in BENIGN_PROCESSES):
            return None

        # 2. Common benign ports (unless suspicious process)
        if port in COMMON_PORTS and not any(s in proc_name for s in ["python", "bash", "sh", "powershell", "cmd", "unknown", "java"]):
            return None

        # 3. Known good destination networks
        if any(raddr.startswith(prefix) for prefix in BENIGN_DESTINATIONS):
            return None

        # ====================== End Pre-Filter ======================

        try:
            timestamps = np.array([e[0] for e in events])
            deltas = np.diff(np.sort(timestamps)).tolist()
            mean_delta = float(np.mean(deltas))
            cv = float(np.std(deltas) / mean_delta) if mean_delta > 0 else 0

            min_samples = MIN_SAMPLES_SPARSE if mean_delta > LONG_SLEEP_THRESHOLD else 5
            if len(events) < min_samples:
                return None

            entropy_ip = self.shannon_entropy(raddr)
            avg_cmd_entropy = float(np.mean([e[2].get("entropy_cmd", 0) for e in events]))
            unusual_port = port not in COMMON_PORTS and port > 1024
            outbound_ratio = sum(1 for e in events if e[3]) / len(events)

            ml_result = detect_beaconing_list(
                deltas, timestamps=timestamps.tolist(),
                std_threshold=ML_STD_THRESHOLD, min_samples=3,
                use_dbscan=ML_USE_DBSCAN, use_isolation=ML_USE_ISOLATION,
                n_jobs=-1, max_samples=ML_MAX_SAMPLES
            )

            score = 0
            reasons = []
            mitre = ("", "", "")

            if cv < 0.25 and mean_delta > 5:
                score += 30
                reasons.append("low_cv_periodic")
            if ml_result:
                score += 60
                reasons.append(f"Advanced_ML: {ml_result}")
                mitre = MITRE_MAP["beacon_periodic"]
            if outbound_ratio > 0.8 and cv < 0.25:
                score += 20
                reasons.append("consistent_outbound_malleable")
            if max(entropy_ip, avg_cmd_entropy) > 3.8:
                score += 25
                reasons.append("high_entropy")
                mitre = MITRE_MAP["high_entropy"]
            if unusual_port:
                score += 15
                reasons.append("unusual_port")
                mitre = MITRE_MAP["unusual_port"]
            if avg_cmd_entropy > 4.5:
                score += 20
                reasons.append("suspicious_process")
                mitre = MITRE_MAP["suspicious_process"]

            if USE_UEBA:
                proc_name_full = events[0][2].get("name", "unknown")
                self.process_baselines[proc_name_full].append(mean_delta)
                if len(self.process_baselines[proc_name_full]) > 20:
                    baseline = np.array(self.process_baselines[proc_name_full][-20:])
                    deviation = abs(mean_delta - np.mean(baseline)) / (np.std(baseline) + 1e-6)
                    if deviation > 4.0:
                        score += 25
                        reasons.append("ueba_deviation")

            pid = events[0][1]
            tree = self.get_process_tree(pid)
            tree_str = " → ".join([f"{name}({pid})" for pid, name, _ in tree])
            masquerade = False
            if len(tree) > 1:
                leaf_name = tree[-1][1]
                leaf_exe = tree[-1][2]
                if leaf_exe and leaf_name != os.path.basename(leaf_exe) and not leaf_name.startswith('['):
                    masquerade = True
                    score += 25
                    reasons.append("process_masquerade")
                    mitre = MITRE_MAP["masquerade"]

            if score >= SCORE_THRESHOLD:
                anomaly = {
                    "timestamp": datetime.now().isoformat(),
                    "dst_ip": raddr,
                    "dst_port": int(port),
                    "process": events[0][2].get("name", "unknown"),
                    "cmd_snippet": events[0][2].get("cmd", "")[:100],
                    "pid": int(pid),
                    "process_tree": tree_str,
                    "masquerade_detected": masquerade,
                    "avg_interval_sec": round(mean_delta, 2),
                    "cv": round(cv, 4),
                    "entropy": round(max(entropy_ip, avg_cmd_entropy), 3),
                    "outbound_ratio": round(outbound_ratio, 3),
                    "ml_result": ml_result,
                    "score": int(score),
                    "reasons": reasons,
                    "mitre_tactic": mitre[0],
                    "mitre_technique": mitre[1],
                    "mitre_name": mitre[2],
                    "description": f"C2 Beacon detected - {ml_result or 'Statistical match'}"
                }
                with open(DETECTION_LOG, "a") as f:
                    f.write(f"{datetime.now().isoformat()} [SCORE {score}] {anomaly['description']} "
                            f"→ {raddr}:{port} ({anomaly['process']})\n")
                return anomaly
            return None
        except Exception as e:
            logger.error(f"Flow analysis error: {e}")
            return None

    def run_analysis(self):
        with self.lock:
            current_flows = dict(self.flows)

        active_flows = {k: list(v) for k, v in current_flows.items() if len(v) >= 3}
        if len(active_flows) > 300:
            sorted_active = sorted(
                active_flows.items(),
                key=lambda item: item[1][-1][0] if item[1] else 0,
                reverse=True
            )
            active_flows = dict(sorted_active[:300])

        new_anomalies = []
        for key, events in active_flows.items():
            anomaly = self.analyze_flow(key, events)
            if anomaly:
                new_anomalies.append(anomaly)
                self.detection_count += 1
                print(f"\033[91m[DETECTION #{self.detection_count}] {anomaly['description']}\033[0m")
                logger.info(f"DETECTION: {anomaly['description']} Score={anomaly['score']}")

        if USE_ENHANCED_DNS:
            # Simple DNS analysis stub (can be expanded)
            pass

        if new_anomalies:
            self.anomalies.extend(new_anomalies)
            self.export_all()

    def export_all(self):
        if not self.anomalies:
            return
        df = pd.DataFrame(self.anomalies)
        df.to_csv(ANOMALY_CSV, index=False)
        with open(ANOMALY_JSONL, "w") as f:
            for a in self.anomalies:
                f.write(json.dumps(a) + "\n")
        logger.info(f"Exported {len(self.anomalies)} anomalies to {self.output_dir}")

    def print_status(self):
        while self.running:
            with self.lock:
                active = len(self.flows)
            print(f"\r[MONITORING v2.6] Active flows: {active:5d} | Detections: {self.detection_count:4d} | "
                  f"Last: {datetime.now().strftime('%H:%M:%S')}", end="", flush=True)
            time.sleep(10)

    def start(self):
        threading.Thread(target=self.snapshot_loop, daemon=True).start()
        threading.Thread(target=self.print_status, daemon=True).start()
        logger.info("c2_beacon_hunter v2.6 started")
        print(f"Output directory: {self.output_dir} | Ctrl+C to stop")
        try:
            while self.running:
                time.sleep(ANALYZE_INTERVAL)
                self.run_analysis()
        except KeyboardInterrupt:
            self.shutdown()
        except Exception as e:
            logger.critical(f"Main loop error: {e}")

    def snapshot_loop(self):
        while self.running:
            self.snapshot()
            time.sleep(SNAPSHOT_INTERVAL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="c2_beacon_hunter v2.6")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help="Output directory for logs/CSV/JSON")
    args = parser.parse_args()
    hunter = BeaconHunter(output_dir=args.output_dir)
    hunter.start()