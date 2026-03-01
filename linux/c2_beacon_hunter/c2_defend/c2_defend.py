#!/usr/bin/env python3
"""
==============================================================================
Script Name: c2_defend.py (Daemon Mode - Iteration 2.8.1)
Description: Automated threat mitigation daemon. Monitors anomalies.jsonl.
             Surgically terminates processes (psutil) and blackholes IPs
             using firewalld, ufw, or iptables.
Features:    Includes dry-run mode (--arm to enable) and firewalld zone awareness.
==============================================================================
"""

import json
import time
import psutil
import subprocess
import os
import sys
import argparse
from pathlib import Path

# Configuration [cite: 1, 4]
LOG_FILE = Path("../output/anomalies.jsonl")
BLOCKLIST = Path("blocklist.txt")
DAEMON_LOG = Path("c2_defend_daemon.log")
SCORE_THRESHOLD = 90

def log_action(msg, is_dry_run=True):
    prefix = "[DRY RUN]" if is_dry_run else "[ACTIVE]"
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    entry = f"{ts} | {prefix} {msg}"
    with open(DAEMON_LOG, "a") as f:
        f.write(entry + "\n")
    print(entry)

def get_firewall_info():
    """Detects firewall type and active zone."""
    if subprocess.call(["which", "firewall-cmd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        try:
            zone = subprocess.check_output(["firewall-cmd", "--get-default-zone"]).decode().strip()
            return "firewalld", zone
        except:
            return "firewalld", "public"
    elif subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return "ufw", None
    elif subprocess.call(["which", "iptables"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return "iptables", None
    return "none", None

def isolate_network(fw_type, zone, ip, port, arm=False):
    """Injects isolation rules (Story 1.3)[cite: 4, 8]."""
    if ip == "0.0.0.0" or fw_type == "none":
        return

    if not arm:
        log_action(f"WOULD ISOLATE: {ip}:{port} via {fw_type}", is_dry_run=True)
        return

    try:
        if fw_type == "firewalld":
            # Apply surgical Rich Rule
            if port == 0:
                rule = f'rule family="ipv4" source address="{ip}" drop'
            else:
                rule = f'rule family="ipv4" source address="{ip}" port port="{port}" protocol="tcp" drop'

            subprocess.run(["firewall-cmd", "--permanent", f"--zone={zone}", "--add-rich-rule", rule], check=True, capture_output=True)
            subprocess.run(["firewall-cmd", "--reload"], check=True, capture_output=True)

        elif fw_type == "ufw":
            if port == 0:
                subprocess.run(["ufw", "insert", "1", "deny", "from", ip], check=True, capture_output=True)
            else:
                subprocess.run(["ufw", "deny", f"from {ip} to any port {port}"], check=True, capture_output=True)

        elif fw_type == "iptables":
            # Dual-direction drop for maximum isolation
            cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
            if port != 0:
                cmd.extend(["-p", "tcp", "--dport", str(port)])
            subprocess.run(cmd, check=True)

        log_action(f"NETWORK ISOLATED: {ip}:{port} via {fw_type}", is_dry_run=False)

        # Log for undo.py (Story 1.4) [cite: 3, 4]
        with open(BLOCKLIST, "a") as f:
            f.write(f"{time.time()}|{fw_type}|{zone}|{ip}|{port}\n")

    except Exception as e:
        log_action(f"ERROR: Failed to block {ip} - {e}", is_dry_run=False)

def terminate_process(pid, arm=False):
    """Surgical termination using psutil (Story 1.2)."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        if not arm:
            log_action(f"WOULD TERMINATE: PID {pid} ({name})", is_dry_run=True)
            return

        proc.kill() # Direct kill as per Epic 1 requirements
        log_action(f"PROCESS TERMINATED: PID {pid} ({name})", is_dry_run=False)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        log_action(f"NOTICE: Could not terminate PID {pid} - {e}", is_dry_run=not arm)

def tail_log(file_path):
    """Continuously monitors log for new entries (Story 1.1)."""
    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def main():
    parser = argparse.ArgumentParser(description="C2 Defend Active Response Daemon")
    parser.add_argument("--arm", action="store_true", help="Enable active containment (Kill/Block)")
    args = parser.parse_args()

    if os.getuid() != 0:
        print("Fatal: Must run as root to manage firewalls and processes.")
        sys.exit(1)

    if not LOG_FILE.exists():
        LOG_FILE.touch()

    fw_type, zone = get_firewall_info()
    mode_str = "ACTIVE CONTAINMENT" if args.arm else "DRY RUN (Observation Only)"

    print(f"--- c2_defend Daemon: {mode_str} ---")
    print(f"Firewall: {fw_type} | Zone: {zone or 'N/A'}")
    log_action(f"Daemon started. Monitoring {LOG_FILE}")

    handled_events = set()
    for line in tail_log(LOG_FILE):
        try:
            data = json.loads(line.strip())
            if data.get("score", 0) >= SCORE_THRESHOLD:
                pid = data.get("pid")
                ip = data.get("dst_ip")
                port = data.get("dst_port", 0)
                event_key = f"{pid}_{ip}_{port}"

                if event_key not in handled_events:
                    handled_events.add(event_key)
                    terminate_process(pid, arm=args.arm)
                    isolate_network(fw_type, zone, ip, port, arm=args.arm)
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    main()