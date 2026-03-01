#!/usr/bin/env python3
"""
c2_defend/defender.py - Active protection engine (DFIR Enhanced)
"""

import json
import subprocess
import time
import os
import signal
from pathlib import Path

BLOCKLIST = Path("blocklist.txt")
LOGFILE = Path("defender.log")
JSONL_LOG = Path("../output/anomalies.jsonl")

def log_action(msg):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(LOGFILE, "a") as f:
        f.write(f"{ts} | {msg}\n")
    print(f"[+] {msg}")

def get_firewall_info():
    if subprocess.call(["which", "firewall-cmd"], stdout=subprocess.DEVNULL) == 0:
        try:
            zone = subprocess.check_output(["firewall-cmd", "--get-default-zone"]).decode().strip()
            return "firewalld", zone
        except:
            return "firewalld", "public"
    elif subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL) == 0:
        return "ufw", None
    elif subprocess.call(["which", "iptables"], stdout=subprocess.DEVNULL) == 0:
        return "iptables", None
    return "none", None

def block_ip_port(fw_type, zone, ip, port):
    # Prevent crashing if IP is internal 0.0.0.0
    if ip == "0.0.0.0":
        return

    try:
        if fw_type == "firewalld":
            if port == 0:
                rule = f'rule family="ipv4" source address="{ip}" drop'
            else:
                rule = f'rule family="ipv4" source address="{ip}" port port="{port}" protocol="tcp" drop'

            subprocess.run(["firewall-cmd", "--permanent", f"--zone={zone}", "--add-rich-rule", rule], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["firewall-cmd", "--reload"], check=True, stdout=subprocess.DEVNULL)

        elif fw_type == "ufw":
            if port == 0:
                subprocess.run(["ufw", "deny", f"from", ip], check=True, stdout=subprocess.DEVNULL)
            else:
                subprocess.run(["ufw", "deny", f"from", ip, "to", "any", "port", str(port)], check=True, stdout=subprocess.DEVNULL)

        elif fw_type == "iptables":
            if port == 0:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            else:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP"], check=True)

        log_action(f"BLOCKED IP {ip} (Port: {port if port != 0 else 'ALL'}) via {fw_type}")

        # Log for undo utility
        with open(BLOCKLIST, "a") as f:
            f.write(f"{time.time()}|{fw_type}|{zone}|{ip}|{port}\n")

    except Exception as e:
        log_action(f"Failed to block {ip}:{port} - {e}")

def main():
    print("=== c2_defend - Active Defender (DFIR Edition) ===")

    fw_type, zone = get_firewall_info()
    print(f"Firewall: {fw_type} | Zone: {zone or 'N/A'}")

    if not JSONL_LOG.exists():
        print(f"No log found at {JSONL_LOG}")
        return

    # Parse JSONL directly
    suspicious = []
    with open(JSONL_LOG, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("score", 0) >= 80:
                    # Deduplicate based on PID and IP
                    if not any(s['pid'] == data['pid'] and s['dst_ip'] == data['dst_ip'] for s in suspicious):
                        suspicious.append(data)
            except:
                continue

    if not suspicious:
        print("No high-confidence suspicious flows found (Score >= 80).")
        return

    print(f"\nFound {len(suspicious)} high-risk anomalies:\n")
    for i, row in enumerate(suspicious):
        ip_display = row['dst_ip'] if row['dst_ip'] != '0.0.0.0' else 'Local/Masquerade'
        print(f"{i+1:2d}. PID: {row['pid']} ({row['process']}) → {ip_display}:{row['dst_port']} | Score: {row['score']}")

    print("\n[DFIR NOTE] We recommend 'f' (Freeze) instead of 'k' (Kill) to prevent systemd restarts and preserve memory.")
    action = input("\nAction (f=freeze, k=kill, b=block ip, a=all (freeze+block), q=quit): ").strip().lower()

    if action == 'q':
        return

    for row in suspicious:
        pid = int(row.get("pid", 0))
        ip = row.get("dst_ip")
        port = int(row.get("dst_port", 0))
        proc = row.get("process")

        if action in ["a", "f"] and pid > 0:
            try:
                # SIGSTOP freezes the process without killing it.
                # This breaks the C2 connection but allows you to dump memory later.
                os.kill(pid, signal.SIGSTOP)
                log_action(f"FROZE (SIGSTOP) PID {pid} ({proc}) to preserve memory and stop restarts.")
            except ProcessLookupError:
                log_action(f"PID {pid} no longer running.")
            except Exception as e:
                log_action(f"Failed to freeze PID {pid} - {e}")

        if action == "k" and pid > 0:
            try:
                os.kill(pid, signal.SIGKILL)
                log_action(f"KILLED (SIGKILL) PID {pid} ({proc})")
            except Exception as e:
                pass

        if action in ["a", "b"]:
            block_ip_port(fw_type, zone, ip, port)

    print("\nActions completed. Check defender.log")

if __name__ == "__main__":
    main()