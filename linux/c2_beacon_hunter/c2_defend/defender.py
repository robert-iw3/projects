#!/usr/bin/env python3
"""
c2_defend/defender.py - Active protection engine
"""

import pandas as pd
import subprocess
import time
import os
from pathlib import Path

BLOCKLIST = Path("blocklist.txt")
LOGFILE = Path("defender.log")

def log_action(msg):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(LOGFILE, "a") as f:
        f.write(f"{ts} | {msg}\n")
    print(f"[+] {msg}")

def get_firewall_info():
    """Return (firewall_type, zone)"""
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
    try:
        if fw_type == "firewalld":
            rule = f'rule family="ipv4" source address="{ip}" port port="{port}" protocol="tcp" drop'
            subprocess.run(["firewall-cmd", "--permanent", f"--zone={zone}", "--add-rich-rule", rule], check=True)
            subprocess.run(["firewall-cmd", "--reload"], check=True)
            log_action(f"BLOCKED {ip}:{port} in zone '{zone}' via firewalld")

        elif fw_type == "ufw":
            subprocess.run(["ufw", "deny", f"from {ip} to any port {port}"], check=True)
            log_action(f"BLOCKED {ip}:{port} via ufw")

        elif fw_type == "iptables":
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP"], check=True)
            log_action(f"BLOCKED {ip}:{port} via iptables")

        # Log for undo
        with open(BLOCKLIST, "a") as f:
            f.write(f"{time.time()}|{fw_type}|{zone}|{ip}|{port}\n")

    except Exception as e:
        log_action(f"Failed to block {ip}:{port} - {e}")

def main():
    print("=== c2_defend - Active Defender (v1.1) ===")

    fw_type, zone = get_firewall_info()
    print(f"Firewall: {fw_type} | Zone: {zone or 'N/A'}")

    csv = Path("../output/anomalies.csv")
    if not csv.exists():
        print("No detections found yet.")
        return

    df = pd.read_csv(csv)
    suspicious = df[df["score"] >= 70]

    if suspicious.empty:
        print("No high-confidence suspicious flows found.")
        return

    print(f"\nFound {len(suspicious)} suspicious flows:\n")
    for i, row in suspicious.iterrows():
        print(f"{i+1:2d}. {row['process']} → {row['dst_ip']}:{row['dst_port']} | Score: {row['score']}")

    action = input("\nAction (k=kill, b=block, a=all, f=false-positive): ").strip().lower()

    for _, row in suspicious.iterrows():
        pid = int(row.get("pid", 0))
        ip = row["dst_ip"]
        port = int(row["dst_port"])
        proc = row["process"]

        if action in ["a", "k"] and pid > 0:
            try:
                subprocess.run(["kill", "-9", str(pid)], check=True)
                log_action(f"KILLED PID {pid} ({proc})")
            except:
                log_action(f"Failed to kill PID {pid}")

        if action in ["a", "b"]:
            block_ip_port(fw_type, zone, ip, port)

    print("\nActions completed. Check defender.log")

if __name__ == "__main__":
    main()