#!/usr/bin/env python3
"""
c2_defend/undo.py - Reverse firewall blocks
"""

from pathlib import Path
import subprocess

BLOCKLIST = Path("blocklist.txt")

def undo_block(line):
    try:
        ts, fw_type, zone, ip, port = line.strip().split("|")
        print(f"Removing block: {ip}:{port} (zone: {zone})")

        if fw_type == "firewalld":
            rule = f'rule family="ipv4" source address="{ip}" port port="{port}" protocol="tcp" drop'
            subprocess.run(["firewall-cmd", "--permanent", f"--zone={zone}", "--remove-rich-rule", rule], check=True)
            subprocess.run(["firewall-cmd", "--reload"], check=True)

        elif fw_type == "ufw":
            subprocess.run(["ufw", "delete", "deny", f"from {ip} to any port {port}"], check=True)

        elif fw_type == "iptables":
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--dport", port, "-j", "DROP"], check=True)

        print(f"Successfully removed block for {ip}:{port}")
    except Exception as e:
        print(f"Failed to undo: {e}")

def main():
    if not BLOCKLIST.exists() or BLOCKLIST.stat().st_size == 0:
        print("No blocks found to undo.")
        return

    with open(BLOCKLIST) as f:
        blocks = f.readlines()

    print(f"Found {len(blocks)} blocked entries:\n")
    for i, line in enumerate(blocks):
        ts, fw, zone, ip, port = line.strip().split("|")
        print(f"{i+1:2d}. {ip}:{port} | Zone: {zone} | Firewall: {fw}")

    choice = input("\nUndo ALL blocks? (y/N): ").strip().lower()
    if choice == "y":
        for line in blocks:
            undo_block(line)
        BLOCKLIST.unlink(missing_ok=True)
        print("All blocks removed successfully.")
    else:
        print("No changes made.")

if __name__ == "__main__":
    main()