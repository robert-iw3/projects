#!/usr/bin/env python3
"""
C2 Beacon Simulator for testing c2_beacon_hunter v2.6

# 1. Test Pre-filter (should be skipped)
./tests/test_beacon_simulator.py --process-name firefox --period 60 --jitter 0.1 --duration 120

# 2. Test Sparse / Long-sleep tracking
./tests/test_beacon_simulator.py --long-sleep --period 1800 --jitter 0.2 --duration 7200

# 3. Test Malleable C2 (high outbound ratio)
./tests/test_beacon_simulator.py --high-outbound --period 60 --jitter 0.35 --duration 300

# 4. Test UEBA + normal suspicious process
./tests/test_beacon_simulator.py --process-name python --period 45 --jitter 0.4 --duration 240
"""

import argparse
import socket
import time
import random
import threading
import subprocess
import sys

def start_listener(port: int):
    def server():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(5)
        print(f"[+] Listener started on 0.0.0.0:{port}")
        while True:
            try:
                conn, addr = s.accept()
                print(f"[+] Accepted from {addr}")
                time.sleep(2)
                conn.close()
            except:
                break
    t = threading.Thread(target=server, daemon=True)
    t.start()
    return t

def send_beacon(target_ip: str, port: int, hold_time: float = 8.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((target_ip, port))
        junk = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=80))
        s.sendall(junk.encode())
        time.sleep(hold_time)
        s.close()
        return True
    except Exception as e:
        print(f"[-] Beacon failed: {e}")
        return False

def firewall_open_port(port: int):
    try:
        zone = subprocess.check_output(['sudo', 'firewall-cmd', '--get-default-zone']).decode().strip()
        print(f"[+] Firewalld detected - zone: {zone}")
        subprocess.check_call(['sudo', 'firewall-cmd', '--zone', zone, '--add-port', f'{port}/tcp'])
        print(f"[+] Port {port} opened in zone {zone}")
        return zone
    except Exception:
        print("[-] Firewall adjustment skipped")
        return None

def firewall_close_port(port: int, zone: str):
    if not zone:
        return
    try:
        subprocess.check_call(['sudo', 'firewall-cmd', '--zone', zone, '--remove-port', f'{port}/tcp'])
        print(f"[+] Port {port} removed - firewall restored")
    except Exception as e:
        print(f"[-] Could not remove port: {e}")

def main():
    parser = argparse.ArgumentParser(description="C2 Beacon Simulator v2.6 - Test Tool for Pre-filter, Sparse, Malleable & UEBA")
    parser.add_argument("--port", type=int, default=1337, help="TCP port")
    parser.add_argument("--target-ip", default="127.0.0.1", help="Target IP (127.0.0.1 for loopback)")
    parser.add_argument("--period", type=float, default=60, help="Base interval in seconds")
    parser.add_argument("--jitter", type=float, default=0.35, help="Jitter factor 0.0-1.0")
    parser.add_argument("--hold", type=float, default=8.0, help="Hold connection open (seconds)")
    parser.add_argument("--duration", type=int, default=300, help="Test duration in seconds")
    parser.add_argument("--process-name", default="python", help="Simulated process name (tests whitelist/UEBA)")
    parser.add_argument("--long-sleep", action="store_true", help="Test sparse/long-sleep beacon (few connections)")
    parser.add_argument("--high-outbound", action="store_true", help="Long hold times (tests outbound consistency)")
    parser.add_argument("--no-listener", action="store_true", help="Do not start local listener")
    args = parser.parse_args()

    print("="*70)
    print("          C2 BEACON SIMULATOR v2.6 (Pre-filter + Sparse + Malleable Test)")
    print("="*70)
    print(f"Target       : {args.target_ip}:{args.port}")
    print(f"Process Name : {args.process_name}")
    print(f"Period       : {args.period}s ± {args.jitter*100:.0f}% jitter")
    print(f"Mode         : {'LONG-SLEEP (Sparse)' if args.long_sleep else 'Normal'}")
    print(f"Outbound     : {'HIGH (Malleable test)' if args.high_outbound else 'Normal'}")
    print("="*70 + "\n")

    zone = None
    if not args.no_listener:
        zone = firewall_open_port(args.port)
        start_listener(args.port)
        time.sleep(2)

    print("Starting beaconing loop... (Ctrl+C to stop)")
    start_time = time.time()
    counter = 0

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed >= args.duration:
                break

            # For long-sleep test: send fewer, longer-spaced beacons
            hold_time = args.hold * 3 if args.long_sleep else args.hold
            success = send_beacon(args.target_ip, args.port, hold_time)
            counter += 1

            if success:
                jitter_amount = random.uniform(-args.jitter * args.period, args.jitter * args.period)
                sleep_time = max(5.0, args.period + jitter_amount) if not args.long_sleep else args.period * 4
                print(f"\r[+] Beacon #{counter:3d} | Process: {args.process_name} | Elapsed: {elapsed:3.0f}s | Next: {sleep_time:4.1f}s", end="", flush=True)
                time.sleep(sleep_time)
            else:
                time.sleep(10)
    except KeyboardInterrupt:
        print("\n\nStopped by user.")
    finally:
        print(f"\n\nTest finished — {counter} beacons sent.")
        print("Check hunter logs for:")
        print("   • Pre-filter skipping (whitelisted processes)")
        print("   • Sparse beacon detection (if --long-sleep used)")
        print("   • Outbound consistency scoring (if --high-outbound used)")
        firewall_close_port(args.port, zone)

if __name__ == "__main__":
    main()