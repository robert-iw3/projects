#!/usr/bin/env python3
"""
C2 Beacon Simulator for testing c2_beacon_hunter v2.5
- Full loopback support (127.0.0.1)
- Configurable jitter (0-100%) to trigger Lomb-Scargle
- Built-in listener + high-entropy payload
- Full firewalld policy detection + exact restore on exit/abort
- Works with Podman --network host + setup.sh test mode

chmod +x test_beacon_simulator.py

# Low-jitter test (classic detection)
./test_beacon_simulator.py --target-ip 127.0.0.1 --period 12 --jitter 0.05 --duration 180

# High-jitter test (triggers Lomb-Scargle)
./test_beacon_simulator.py --target-ip 127.0.0.1 --period 60 --jitter 0.35 --duration 300

# LAN test (no loopback)
./test_beacon_simulator.py --target-ip $(hostname -I | awk '{print $1}') --period 30 --jitter 0.25
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
        print(f"[+] Listener started on 0.0.0.0:{port} (background thread)")
        while True:
            try:
                conn, addr = s.accept()
                print(f"[+] Accepted connection from {addr}")
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
    """Detect default zone, add port to runtime rules, return zone for later removal."""
    try:
        zone = subprocess.check_output(['sudo', 'firewall-cmd', '--get-default-zone']).decode().strip()
        print(f"[+] Firewalld detected - default zone: {zone}")
        print(f"[+] Temporarily adding port {port}/tcp to zone {zone}...")
        subprocess.check_call(['sudo', 'firewall-cmd', '--zone', zone, '--add-port', f'{port}/tcp'])
        print(f"[+] Port {port} opened in runtime rules.")
        return zone
    except subprocess.CalledProcessError as e:
        print(f"[-] Firewalld error: {e}")
        return None
    except FileNotFoundError:
        print("[-] firewall-cmd not found. Skipping firewall adjustment.")
        return None
    except Exception as e:
        print(f"[-] Firewall adjustment skipped: {e}")
        return None

def firewall_close_port(port: int, zone: str):
    """Remove the port from the same zone (exact restore)."""
    if not zone:
        return
    try:
        print(f"[+] Removing port {port}/tcp from zone {zone}...")
        subprocess.check_call(['sudo', 'firewall-cmd', '--zone', zone, '--remove-port', f'{port}/tcp'])
        print(f"[+] Port {port} removed - firewall restored to original state.")
    except Exception as e:
        print(f"[-] Could not remove port: {e}")

def main():
    parser = argparse.ArgumentParser(description="C2 Beacon Simulator v2.5 - Test Tool for Lomb-Scargle + Loopback")
    parser.add_argument("--port", type=int, default=1337, help="TCP port (default: 1337)")
    parser.add_argument("--target-ip", default="127.0.0.1",
                        help="Target IP - use 127.0.0.1 for true loopback test")
    parser.add_argument("--period", type=float, default=10.0,
                        help="Base beacon interval in seconds (default: 10)")
    parser.add_argument("--jitter", type=float, default=0.15,
                        help="Jitter factor 0.0-1.0 (e.g. 0.35 = 35% jitter for Lomb-Scargle test)")
    parser.add_argument("--hold", type=float, default=8.0,
                        help="Seconds to hold each connection open")
    parser.add_argument("--duration", type=int, default=300,
                        help="Total test duration in seconds (default: 5 min)")
    parser.add_argument("--no-listener", action="store_true",
                        help="Do NOT start local listener (use external C2 server)")
    args = parser.parse_args()

    print("="*60)
    print("          C2 BEACON SIMULATOR v2.5 (Lomb-Scargle Ready)")
    print("="*60)
    print(f"Target      : {args.target_ip}:{args.port}")
    print(f"Period      : {args.period}s  ± {args.jitter*100:.0f}% jitter")
    print(f"Hold time   : {args.hold}s")
    print(f"Duration    : {args.duration}s")
    print(f"Mode        : {'LOOPBACK TEST' if args.target_ip == '127.0.0.1' else 'LAN Test'}")
    print(f"Jitter test : {'HIGH (Lomb-Scargle)' if args.jitter >= 0.25 else 'LOW (classic detection)'}")
    print("="*60 + "\n")

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

            success = send_beacon(args.target_ip, args.port, args.hold)
            counter += 1

            if success:
                jitter_amount = random.uniform(-args.jitter * args.period, args.jitter * args.period)
                sleep_time = max(1.0, args.period + jitter_amount)
                print(f"\r[+] Beacon #{counter:3d} sent | Elapsed: {elapsed:3.0f}s | Next in {sleep_time:4.1f}s", end="", flush=True)
                time.sleep(sleep_time)
            else:
                time.sleep(5)
    except KeyboardInterrupt:
        print("\n\nStopped by user.")
    finally:
        print(f"\n\nTest finished - {counter} beacons sent.")
        print("Check your hunter container for detections (especially LombScargle when jitter >= 25%)")
        firewall_close_port(args.port, zone)

if __name__ == "__main__":
    main()