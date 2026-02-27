#!/usr/bin/env python3
"""
run_full_stack.py - v2.7 Unified Launcher
Starts: c2_beacon_hunter + baseline_learner + eBPF collector
"""

import subprocess
import time
import sys
import os
from pathlib import Path

def main():
    print("="*80)
    print("          c2_beacon_hunter v2.7 - Full Stack Launcher")
    print("="*80)
    print("Starting: Hunter + Baseline Learner + eBPF Collector")
    print("")

    processes = []

    try:
        # 1. Start Baseline Learner
        print("[1/3] Starting Baseline Learner...")
        learner = subprocess.Popen([sys.executable, "src/baseline_learner.py"],
                                   cwd="dev", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(learner)

        # 2. Start eBPF Collector
        print("[2/3] Starting eBPF Collector...")
        collector = subprocess.Popen([sys.executable, "src/collector_factory.py"],
                                     cwd="dev", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(collector)

        # 3. Start Main Hunter
        print("[3/3] Starting Main Hunter...")
        hunter = subprocess.Popen([sys.executable, "../../c2_beacon_hunter.py"])
        processes.append(hunter)

        print("\nAll components started successfully!")
        print("Press Ctrl+C to stop everything gracefully.\n")

        # Keep main thread alive
        hunter.wait()

    except KeyboardInterrupt:
        print("\n\nShutting down all components...")
        for p in processes:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=5)
        print("All components stopped.")

    except Exception as e:
        print(f"Launcher error: {e}")
        for p in processes:
            if p.poll() is None:
                p.kill()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: eBPF collector requires root privileges.")
        print("Run with: sudo python3 run_full_stack.py")
        sys.exit(1)
    main()