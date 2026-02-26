#!/usr/bin/env python3
"""
run_full_stack.py - v2.7 Launcher
Starts: c2_beacon_hunter + baseline_learner + eBPF collector
"""

import subprocess
import time
import sys
import os
from pathlib import Path

def main():
    print("="*70)
    print("          c2_beacon_hunter v2.7 Full Stack Launcher")
    print("="*70)
    print("Starting: Hunter + Baseline Learner + eBPF Collector")
    print("")

    try:
        # Start baseline learner
        learner = subprocess.Popen([sys.executable, "baseline_learner.py"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Start eBPF collector
        collector = subprocess.Popen([sys.executable, "ebpf_collector.py"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Start main hunter
        print("Starting main hunter...")
        hunter = subprocess.Popen([sys.executable, "c2_beacon_hunter.py"])

        print("\nAll components started successfully!")
        print("Press Ctrl+C to stop all components.")

        # Keep main thread alive
        hunter.wait()

    except KeyboardInterrupt:
        print("\n\nShutting down all components...")
        for p in [hunter, learner, collector]:
            if p.poll() is None:
                p.terminate()
        print("All components stopped.")

    except Exception as e:
        print(f"Launcher error: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This launcher must be run as root (for eBPF).")
        sys.exit(1)
    main()