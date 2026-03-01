# **c2_beacon_hunter**
**Native Linux C2 Beacon & Stealthy Channel Detector (v2.7)**

*Advanced host-based detection with adaptive learning, eBPF integration, sparse beacon tracking, malleable C2 resistance, and enhanced DNS detection*

---

### Overview
`c2_beacon_hunter` is a lightweight, **100% native Linux** tool that detects command-and-control (C2) beacons in real time using statistical analysis, machine learning, spectral methods, and now adaptive baselines with eBPF for low-level monitoring.

**v2.7** introduces adaptive learning via `baseline_learner.py`, modular eBPF collectors (BCC and libbpf backends), packet size/direction/entropy enhancements in models, and full stack integration—while preserving all v2.6 features like long-sleep/sparse beacon detection, packet direction analysis, enhanced DNS detection, and per-process behavioral baselining.

---

### Proactive Protection
A companion tool is included:

**`c2_defend/`** — Turns detections into active containment:
- Kill suspicious processes
- Block IPs and ports via firewalld / ufw / iptables
- Quarantine option
- Persistent blocklist with easy undo (`undo.py`)
- Full action logging

---

## Project Structure

```bash
c2_beacon_hunter/
├── README.md
├── setup.sh
├── config.ini
├── requirements.txt
├── c2_beacon_hunter.py               # v2.7 detection engine
├── BeaconML.py
├── Dockerfile
├── ebpf.Dockerfile                   # For eBPF dev container
├── docker-compose.yaml               # For full stack dev container
├── beaconing_algorithms_summary.md
│
├── tests/
│   └── test_beacon_simulator.py
│
├── c2_defend/                        # Proactive Protection
│   ├── README.md
│   ├── run.sh
│   ├── analyzer.py
│   ├── defender.py
│   └── undo.py
│
├── output/                           # Auto-created
│   ├── detections.log
│   ├── anomalies.csv
│   ├── anomalies.jsonl
│   └── c2_beacon_hunter.log
│
├── audit_rules.d/
├── systemd/
├── venv/
│
└── dev/                              # v2.7 development components
    ├── config_dev.ini                # Dev-specific config (eBPF backend, etc.)
    ├── run_full_stack.py             # Unified launcher for hunter + learner + collector
    ├── requirements.txt              # Dev dependencies (eBPF, ML extras)
    ├── plan.md                       # Roadmap and notes
    │
    ├── src/                          # Core v2.7 Python package
    │   ├── __init__.py
    │   ├── baseline_learner.py       # Builds statistical + ML baselines
    │   ├── ebpf_collector_base.py    # Abstract base for collectors
    │   ├── bcc_collector.py          # BCC eBPF collector (dev mode)
    │   ├── libbpf_collector.py       # libbpf + CO-RE collector (prod mode)
    │   └── collector_factory.py      # Selects backend based on config
    │
    ├── probes/                       # eBPF C probes
    │   ├── c2_probe.bpf.c            # CO-RE compatible probe code
    │   └── Makefile                  # For compiling probes
    │
    └── tests/                        # v2.7 tests
        ├── __init__.py
        ├── test_baseline_learner.py  # Baseline learner tests
        └── test_c2_simulation_libbpf.py  # Simulates traffic for eBPF testing
```

---

## Quick Start

```bash
chmod +x setup.sh
sudo ./setup.sh install      # Install dependencies + systemd
sudo ./setup.sh container    # Build container image (recommended for eBPF dev)
```

**Run full test (recommended):**
```bash
sudo ./setup.sh test
```

**Start detection (standalone hunter):**
```bash
sudo ./setup.sh start
sudo ./setup.sh watch        # Live detections
```

**Start full v2.7 stack (hunter + learner + eBPF collector):**
```bash
cd dev
sudo python3 run_full_stack.py
```

**Activate proactive protection:**
```bash
cd c2_defend
sudo ./run.sh
```

---

### How It Works
- **Core Detection (from v2.6)**: Polls connections via `ss` (fallback psutil), analyzes intervals/CV/entropy/outbound ratios, runs ML (K-Means/DBSCAN/Isolation Forest/Lomb-Scargle), checks process trees/masquerading.
- **v2.7 Enhancements**:
  - **Adaptive Baselines**: `baseline_learner.py` builds per-process/dest/hour/weekend models (stats + Isolation Forest) from eBPF data.
  - **eBPF Collectors**: Modular backends capture syscalls/packets (execve, connect, sendmsg, etc.), feed learner with MITRE-mapped metrics.
  - **Score Adjustments**: UEBA deviations from baselines boost anomaly scores.
  - **Full Stack**: `run_full_stack.py` launches everything together for holistic operation.

## The eBPF Pipeline

1. **Kernel Hooks:** `c2_probe.bpf.o` attaches to the Linux kernel, intercepting deep network stack events to extract precise IP addresses, process IDs, and packet sizes.
2. **The Streamer:** `c2_loader` reads the eBPF ring buffer and pipes strict JSON to the Python backend.
3. **The Broker:** The collector ingests the data and writes it to a high-speed SQLite database (`baseline.db`) to ensure zero dropped events.
4. **The Hunter:** `c2_beacon_hunter.py` reads the database concurrently, reconstructing process trees and piping the microsecond intervals into the Machine Learning engine (K-Means, DBSCAN, Isolation Forests) to catch the beacon.

Exports anomalies to CSV/JSONL/logs for SIEM integration.

---

### Features
- Real-time beacon detection (periodic, jittered, sparse/long-sleep)
- Malleable C2 resistance (outbound consistency, entropy scoring)
- Enhanced DNS beaconing (Scapy sniffer + ML intervals)
- Per-process UEBA (lite in-memory + advanced baselines)
- Process tree analysis + masquerading detection
- Configurable whitelists (processes, destinations)
- Container support with host visibility
- MITRE ATT&CK mappings in anomalies
- Low overhead (threaded, limited flows)

See `beaconing_algorithms_summary.md` for detection details.

---

### Dependencies
- Python 3.12+ (venv recommended)
- Core: psutil, numpy, pandas, scikit-learn, astropy, scipy, joblib, scapy
- eBPF (v2.7): bpfcc-tools, python3-bpfcc (BCC), libbpf-dev, libbpf-python (libbpf)
- Install via `requirements.txt` and system packages (see `ebpf.Dockerfile`)

---

### Configuration (`config.ini`)
```ini
[general]
snapshot_interval = 60
analyze_interval = 300
score_threshold = 60
max_flow_age_hours = 48
max_flows = 5000
output_dir = output
long_sleep_threshold = 1800
min_samples_sparse = 3

[ml]
std_threshold = 10.0
use_dbscan = true
use_isolation = true
max_samples = 2000
use_ueba = true\s+$
use_enhanced_dns = true

[ebpf]
backend = auto  # auto, bcc, libbpf
enabled = true

[whitelist]
benign_processes = NetworkManager,pipewire,pulseaudio,nautilus,tracker
benign_destinations = 192.168.,10.,172.16.,172.17.,172.18.,172.19.,172.20.,172.21.,172.22.,172.23.,172.24.,172.25.,8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,9.9.9.9

[container]
enabled = true
runtime = auto
```

---

### Testing
- `tests/test_beacon_simulator.py`: Simulates beacons for core detection.
- `dev/tests/test_c2_simulation_libbpf.py`: Generates traffic for eBPF/learner validation.
- `dev/tests/test_baseline_learner.py`: Verifies model building.

Run `sudo ./setup.sh test` for end-to-end.

---

### eBPF Dev Container
Build/run full stack in container for isolated testing:

```bash
sudo docker-compose up  # or podman-compose

# Example logs
[c2-beacon-hunter-dev] | 2026-03-01 01:24:50,951 - INFO - ================================================================================
[c2-beacon-hunter-dev] | 2026-03-01 01:24:50,951 - INFO -  c2_beacon_hunter v2.7 - Full Stack Launcher
[c2-beacon-hunter-dev] | 2026-03-01 01:24:50,951 - INFO - ================================================================================
[c2-beacon-hunter-dev] | 2026-03-01 01:24:50,951 - INFO - Starting: Hunter + Baseline Learner + eBPF Collector
[c2-beacon-hunter-dev] | ...
[MONITORING v2.7] Active flows:     0 | Detections:    0 | Last: 01:24:52

# see if event capture/collection is occuring
podman exec -it c2-beacon-hunter /app/venv/bin/python -c "import sqlite3; [print(row) for row in sqlite3.connect('/app/baseline.db').execute('SELECT process_name, dst_ip, interval, packet_size_mean, mitre_tactic FROM flows ORDER BY id DESC LIMIT 15')]"
```

---

### Roadmap
See `dev/plan.md` for completed phases and future ideas (e.g., packet entropy in models, full eBPF engine).

**Last updated:** March 2026 (v2.7)

---

### Monitoring and Tuning Steps:

- Events will start to populate that mimic c2 behavior, over time the ```baseline_learner.py```will eventually learn that your specific machine constantly runs certain processes, and the UEBA logic will begin to naturally suppress the score.

- Add to the benign_processes in the config.ini

```ini
[whitelist]
benign_processes = firefox-bin, code, chrome_childiot, socket thread, gvfsd-wsdd
```

***Example***

```json
{"timestamp": "2026-03-01T19:26:33.358749", "dst_ip": "0.0.0.0", "dst_port": 0, "process": "python3", "cmd_snippet": "", "pid": 5902, "process_tree": "systemd(1) \u2192 systemd(3312) \u2192 gvfsd(3559) \u2192 gvfsd-wsdd(5897) \u2192 python3(5902)", "masquerade_detected": true, "avg_interval_sec": 0.16, "cv": 0.9961, "entropy": 0.985, "outbound_ratio": 1.0, "ml_result": "ML K-Means Beaconing (Clusters: 5, Min StdDev: 0.01, Score: 0.85); ML Adaptive DBSCAN Beaconing (Core StdDev: 0.16, eps=0.500)", "score": 85, "reasons": ["Advanced_ML: ML K-Means Beaconing (Clusters: 5, Min StdDev: 0.01, Score: 0.85); ML Adaptive DBSCAN Beaconing (Core StdDev: 0.16, eps=0.500)", "process_masquerade"], "mitre_tactic": "TA0005", "mitre_technique": "T1036", "mitre_name": "Masquerading", "description": "C2 Beacon detected - ML K-Means Beaconing (Clusters: 5, Min StdDev: 0.01, Score: 0.85); ML Adaptive DBSCAN Beaconing (Core StdDev: 0.16, eps=0.500)"}
{"timestamp": "2026-03-01T19:31:38.816719", "dst_ip": "0.0.0.0", "dst_port": 0, "process": "python3", "cmd_snippet": "", "pid": 5902, "process_tree": "systemd(1) \u2192 systemd(3312) \u2192 gvfsd(3559) \u2192 gvfsd-wsdd(5897) \u2192 python3(5902)", "masquerade_detected": true, "avg_interval_sec": 0.16, "cv": 0.9961, "entropy": 0.985, "outbound_ratio": 1.0, "ml_result": "ML K-Means Beaconing (Clusters: 5, Min StdDev: 0.01, Score: 0.86); ML Adaptive DBSCAN Beaconing (Core StdDev: 0.16, eps=0.500)", "score": 85, "reasons": ["Advanced_ML: ML K-Means Beaconing (Clusters: 5, Min StdDev: 0.01, Score: 0.86); ML Adaptive DBSCAN Beaconing (Core StdDev: 0.16, eps=0.500)", "process_masquerade"], "mitre_tactic": "TA0005", "mitre_technique": "T1036", "mitre_name": "Masquerading", "description": "C2 Beacon detected - ML K-Means Beaconing (Clusters: 5, Min StdDev: 0.01, Score: 0.86); ML Adaptive DBSCAN Beaconing (Core StdDev: 0.16, eps=0.500)"}
```

- The hunter caught ```gvfsd-wsdd```, which is the GNOME Virtual File System Web Services Dynamic Discovery daemon. It is a standard Linux background service used to discover Windows/SMB shares on your local network.

***Here is exactly why C2 Hunter flagged it with a score of 85***:

1. It acts exactly like a UDP Beacon

```gvfsd-wsdd``` is designed to continuously broadcast UDP packets to the local network on a robotic timer to see if any new Windows file shares have come online. Because the timing is perfectly scripted, ML clustering algorithms correctly identified it as a mathematical beacon (Min StdDev: 0.01).

2. It triggered the "Process Masquerade" penalty (+25 points)

```gvfsd-wsdd``` is actually a Python script. When it starts up, it uses a trick to rewrite its own process name from python3 to gvfsd-wsdd so it looks prettier in htop or ps.

- However, ```c2_beacon_hunter.py``` masquerading logic looks at the underlying executable path (```/usr/bin/python3```) and compares it to the running process name (```gvfsd-wsdd```). Because they didn't match, the engine immediately (and correctly) flagged it as Masquerading / Process Hollowing.

- Initial tuning will be required.  Consult/Research events like this to understand what is happening and why the benign_processes is important.

- If the intent is to monitor everything, then do not add to the benign_processes filter (lots of alerts/event will occur and require false-positive review).