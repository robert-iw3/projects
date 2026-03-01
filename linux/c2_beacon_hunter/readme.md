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
use_ueba = true
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
```

---

### Roadmap
See `dev/plan.md` for completed phases and future ideas (e.g., packet entropy in models, full eBPF engine).

**Last updated:** February 2026 (v2.7)