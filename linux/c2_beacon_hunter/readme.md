# **c2_beacon_hunter**
**Native Linux C2 Beacon & Stealthy Channel Detector (v2.6)**

*Advanced host-based detection with sparse beacon tracking, malleable C2 resistance, and enhanced DNS detection*

---

### Overview
`c2_beacon_hunter` is a lightweight, **100% native Linux** tool that detects command-and-control (C2) beacons in real time using statistical analysis, machine learning, and spectral methods.

**v2.6** adds long-sleep/sparse beacon detection, packet direction analysis, enhanced DNS detection, and per-process behavioral baselining.

---

### Proactive Protection
A new companion tool is included:

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
├── c2_beacon_hunter.py               # v2.6 detection engine
├── BeaconML.py
├── Dockerfile
├── beaconing_algorithms_summary.md
│
├── tests/
│   └── test_beacon_simulator.py
│
├── c2_defend/                        # ← New Proactive Protection
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
└── venv/
```

---

## Quick Start

```bash
chmod +x setup.sh
sudo ./setup.sh install      # Install dependencies + systemd
sudo ./setup.sh container    # Build container image (recommended)
```

**Run full test (recommended):**
```bash
sudo ./setup.sh test
```

**Start detection:**
```bash
sudo ./setup.sh start
sudo ./setup.sh watch        # Live detections
```

**Activate proactive protection:**
```bash
cd c2_defend
sudo ./run.sh
```

---

### How to Use c2_defend

```bash
cd c2_defend
sudo ./run.sh
```

Choose:
- **1** → Analyzer (view detections)
- **2** → Defender (kill + block)
- **3** → Undo previous blocks

---

### v2.5
- Lomb-Scargle + circular phase clustering (detects heavily jittered beacons)
- Dynamic `TEST_MODE=true` (loopback works in test mode, filtered in production)
- Fully interactive comprehensive test mode in `setup.sh`
- All test scripts moved to dedicated `tests/` directory
- Automatic firewalld handling + exact restore in simulator
- Performance: analysis limited to 300 most-recent active flows

### v2.6
- Strong pre-filter layer (configurable whitelist for processes & destinations to reduce noise)
- Sparse / long-sleep beacon tracking (up to 48 hours)
- Packet direction & outbound consistency scoring (strong against malleable C2)
- Enhanced DNS beacon detection
- Per-process UEBA lite baseline (further reduces false positives)
- New `c2_defend/` proactive protection module (kill + firewall blocking + undo)

---

## Configuration (`config.ini`)

**Important Note:**
**Do not add comments on the same line as a value.**
`configparser` will read the comment as part of the value and cause errors (e.g. `ValueError: invalid literal for int()`).

**Correct format:**
```ini
long_sleep_threshold = 1800
```

**Incorrect format:**
```ini
long_sleep_threshold = 1800    # this will break
```

---

#### Configuration Reference

```ini
[general]
snapshot_interval = 60          # Seconds between connection snapshots (recommended: 30-60)
analyze_interval = 300          # Seconds between analysis runs (recommended: 180-600)
score_threshold = 60            # Minimum score to trigger an alert (higher = fewer false positives)
max_flow_age_hours = 48         # How long to keep flow history (increased in v2.6 for sparse beacons)
max_flows = 5000                # Maximum number of flows to track in memory
output_dir = output             # Directory for logs and exported data

# Sparse / long-sleep beacon settings (v2.6)
long_sleep_threshold = 1800     # Seconds. If average interval > this → treat as sparse beacon (default 30 min)
min_samples_sparse = 3          # Minimum connections needed for sparse beacons (lowered for long sleep)

[ml]
std_threshold = 10.0            # Maximum standard deviation for "tight" clusters
use_dbscan = true               # Enable Adaptive DBSCAN clustering
use_isolation = true            # Enable Isolation Forest anomaly detection
max_samples = 2000              # Subsample large flows for performance
use_ueba = true                 # Enable per-process baseline (UEBA lite) - reduces false positives
use_enhanced_dns = true         # Enable dedicated DNS beacon detection

# ====================== Pre-Filter Whitelist ======================
# Multi-line values without continuation configparser does not automatically handle multi-line values like this.
# This is for more readability, reference the current config.ini
[whitelist]
benign_processes = NetworkManager, firefox, firefox-bin, chrome, chromium,
                   gnome-shell, systemd, dbus-daemon, pipewire, pulseaudio,
                   nautilus, tracker, teams, slack, discord, zoom, code,
                   github-desktop, git, ssh, sshd, conmon, crun, podman
                                   # List of legitimate processes that are almost always benign.
                                   # Traffic from these is skipped early to reduce noise.
                                   # WARNING: Do not add powershell, cmd, python, bash, etc.
                                   # (threat actors can abuse these for stealthy C2)

benign_destinations = 192.168., 10., 172.16., 172.17., 172.18., 172.19.,
                      172.20., 172.21., 172.22., 172.23., 172.24., 172.25.,
                      8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9
                                   # IP prefixes and addresses considered "known good".
                                   # Traffic to these destinations is skipped early.
                                   # Private ranges + major public DNS servers are included by default.

[container]
enabled = false                 # Set to true to prefer container mode
runtime = auto                  # docker, podman, or auto
```

---

## Testing

Use the interactive test mode for the easiest and most complete validation:

```bash
sudo ./setup.sh test
```

This automatically starts the hunter in TEST MODE and launches the simulator with guided profiles.

#### Manual Simulator Tests (Recommended for v2.6)

```bash
cd tests

# 1. Pre-filter test (should be completely skipped / no alert)
./test_beacon_simulator.py --process-name firefox --period 60 --jitter 0.05 --duration 120

# 2. Sparse / Long-sleep beacon test (tests new long-sleep tracking)
./test_beacon_simulator.py --long-sleep --period 1800 --jitter 0.25 --duration 7200

# 3. Malleable C2 test (tests outbound consistency scoring)
./test_beacon_simulator.py --high-outbound --period 60 --jitter 0.35 --duration 300

# 4. UEBA + suspicious process test (tests baseline deviation)
./test_beacon_simulator.py --process-name python --period 45 --jitter 0.40 --duration 240

# 5. Classic high-jitter test (Lomb-Scargle)
./test_beacon_simulator.py --period 60 --jitter 0.35 --duration 300
```

#### What Each Test Validates

| Test | Feature Being Tested                  | Expected Result                     |
|------|---------------------------------------|-------------------------------------|
| 1    | Pre-filter whitelist                  | No detection (skipped)              |
| 2    | Sparse / long-sleep tracking          | Detection with sparse beacon logic  |
| 3    | Malleable C2 resistance               | `consistent_outbound_malleable`     |
| 4    | UEBA baseline                         | `ueba_deviation` if abnormal        |
| 5    | Lomb-Scargle jitter detection         | Strong ML + LombScargle alert       |

---

### Outputs
- `detections.log` → Human readable alerts
- `anomalies.csv` / `anomalies.jsonl` → SIEM-ready

---

### MITRE ATT&CK
- `TA0011` / `T1071` → Application Layer Protocol (periodic beaconing)
- `TA0011` / `T1568.002` → High entropy / DGA-like behavior
- `TA0011` / `T1090` → Unusual ports
- `TA0005` / `T1036` → Process masquerading

---

## Real World Application (v2.6)

This tool is specifically designed to detect modern C2 frameworks that use **jitter, long sleep intervals, malleable profiles, and DNS-only** communication.

| C2 Framework       | Typical Behavior                              | How v2.6 Detects It                                              | Expected Effectiveness |
|--------------------|-----------------------------------------------|------------------------------------------------------------------|------------------------|
| **Cobalt Strike**  | 30–300s base + 0–50% jitter, malleable C2     | Lomb-Scargle + outbound consistency + UEBA baseline              | **Very High**          |
| **Sliver**         | Default jitter + optional long sleep          | Sparse/long-sleep tracking + Lomb-Scargle + direction scoring    | **Very High**          |
| **Havoc (Demon)**  | Configurable sleep + jitter + obfuscation     | Long-sleep tracking + enhanced DNS + process masquerade scoring  | **High**               |
| **Adaptix**        | sleep_delay + jitter_delay                    | Full timing suite + malleable outbound detection                 | **High**               |

#### v2.6 Detections
- **Sparse/Long-sleep tracking** — Detects beacons with very long intervals (30 minutes to many hours)
- **Packet direction & outbound consistency** — Excellent against malleable C2 profiles on common ports (443/80)
- **Enhanced DNS beacon detection** — Strong coverage for pure DNS C2 channels
- **Per-process UEBA lite baseline** — Learns normal behavior per process to reduce false positives
- **Lomb-Scargle spectral analysis** — Still the strongest feature against jittered beacons (30–50%+ jitter)

**Realistic testing tip**:
Use `--jitter 0.30` to `0.45` in the simulator to closely mimic real Cobalt Strike / Sliver / Havoc behavior.

---

**Project maintained for red team, blue team, and detection engineering use.**

**Last updated:** February 2026 (v2.6)

---

# v2.7 Roadmap Strategy

| Priority | Feature                  | Difficulty | Strategy / Approach                                                                 | Expected Impact |
|----------|--------------------------|------------|-------------------------------------------------------------------------------------|-----------------|
| 1        | `baseline_learner.py`    | Medium     | Separate long-running learner + lightweight model export                           | **Major** reduction in false positives |
| 2        | Optional eBPF mode       | Hard       | Hybrid: Start with eBPF data collection only, then optional full eBPF detection    | Very high accuracy (future) |

---

### Detailed Strategy for `baseline_learner.py` (Priority 1)

**Goal**: Build a **per-process, per-destination behavioral baseline** that learns what is normal on this specific system over days/weeks.

**High-level Design:**

1. **Data Collection** (Background mode)
   - Runs in parallel with the main hunter
   - Records for every flow: process name, destination IP/CIDR, avg interval, CV, outbound ratio, packet size stats, entropy, etc.
   - Stores in a lightweight database (SQLite) or JSONL files

2. **Learning Engine**
   - Uses statistical models (mean, std, percentiles) + simple ML (Isolation Forest or One-Class SVM)
   - Builds a **profile** for each `(process_name, destination_prefix)` pair
   - Updates continuously or on a schedule (e.g. every 6–12 hours)

3. **Integration with Main Detector**
   - Main `c2_beacon_hunter.py` loads the latest baseline model on startup or every analysis cycle
   - In `analyze_flow()`: Compare current flow against the learned baseline
   - If behavior deviates significantly → boost score or trigger alert
   - If behavior matches baseline → suppress or heavily discount the alert

**Key Benefits**:
- Dramatically reduces false positives from firefox, NetworkManager, github-desktop, etc.
- Adapts to your unique environment (no more generic whitelists)
- Still catches new/abnormal C2 behavior quickly

---

### High-Level Plan for Optional eBPF Mode (Priority 2)

- Phase 1: Add eBPF data collection (using `bcc` or `bpftrace`) to gather richer metrics (syscalls, packet sizes, exact connection events)
- Phase 2: Optional eBPF-based detection engine (very accurate but complex)

---

### Phases for v2.7

1. **Phase 1 (Next)** – Build `baseline_learner.py` + integration
2. **Phase 2** – Improve baseline model (add packet size, direction, entropy)
3. **Phase 3** – eBPF data collection (non-intrusive first)
4. **Phase 4** – Optional full eBPF detection engine