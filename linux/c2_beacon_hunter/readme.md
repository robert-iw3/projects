# **c2_beacon_hunter**
**Native Linux C2 Beacon & Stealthy Channel Detector**

*Host-based detection using statistical analysis + modern ML (K-Means, Adaptive DBSCAN, Isolation Forest, Lomb-Scargle spectral analysis)*

---

### Overview
`c2_beacon_hunter` is a lightweight, **100% native Linux** C2 beacon detector. It monitors live connections via `ss` + `psutil`, analyzes inter-arrival times, and detects both classic periodic beacons and **stealthy jittered beacons** using spectral analysis.

**updates**: Lomb-Scargle periodogram + circular phase clustering — reliably catches modern jittered C2 that defeats traditional low-CV methods.

---

### Project Structure

```bash
c2_beacon_hunter/
├── README.md
├── setup.sh                          # One-command installer, test mode & container management
├── graceful_shutdown.sh              # Clean shutdown helper
├── requirements.txt
├── config.ini
├── Dockerfile
├── c2_beacon_hunter.py               # Main detector (v2.5)
├── BeaconML.py                       # ML engine with Lomb-Scargle
├── beaconing_algorithms_summary.md
│
├── tests/                            # All testing tools
│   ├── test_beacon_simulator.py      # Official C2 simulator (loopback + jitter)
│   ├── test_MLBeacon.py              # ML validation suite
│   ├── live_c2_advanced.sh
│   ├── live_c2_firewall_aware.sh
│   ├── run_beacon_test.sh
│   └── test_beacon_ml_full.sh
│
├── audit_rules.d/
│   └── c2_beacon.rules
│
├── systemd/
│   └── c2_beacon_hunter.service
│
├── output/                           # Auto-created at runtime
│   ├── detections.log
│   ├── anomalies.csv
│   ├── anomalies.jsonl
│   └── c2_beacon_hunter.log
│
└── venv/                             # Created automatically by setup.sh
```

---

### Quick Start

```bash
chmod +x setup.sh graceful_shutdown.sh

sudo ./setup.sh install      # Install dependencies + systemd service
sudo ./setup.sh container    # Build Podman/Docker image
```

**Run full interactive test (recommended):**
```bash
sudo ./setup.sh test
```

**Manual simulator test:**
```bash
cd tests
./test_beacon_simulator.py --target-ip 127.0.0.1 --period 60 --jitter 0.35 --duration 180
```

**Live monitoring:**
```bash
sudo ./setup.sh watch        # or: tail -f output/detections.log
```

**Production start:**
```bash
sudo ./setup.sh start
```

**Clean stop:**
```bash
sudo ./setup.sh stop
```

---

### v2.5
- Lomb-Scargle + circular phase clustering (detects heavily jittered beacons)
- Dynamic `TEST_MODE=true` (loopback works in test mode, filtered in production)
- Fully interactive comprehensive test mode in `setup.sh`
- All test scripts moved to dedicated `tests/` directory
- Automatic firewalld handling + exact restore in simulator
- Performance: analysis limited to 300 most-recent active flows

---

### Configuration (`config.ini`)

```ini
[general]
snapshot_interval = 60
analyze_interval = 300
score_threshold = 45
max_flow_age_hours = 12
max_flows = 5000
output_dir = output

[ml]
std_threshold = 10.0
use_dbscan = true
use_isolation = true
max_samples = 2000
```

---

### Testing
Use `./setup.sh test` for guided testing (Basic / Advanced / Custom profiles).
Advanced profile specifically stresses the new Lomb-Scargle detection.

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

**Project maintained for red team, blue team, and detection engineering use.**

**Last updated:** February 2026 (v2.5)