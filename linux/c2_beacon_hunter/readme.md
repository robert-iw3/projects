# **c2_beacon_hunter**
**Native Linux C2 Beacon & Channel Detection Suite**
*Advanced, lightweight, host-based beaconing detection using statistical analysis + state-of-the-art ML (K-Means, DBSCAN, Isolation Forest)*

---

### Overview
`c2_beacon_hunter` is a **100% native Linux** (no Zeek/Suricata required) command-and-control (C2) beaconing detector. It monitors live processes and network connections via `psutil`, tracks connection intervals, and applies:

- Statistical analysis (CV, entropy, jitter)
- Spectral analysis (Lomb-Scargle via astropy)
- **Advanced ML** via integrated `BeaconML.py` (parallel silhouette scoring, adaptive DBSCAN, Isolation Forest, subsampling for massive flows)
- MITRE ATT&CK mapping
- Optional real-time DNS query monitoring (scapy)

---

### Features
- Live monitoring with minimal overhead (<5% CPU typical)
- Real-time colored console output + status line
- Human-readable `detections.log` (perfect for `tail -f`)
- SIEM-ready `anomalies.csv` + `anomalies.jsonl` (NDJSON)
- Configurable via `config.ini` or CLI
- Systemd service with auto-restart
- Graceful shutdown & final export

---

### Project Files

| File                                 | Purpose                                      | Verified |
|--------------------------------------|----------------------------------------------|----------|
| `setup.sh`                           | One-shot installer & service manager         | OK       |
| `requirements.txt`                   | Python dependencies (incl. joblib, scikit-learn) | OK       |
| `config.ini`                         | All tuning options (intervals, thresholds, output dir) | OK       |
| `c2_beacon_hunter.py`                | Main detector (fully revised & optimized)    | OK       |
| `BeaconML.py`                        | Advanced ML engine (parallel, subsampled)    | OK       |
| `audit_rules.d/c2_beacon.rules`      | Optional auditd rules for process/network    | OK       |
| `systemd/c2_beacon_hunter.service`   | Systemd service (edit paths once)            | OK       |
| `beaconing_algorithms_summary.md`    | Research references & algorithm explanations | OK       |
| `test_MLBeacon.py`                   | Full ML validation suite (run anytime)       | OK       |

```bash
c2_beacon_hunter/
├── README.md                          # Project documentation
├── setup.sh                           # One-shot installer + container + shutdown
├── graceful_shutdown.sh               # Intelligent graceful shutdown script
├── requirements.txt                   # Python dependencies
├── config.ini                         # All configuration (general, ml, container)
├── Dockerfile                         # Docker/Podman build file
├── c2_beacon_hunter.py                # Main detector (full v2.3 with container awareness)
├── BeaconML.py                        # Advanced ML engine (K-Means + adaptive DBSCAN + Isolation Forest)
├── test_MLBeacon.py                   # ML validation test suite
├── beaconing_algorithms_summary.md    # Research & algorithm reference
│
├── audit_rules.d/
│   └── c2_beacon.rules                # Enhanced auditd rules
│
├── systemd/
│   └── c2_beacon_hunter.service       # Hardened systemd unit
│
├── output/                            # Runtime-generated (created automatically)
│   ├── detections.log                 # Human-readable live alerts
│   ├── anomalies.csv                  # Full analysis for Excel/SIEM
│   ├── anomalies.jsonl                # NDJSON for SIEM ingestion
│   └── c2_beacon_hunter.log           # Rotating debug log
│
└── venv/                              # Python virtual environment (created by setup.sh)
```

---

### Quick Start
```bash
chmod +x setup.sh graceful_shutdown.sh

sudo ./setup.sh install     # copies new rules + service + reloads everything
sudo ./setup.sh run         # native mode
# or
sudo ./setup.sh container   # Docker/Podman
# run smoke test
sudo ./setup.sh test        # runs tests/live_c2_advanced.sh
# To stop cleanly:
sudo ./setup.sh shutdown
```

In another terminal:
```bash
sudo ./setup.sh watch      # live human-readable detections
# or
tail -f output/detections.log
```

Stop: `sudo ./setup.sh stop`

---

### Configuration (`config.ini`)
```ini
[general]
snapshot_interval = 60
analyze_interval = 300
score_threshold = 45
max_flow_age_hours = 12
output_dir = output
max_flows = 5000

[ml]
std_threshold = 10.0
use_dbscan = true
use_isolation = true
max_samples = 2000

[container]
enabled = false
runtime = auto          # docker, podman, or auto (prompted)
```

---

### Outputs (in `output/` or your custom dir)
- `detections.log`      → Human-readable alerts (`tail -f` this)
- `anomalies.csv`       → Full details for Excel/analysis
- `anomalies.jsonl`     → NDJSON for SIEM ingestion (Splunk, Elastic, QRadar, etc.)
- `c2_beacon_hunter.log` → Detailed debug log (rotating)

---

### Testing the ML Engine
```bash
source venv/bin/activate
python test_MLBeacon.py
```
→ Should output "All Tests Passed!" (includes regular, jittered, large dataset, etc.)

---

### MITRE ATT&CK Mapping (included)
- `TA0011` / `T1071`  → Periodic beaconing
- `TA0011` / `T1568.002` → High-entropy/DGA
- `TA0011` / `T1090` → Unusual ports/proxies
- `TA0002` / `T1059` → Suspicious process/cmdline

---

### Credits & Research Foundation
- ML engine derived from Robert Weber's advanced beaconing algorithms (Jan 2026)
- Statistical/spectral methods from SEI/CMU, RITA, Elastic, and Lomb-Scargle literature
- Entropy detection inspired by DGA research
- Project maintained for red/blue team use