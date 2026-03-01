**notes, because I forget**

---

**Completed Modifications (v2.7)**

- Implemented `baseline_learner.py` with per-process/dest/hour/weekend baselines, batch DB inserts, Isolation Forest, and data retention.
- Integrated baseline model loading in `c2_beacon_hunter.py` for UEBA score adjustments.
- Added modular eBPF collectors: `ebpf_collector_base.py` (abstract), `bcc_collector.py` (dev), `libbpf_collector.py` (prod with CO-RE).
- Created `collector_factory.py` for config-driven backend selection (auto/BCC/libbpf).
- Added `c2_probe.bpf.c` and `Makefile` in `dev/probes/` for CO-RE compilation.
- Ensured collectors pass MITRE ATT&CK mappings to learner via `record_flow()`.
- Developed `run_full_stack.py` to launch hunter + learner + collector.
- Added `test_c2_simulation_libbpf.py` and `test_baseline_learner.py` in `dev/tests/`.
- Updated configs, Dockerfiles, and compose for full stack support.
- Preserved all v2.6 features (sparse tracking, direction analysis, DNS, UEBA lite).

```bash
dev/
├── config_dev.ini                   # Development-specific config (different from main config.ini)
│                                    # Controls ebpf backend, intervals, whitelists, etc.
│
├── run_full_stack.py                # Unified launcher: starts hunter + learner + collector together
│
├── requirements.txt                 # Python dependencies needed only for v2.7 dev
│
├── plan.md                          # Development roadmap and notes for v2.7
│
├── src/                             # Core Python source code (organized as a package)
│   ├── __init__.py                  # Makes src/ a proper Python package (allows clean imports)
│   ├── baseline_learner.py          # Core learning engine - builds statistical + ML baselines
│   ├── ebpf_collector_base.py       # Abstract base class - defines common interface for collectors
│   ├── bcc_collector.py             # BCC-based eBPF collector (development-friendly)
│   ├── libbpf_collector.py          # libbpf + CO-RE collector (production-optimized)
│   └── collector_factory.py         # Factory that chooses BCC or libbpf based on config
│
├── probes/                          # Raw eBPF C source files
│   └── c2_probe.bpf.c               # The actual eBPF probe code (CO-RE compatible)
│   └── Makefile                     # Automated CO-RE compilation
│
└── tests/                           # Unit and integration tests for v2.7 components
    ├── __init__.py                  # Makes tests/ a proper Python package
    ├── test_baseline_learner.py     # Tests for baseline_learner.py
    └── test_c2_simulation_libbpf.py # Simulates normal and C2 traffic for eBPF/learner evaluation
```

**Long-term Modularity**

**Goal**:
Build a **modular eBPF collector** that supports two backends:
- **BCC** → Fast development, easy debugging, great for testing (implemented)
- **libbpf + CO-RE** → Production-grade performance, lower overhead, better portability (implemented)

---

### Overall Architecture (Implemented)

```
Collector Factory
       │
       ├── BCCCollector (dev-friendly)
       └── LibbpfCollector (production-optimized, CO-RE)
                │
         Calls same record_flow() → baseline_learner.py
```

---

### Completed Phases (v2.7)

1. **Phase 1** – Built `baseline_learner.py` + integration into hunter for UEBA adjustments.
2. **Phase 2** – Improved baseline model (added packet size, direction, entropy via eBPF data).
3. **Phase 3** – Implemented eBPF data collection (non-intrusive, modular backends).
4. **Phase 4** – Optional full eBPF detection engine (deferred; current focuses on collection for baselines).

---

### Detailed Next Steps (v2.8 Ideas)

**Step 1: Enhance Baselines**
- Incorporate more eBPF metrics (e.g., interval_ns, packet_size_min/max) into models.
- Add real-time anomaly feedback loop from hunter to learner.

**Step 2: Full eBPF Engine**
- Extend probes to detect in-kernel (e.g., direct beacon scoring).
- Integrate with `c2_defend` for auto-response on eBPF events.

**Step 3: Advanced Testing**
- Add integration tests for full stack (e.g., simulate C2, verify detections/baselines).
- Performance benchmarks (CPU/mem) for BCC vs. libbpf.

**Step 4: Deployment Improvements**
- Systemd service for full stack.
- Kubernetes manifests for containerized prod.

**Step 5: New Features**
- DGA detection in DNS sniffer.
- Export to SIEM (e.g., JSON over HTTP).
- GUI dashboard for anomalies.

**Compilation Instructions for the C Probe** (Verified)

- Run these commands in the dev/probes/ folder:

```bash
cd dev/probes

sudo apt update
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)
make

# Verify
ls -l c2_probe.bpf.o
```

**Pre-reqs** (Updated for v2.7)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r dev/requirements.txt  # For eBPF/ML extras

sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r) libbpf-dev   # Ubuntu/Debian
# or
sudo dnf install bcc-tools python3-bcc kernel-devel libbpf-devel                # Fedora/RHEL
```