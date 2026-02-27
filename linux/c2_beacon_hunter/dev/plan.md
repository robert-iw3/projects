**notes, because I forget**

---

```bash
dev/
├── config_dev.ini                  # Development-specific config (different from main config.ini)
│                                   # Controls ebpf backend, intervals, whitelists, etc.
│
├── run_full_stack.py               # Unified launcher: starts hunter + learner + collector together
│
├── requirements.txt                # Python dependencies needed only for v2.7 dev
│
├── plan.md                         # Development roadmap and notes for v2.7
│
├── src/                            # Core Python source code (organized as a package)
│   ├── __init__.py                 # Makes src/ a proper Python package (allows clean imports)
│   ├── baseline_learner.py         # Core learning engine - builds statistical + ML baselines
│   ├── ebpf_collector_base.py      # Abstract base class - defines common interface for collectors
│   ├── bcc_collector.py            # BCC-based eBPF collector (development-friendly)
│   ├── libbpf_collector.py         # libbpf + CO-RE collector (production-optimized)
│   └── collector_factory.py        # Factory that chooses BCC or libbpf based on config
│
├── probes/                         # Raw eBPF C source files
│   └── c2_probe.bpf.c              # The actual eBPF probe code (CO-RE compatible)
│
└── tests/                          # Unit and integration tests for v2.7 components
    ├── __init__.py                 # Makes tests/ a proper Python package
    ├── test_baseline_learner.py    # Tests for baseline_learner.py
    ├── test_collector_factory.py   # Tests for the factory pattern
    ├── test_ebpf_collector.py      # Tests for eBPF collector interface
    └── test_libbpf_collector.py    # Tests for the libbpf backend specifically
```

### High-Level Game Plan for Phase 3B & Long-term Modularity

**Goal**:
Build a **modular eBPF collector** that supports two backends:
- **BCC** → Fast development, easy debugging, great for testing
- **libbpf + CO-RE** → Production-grade performance, lower overhead, better portability

---

### Overall Architecture

```
Collector Factory
       │
       ├── BCCCollector (current, dev-friendly)
       └── LibbpfCollector (new, production-optimized, CO-RE)
                │
         Calls same record_flow() → baseline_learner.py
```

---

### Detailed Next Steps (Phase 3B)

**Step 1: Create Modular Foundation (Immediate)**

Create these files:

- `ebpf_collector_base.py` → Abstract base class with common interface
- `collector_factory.py` → Decides which backend to use (config-driven)
- Keep existing `ebpf_collector.py` as `bcc_collector.py`

**Step 2: Port Core Probes to libbpf + CO-RE**

Write clean C code for the essential probes:
- `execve` + parent PID
- `connect`
- `sendmsg` / `recvmsg` (with packet size)
- `memfd_create`
- `socket`

Compile once with Clang + libbpf, then load from Python.

**Step 3: Python libbpf Loader**

Use `libbpf-python` or `ctypes` + `libbpf` to load the pre-compiled `.o` object.

**Step 4: Configuration & Fallback**

Add to `config.ini`:
```ini
[ebpf]
backend = auto        # auto, bcc, or libbpf
enabled = false
```

**Step 5: Testing Strategy**

- Unit test both backends
- Performance comparison (CPU / memory)
- Graceful fallback if libbpf fails

**Compilation Instructions for the C Probe**

- Run these commands in the dev/probes/ folder:

```bash
cd dev/probes

# Compile to CO-RE object (no kernel headers needed at runtime)
clang -target bpf -O2 -g -Wall -Werror -c c2_probe.bpf.c -o c2_probe.bpf.o

# Verify
ls -l c2_probe.bpf.o
```

**Pre-reqs**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)   # Ubuntu/Debian
# or
sudo dnf install bcc-tools python3-bcc kernel-devel                  # Fedora/RHEL
```