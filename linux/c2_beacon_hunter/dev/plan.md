**notes, because I forget**

---

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

We will write clean C code for the essential probes:
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