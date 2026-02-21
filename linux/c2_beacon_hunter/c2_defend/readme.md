# c2_defend - Proactive Protection Layer

**Turns c2_beacon_hunter detections into active containment.**

### Security Warning
This tool can **kill processes** and **modify the host firewall**.
It must be run with **root privileges** directly on the host.

---

### Usage

```bash
cd c2_defend
sudo chmod +x run.sh analyzer.py defender.py undo.py
sudo ./run.sh
```

---

### Features

- Reads detections from `../output/anomalies.csv`
- Supports **firewalld** (preferred), **ufw**, and **iptables**
- Respects the current firewalld zone
- Persistent blocklist (`blocklist.txt`)
- Full action logging (`defender.log`)
- Easy undo with `undo.py`

---

### Recommended Workflow

1. Run the hunter: `sudo ../setup.sh start`
2. When suspicious activity is detected → `cd c2_defend && sudo ./run.sh`
3. Choose mode **2** (Defender) to contain the threat
4. Use mode **3** (Undo) if it was a false positive

---

### Files

- `run.sh`          → Main menu launcher
- `analyzer.py`     → Safe read-only viewer
- `defender.py`     → Active kill + block
- `undo.py`         → Reverse blocks
- `blocklist.txt`   → Auto-generated persistent list

---

**Last updated:** February 2026
