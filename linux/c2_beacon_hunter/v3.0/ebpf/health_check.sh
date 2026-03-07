#!/bin/bash
# ==============================================================================
# health_check.sh - v3.0
# ==============================================================================

if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

echo "====================================================================="
echo " C2 BEACON HUNTER v3.0 - HEALTH CHECK"
echo "====================================================================="

# Detect current mode
MODE=$(grep -E "^mode\s*=" /app/config.ini 2>/dev/null | cut -d= -f2 | tr -d ' ' || echo "host")
echo "[*] Epic 1 Mode: ${MODE^^}"

# Phase 0: Process & Loader
echo ""
echo "[*] Phase 0: Process & Loader"
if pgrep -f "c2_beacon_hunter" > /dev/null; then
    echo " [OK] Main hunter running"
else
    echo " [FAIL] Main hunter not running"
fi

if [ "$MODE" = "promisc" ]; then
    if pgrep -f "c2_promisc_loader" > /dev/null; then
        echo " [OK] Promiscuous XDP loader running (Epic 1)"
    else
        echo " [WARN] Promiscuous loader not detected"
    fi
else
    if pgrep -f "c2_loader" > /dev/null; then
        echo " [OK] Standard loader running (host mode)"
    else
        echo " [WARN] Standard loader not detected"
    fi
fi

# Phase 1: eBPF Objects
echo ""
echo "[*] Phase 1: eBPF Objects"
if [ "$MODE" = "promisc" ]; then
    ip link show type xdp | grep -q "xdp" && echo " [OK] XDP promisc parser attached" || echo " [WARN] No XDP program attached"
else
    echo " [INFO] Host mode — using kprobes/tracepoints"
fi

# Phase 2: Database Ingestion
echo ""
echo "[*] Phase 2: Database Ingestion"
if [ -f "/app/data/baseline.db" ]; then
    COUNT=$(sqlite3 /app/data/baseline.db "SELECT COUNT(*) FROM flows;" 2>/dev/null || echo "0")
    LAST=$(sqlite3 /app/data/baseline.db "SELECT MAX(timestamp) FROM flows;" 2>/dev/null || echo "0")
    if [ "$LAST" != "0" ]; then
        LAG=$(awk "BEGIN {print $(date +%s) - $LAST}")
        echo " [OK] Flows: $COUNT | Last event: ${LAG}s ago"
    else
        echo " [WARN] Database exists but no flows yet"
    fi
else
    echo " [FAIL] baseline.db not found"
fi

# Phase 3: Detections
echo ""
echo "[*] Phase 3: Detections"
if [ -f "/app/output/anomalies.jsonl" ]; then
    DETECT=$(wc -l < /app/output/anomalies.jsonl)
    echo " [INFO] Total detections: $DETECT"
else
    echo " [INFO] No detections yet"
fi

echo ""
echo "====================================================================="
echo " Health Check Complete — v3.0 "
echo "====================================================================="