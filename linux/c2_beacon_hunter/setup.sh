#!/bin/bash

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=== c2_beacon_hunter One-Shot Setup ==="

# --- Dependency Check & Install ---
if command -v apt-get >/dev/null; then
    PKG="apt-get"; UPDATE="apt-get update -qq"; INSTALL="$PKG install -y"
elif command -v dnf >/dev/null; then
    PKG="dnf"; UPDATE="$PKG check-update || true"; INSTALL="$PKG install -y"
elif command -v yum >/dev/null; then
    PKG="yum"; UPDATE="$PKG check-update || true"; INSTALL="$PKG install -y"
else
    echo "Unsupported distro"; exit 1
fi

# Only install host dependencies if NOT in container mode
if [[ "$1" != "container" ]]; then
    $UPDATE
    $INSTALL python3 python3-pip python3-venv auditd curl

    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt

    # Systemd & Auditd Setup
    sudo mkdir -p /etc/audit/rules.d
    sudo cp audit_rules.d/c2_beacon.rules /etc/audit/rules.d/ 2>/dev/null || true
    if [ -f /etc/audit/rules.d/c2_beacon.rules ]; then
        sudo auditctl -R /etc/audit/rules.d/c2_beacon.rules || true
        sudo systemctl restart auditd || true
    fi

    sudo mkdir -p /etc/systemd/system
    sudo cp systemd/c2_beacon_hunter.service /etc/systemd/system/ 2>/dev/null || true
    sudo systemctl daemon-reload
    sudo systemctl enable c2_beacon_hunter.service 2>/dev/null || true
fi

echo "=== Setup complete! ready ==="

# Function to restore config on exit during test mode
restore_config() {
    echo ""
    echo "[*] Teardown: Stopping test components..."

    # Kill the background test script if running
    if [ -n "$TEST_PID" ]; then
        kill $TEST_PID 2>/dev/null || true
    fi

    # Restore Config
    if [ -f config.ini.bak ]; then
        echo "[*] Restoring original config.ini..."
        mv config.ini.bak config.ini
    fi
}

case "$1" in
    install) echo "Now run: sudo ./setup.sh run (native) or sudo ./setup.sh container" ;;
    run)
        sudo systemctl start c2_beacon_hunter.service
        echo "Service started. Tailing detections..."
        sleep 4
        sudo "$0" verify
        journalctl -u c2_beacon_hunter -f --no-pager -n 30
        ;;
    verify)
        echo "=== Verification ==="
        systemctl is-active --quiet c2_beacon_hunter && echo "✓ Service RUNNING" || echo "✗ Service NOT running"
        ps aux | grep -v grep | grep -q "c2_beacon_hunter.py" && echo "✓ Python process ACTIVE" || echo "✗ No process"
        [ -f output/detections.log ] && echo "✓ detections.log exists ($(wc -l < output/detections.log 2>/dev/null || echo 0) lines)" || echo "✗ No log yet"
        tail -n 10 output/detections.log 2>/dev/null || echo "(No detections yet — normal)"
        ;;
    watch) tail -f output/detections.log ;;
    stop|shutdown)
        echo "=== Graceful Shutdown ==="
        if [ -f graceful_shutdown.sh ]; then
            sudo ./graceful_shutdown.sh
        else
            sudo systemctl stop c2_beacon_hunter.service
        fi
        ;;
    test)
        echo "=== LIVE TEST MODE ==="

        # Check for test script
        TEST_SCRIPT="tests/live_c2_advanced.sh"
        if [ ! -f "$TEST_SCRIPT" ]; then
            echo "[-] Error: Test script not found at $TEST_SCRIPT"
            exit 1
        fi
        chmod +x "$TEST_SCRIPT"

        # 1. Backup Config & Trap Exit
        cp config.ini config.ini.bak
        trap restore_config EXIT INT TERM

        # 2. Modify Config for Speed
        echo "[*] Tuning config for test (Snapshot: 5s, Analyze: 30s)..."
        sed -i 's/snapshot_interval = .*/snapshot_interval = 5/' config.ini
        sed -i 's/analyze_interval = .*/analyze_interval = 30/' config.ini

        # 3. Start Traffic Generator in Background
        echo "[*] Starting Traffic Generator ($TEST_SCRIPT)..."
        "$TEST_SCRIPT" &
        TEST_PID=$!
        echo "[*] Traffic Generator PID: $TEST_PID"

        # 4. Run Hunter (Container or Native)
        if grep -q "enabled = true" config.ini; then
            echo "[*] Mode: Container"
            if command -v docker >/dev/null; then RUNTIME="docker"; elif command -v podman >/dev/null; then RUNTIME="podman"; else echo "No runtime"; exit 1; fi

            echo "[*] Rebuilding container..."
            $RUNTIME build -t c2-beacon-hunter:latest . >/dev/null

            echo "[*] Starting Hunter (Foreground)..."
            # Mount config explicitly so we can verify the change inside
            $RUNTIME run --name c2-beacon-hunter --rm -it \
              --privileged --pid=host --network=host \
              --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
              -v /var/log/audit:/var/log/audit:ro \
              -v /proc:/host/proc:ro \
              -v "$(pwd)/output:/app/output" \
              -v "$(pwd)/config.ini:/app/config.ini" \
              c2-beacon-hunter:latest
        else
            echo "[*] Mode: Native Service"
            echo "[*] Restarting Service..."
            sudo systemctl restart c2_beacon_hunter
            echo "[*] Tailing logs (Ctrl+C to stop)..."
            journalctl -u c2_beacon_hunter -f --no-pager
        fi
        ;;
    container)
        echo "=== Docker / Podman Container Mode ==="

        if command -v docker >/dev/null 2>&1; then RUNTIME="docker"; elif command -v podman >/dev/null 2>&1; then RUNTIME="podman"; else echo "[-] Error: Neither docker nor podman found."; exit 1; fi
        echo "[+] Detected Runtime: $RUNTIME"

        read -p "Build image now? (y/n): " build_choice
        if [[ $build_choice == "y" ]]; then
            echo "[*] Building c2-beacon-hunter:latest..."
            $RUNTIME build -t c2-beacon-hunter:latest .
        fi

        echo "[*] Removing old instances..."
        $RUNTIME rm -f c2-beacon-hunter 2>/dev/null || true

        BASE_ARGS="--name c2-beacon-hunter --privileged --pid=host --network=host --cap-add=NET_ADMIN --cap-add=SYS_ADMIN "

        # Mount config.ini so host changes reflect immediately
        MOUNTS="-v /var/log/audit:/var/log/audit:ro \
                -v /proc:/host/proc:ro \
                -v $(pwd)/output:/app/output \
                -v $(pwd)/config.ini:/app/config.ini"

        if [ -f /etc/timezone ]; then MOUNTS="$MOUNTS -v /etc/timezone:/etc/timezone:ro"; fi
        if [ -f /etc/localtime ]; then MOUNTS="$MOUNTS -v /etc/localtime:/etc/localtime:ro"; fi

        echo ""
        echo "Select Run Mode:"
        echo "  1) Foreground (Interactive - Ctrl+C to stop)"
        echo "  2) Background (Daemon - Restart on boot)"
        read -p "Choice [1]: " run_mode
        run_mode=${run_mode:-1}

        if [[ $run_mode == "1" ]]; then
            echo "[*] Starting in Foreground..."
            # shellcheck disable=SC2086
            $RUNTIME run --rm -it $BASE_ARGS $MOUNTS c2-beacon-hunter:latest
        elif [[ $run_mode == "2" ]]; then
            echo "[*] Starting in Background..."
            # shellcheck disable=SC2086
            $RUNTIME run -d --restart unless-stopped $BASE_ARGS $MOUNTS c2-beacon-hunter:latest
            echo "[+] Container started!"
            echo "    View logs: $RUNTIME logs -f c2-beacon-hunter"
        else
            echo "Invalid choice."
            exit 1
        fi
        ;;
    *)
        echo "Usage: sudo ./setup.sh [install|run|verify|watch|stop|shutdown|container|test]"
        ;;
esac