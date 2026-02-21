#!/bin/bash
# c2_beacon_hunter Setup & Management Script
# V2.5
# - Added comprehensive test mode with loopback support and Lomb-Scargle triggering
# - Improved container build and run logic
# - Added systemd service for native host installation
# @RW

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# ====================== TEST DEFAULTS (edit if desired) ======================
TEST_DEFAULT_IP="127.0.0.1"
TEST_DEFAULT_PORT="1337"
TEST_DEFAULT_DURATION=300
TEST_DEFAULT_PERIOD=60
TEST_DEFAULT_JITTER=0.35

# --- HELPER: Detect Container Runtime ---
get_runtime() {
    if command -v docker >/dev/null; then
        echo "docker"
    elif command -v podman >/dev/null; then
        echo "podman"
    else
        echo ""
    fi
}
RUNTIME=$(get_runtime)

# --- USAGE HELP ---
if [[ -z "$1" || "$1" == "help" ]]; then
    echo "Usage: sudo ./setup.sh [command]"
    echo ""
    echo "Commands:"
    echo "  install    - Install host dependencies"
    echo "  container  - Build the Docker/Podman image"
    echo "  test       - Comprehensive interactive test mode (loopback enabled)"
    echo "  run        - Run in Production Mode (Foreground)"
    echo "  start      - Start background service/container"
    echo "  stop       - Stop service/container"
    echo "  watch      - Tail detection logs"
    exit 0
fi

# --- 1. INSTALL ---
if [[ "$1" == "install" ]]; then
    echo "=== Installing Host Dependencies (v2.5) ==="
    if command -v apt-get >/dev/null; then
        PKG="apt-get"; UPDATE="apt-get update -qq"; INSTALL="$PKG install -y"
    elif command -v dnf >/dev/null; then
        PKG="dnf"; UPDATE="$PKG check-update || true"; INSTALL="$PKG install -y"
    elif command -v yum >/dev/null; then
        PKG="yum"; UPDATE="$PKG check-update || true"; INSTALL="$PKG install -y"
    else
        echo "Unsupported distro. Install python3-venv, auditd and curl manually."
        exit 1
    fi

    $UPDATE
    $INSTALL python3 python3-pip python3-venv auditd curl

    if [ ! -d "venv" ]; then
        echo "[*] Creating Python virtual environment..."
        python3 -m venv venv
    fi
    source venv/bin/activate
    echo "[*] Installing Python libraries..."
    pip install --upgrade pip
    pip install -r requirements.txt

    echo "[*] Configuring Auditd..."
    sudo mkdir -p /etc/audit/rules.d
    if [ -f audit_rules.d/c2_beacon.rules ]; then
        sudo cp audit_rules.d/c2_beacon.rules /etc/audit/rules.d/
        sudo auditctl -R /etc/audit/rules.d/c2_beacon.rules || true
    fi

    echo "[*] Installing Systemd Service..."
    cat <<EOF | sudo tee /etc/systemd/system/c2_beacon_hunter.service
[Unit]
Description=C2 Beacon Hunter v2.5 (Native)
After=network.target auditd.service

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/venv/bin/python3 $PROJECT_DIR/c2_beacon_hunter.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    echo "[+] Install complete."
    exit 0
fi

# --- 2. CONTAINER BUILD ---
if [[ "$1" == "container" ]]; then
    if [ -z "$RUNTIME" ]; then
        echo "Error: Docker or Podman not found."
        exit 1
    fi
    echo "=== Building Container Image v2.5 ($RUNTIME) ==="
    $RUNTIME build -t c2-beacon-hunter:v2.5 .
    echo "[+] Build complete."
    exit 0
fi

# --- 3. COMPREHENSIVE TEST MODE (Dynamic TEST_MODE=true) ---
if [[ "$1" == "test" ]]; then
    if [ -z "$RUNTIME" ]; then
        echo "Error: Docker or Podman not found."
        exit 1
    fi

    echo "=== Comprehensive Test Mode v2.5 ==="

    # User selects test profile
    echo "Select test profile:"
    echo "  1) Basic   - Low jitter (classic detection)"
    echo "  2) Advanced- High jitter (Lomb-Scargle test)"
    echo "  3) Custom"
    read -p "Choice [2]: " choice
    choice=${choice:-2}

    if [[ "$choice" == "1" ]]; then
        TEST_PERIOD=12
        TEST_JITTER=0.05
    elif [[ "$choice" == "2" ]]; then
        TEST_PERIOD=60
        TEST_JITTER=0.35
    else
        read -p "Base period (seconds) [60]: " TEST_PERIOD
        TEST_PERIOD=${TEST_PERIOD:-60}
        read -p "Jitter (0.0-1.0) [0.35]: " TEST_JITTER
        TEST_JITTER=${TEST_JITTER:-0.35}
    fi

    read -p "Target IP (127.0.0.1 for loopback) [$TEST_DEFAULT_IP]: " TARGET_IP
    TARGET_IP=${TARGET_IP:-$TEST_DEFAULT_IP}
    read -p "Duration (seconds) [$TEST_DEFAULT_DURATION]: " DURATION
    DURATION=${DURATION:-$TEST_DEFAULT_DURATION}
    read -p "Port [$TEST_DEFAULT_PORT]: " PORT
    PORT=${PORT:-$TEST_DEFAULT_PORT}

    echo ""
    echo "Starting test with:"
    echo "  Target   : $TARGET_IP:$PORT"
    echo "  Period   : $TEST_PERIOD s (±${TEST_JITTER} jitter)"
    echo "  Duration : $DURATION seconds"
    echo ""

    # Backup only config
    cp config.ini config.ini.bak 2>/dev/null || true

    # Fast polling for testing
    sed -i 's/snapshot_interval = .*/snapshot_interval = 5/' config.ini
    sed -i 's/analyze_interval = .*/analyze_interval = 30/' config.ini

    # Cleanup
    cleanup() {
        echo -e "\n\n[*] Cleaning up test mode..."
        $RUNTIME stop c2-beacon-hunter-test 2>/dev/null || true
        $RUNTIME rm -f c2-beacon-hunter-test 2>/dev/null || true
        mv -f config.ini.bak config.ini 2>/dev/null || true
        echo "[+] Test mode ended - production settings restored."
        exit 0
    }
    trap cleanup SIGINT SIGTERM EXIT

    # Start container with TEST_MODE=true (enables loopback)
    echo "[*] Starting hunter container in TEST MODE (loopback allowed)..."
    CONTAINER_ID=$($RUNTIME run -d --name c2-beacon-hunter-test \
        --network host --pid host --privileged \
        --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
        -e TEST_MODE=true \
        -v $(pwd)/config.ini:/app/config.ini \
        -v $(pwd)/c2_beacon_hunter.py:/app/c2_beacon_hunter.py \
        -v $(pwd)/BeaconML.py:/app/BeaconML.py \
        -v $(pwd)/output:/app/output \
        c2-beacon-hunter:v2.5)

    echo "[+] Hunter running in TEST MODE"
    sleep 5

    # Launch simulator
    echo "[*] Starting beacon simulator..."
    ./test_beacon_simulator.py \
        --target-ip "$TARGET_IP" \
        --port "$PORT" \
        --period "$TEST_PERIOD" \
        --jitter "$TEST_JITTER" \
        --duration "$DURATION"

    cleanup
fi

# --- 4. RUN (Production Foreground) ---
if [[ "$1" == "run" ]]; then
    if [ -z "$RUNTIME" ]; then
        echo "Error: Docker or Podman not found."
        exit 1
    fi
    echo "=== Running c2_beacon_hunter v2.5 in Production Mode ==="
    $RUNTIME run --rm -it --network host --pid host --privileged \
        --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
        -v /etc/timezone:/etc/timezone:ro \
        -v /etc/localtime:/etc/localtime:ro \
        -v $(pwd)/config.ini:/app/config.ini \
        -v $(pwd)/c2_beacon_hunter.py:/app/c2_beacon_hunter.py \
        -v $(pwd)/BeaconML.py:/app/BeaconML.py \
        -v $(pwd)/output:/app/output \
        c2-beacon-hunter:v2.5
    exit 0
fi

# --- 5. START (Background) ---
if [[ "$1" == "start" ]]; then
    USE_CONTAINER=$(grep -q "enabled = true" config.ini && echo "true" || echo "false")
    if [[ "$USE_CONTAINER" == "true" && -n "$RUNTIME" ]]; then
        echo "=== Starting c2_beacon_hunter v2.5 Container (Production) ==="
        $RUNTIME run -d --name c2-beacon-hunter --restart unless-stopped \
            --network host --pid host --privileged \
            --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
            -v /etc/timezone:/etc/timezone:ro \
            -v /etc/localtime:/etc/localtime:ro \
            -v $(pwd)/config.ini:/app/config.ini \
            -v $(pwd)/c2_beacon_hunter.py:/app/c2_beacon_hunter.py \
            -v $(pwd)/BeaconML.py:/app/BeaconML.py \
            -v $(pwd)/output:/app/output \
            c2-beacon-hunter:v2.5
        echo "[+] Container started."
    else
        echo "=== Starting Native Systemd Service ==="
        sudo systemctl start c2_beacon_hunter
        sudo systemctl enable c2_beacon_hunter
        echo "[+] Service started."
    fi
    exit 0
fi

# --- 6. STOP ---
if [[ "$1" == "stop" ]]; then
    echo "=== Stopping c2_beacon_hunter v2.5 ==="
    if [ -n "$RUNTIME" ]; then
        $RUNTIME stop c2-beacon-hunter 2>/dev/null || true
        $RUNTIME rm -f c2-beacon-hunter 2>/dev/null || true
        $RUNTIME stop c2-beacon-hunter-test 2>/dev/null || true
        $RUNTIME rm -f c2-beacon-hunter-test 2>/dev/null || true
    fi
    sudo systemctl stop c2_beacon_hunter 2>/dev/null || true
    echo "[+] Stopped."
    exit 0
fi

# --- 7. WATCH LOGS ---
if [[ "$1" == "watch" ]]; then
    tail -f output/detections.log
    exit 0
fi

echo "Unknown command: $1"
echo "Run './setup.sh help' for usage."
exit 1