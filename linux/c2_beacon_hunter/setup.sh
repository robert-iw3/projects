#!/bin/bash

# c2_beacon_hunter Setup & Management Script
# V2.4 - Includes Smart Test Mode (Auto-Patching)

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

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
    echo "  install    - Install host dependencies (Python venv, Auditd)"
    echo "  container  - Build the Docker/Podman image"
    echo "  test       - Run in TEST MODE (Fast polling + Loopback allowed)"
    echo "  run        - Run in Production Mode (Foreground)"
    echo "  start      - Start Systemd Service (Background)"
    echo "  stop       - Stop Service/Container"
    echo "  watch      - Tail the detection logs"
    exit 0
fi

# --- 1. INSTALL (Native Host) ---
if [[ "$1" == "install" ]]; then
    echo "=== Installing Host Dependencies ==="

    # Distro Detection
    if command -v apt-get >/dev/null; then
        PKG="apt-get"; UPDATE="apt-get update -qq"; INSTALL="$PKG install -y"
    elif command -v dnf >/dev/null; then
        PKG="dnf"; UPDATE="$PKG check-update || true"; INSTALL="$PKG install -y"
    elif command -v yum >/dev/null; then
        PKG="yum"; UPDATE="$PKG check-update || true"; INSTALL="$PKG install -y"
    else
        echo "Unsupported distro. Please install python3-venv and auditd manually."
        exit 1
    fi

    $UPDATE
    $INSTALL python3 python3-pip python3-venv auditd curl

    # Python Venv
    if [ ! -d "venv" ]; then
        echo "[*] Creating Python virtual environment..."
        python3 -m venv venv
    fi
    source venv/bin/activate
    echo "[*] Installing Python libraries..."
    pip install --upgrade pip
    pip install -r requirements.txt

    # Auditd Rules
    echo "[*] Configuring Auditd..."
    sudo mkdir -p /etc/audit/rules.d
    if [ -f audit_rules.d/c2_beacon.rules ]; then
        sudo cp audit_rules.d/c2_beacon.rules /etc/audit/rules.d/
        sudo auditctl -R /etc/audit/rules.d/c2_beacon.rules || true
    fi

    # Systemd Service
    echo "[*] Installing Systemd Service..."
    cat <<EOF | sudo tee /etc/systemd/system/c2_beacon_hunter.service
[Unit]
Description=C2 Beacon Hunter (Native)
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
    echo "[+] Install Complete. Run './setup.sh start' to launch."
    exit 0
fi

# --- 2. CONTAINER BUILD ---
if [[ "$1" == "container" ]]; then
    if [ -z "$RUNTIME" ]; then echo "Error: Docker or Podman not found."; exit 1; fi
    echo "=== Building Container Image ($RUNTIME) ==="
    $RUNTIME build -t c2-beacon-hunter:latest .
    echo "[+] Build Complete."
    exit 0
fi

# --- 3. TEST MODE (The Smart Patch Logic) ---
if [[ "$1" == "test" ]]; then
    if [ -z "$RUNTIME" ]; then echo "Error: Docker or Podman not found."; exit 1; fi

    echo -e "\n\033[1;33m=== TEST MODE: Fast Polling + Loopback Allowed ===\033[0m"
    echo "    (Press Ctrl+C to stop and revert to Production Mode)"

    # A. Backup Original Files
    cp config.ini config.ini.bak
    cp c2_beacon_hunter.py c2_beacon_hunter.py.bak

    # B. Patch Config (Fast Intervals)
    # Change snapshot to 5s, analyze to 30s
    sed -i 's/snapshot_interval = .*/snapshot_interval = 5/' config.ini
    sed -i 's/analyze_interval = .*/analyze_interval = 30/' config.ini

    # C. Patch Code (Disable Loopback Filter)
    # This allows the tool to see your local test traffic (127.0.0.1 / 192.168.x.x)
    echo "[*] Temporarily patching c2_beacon_hunter.py to allow loopback traffic..."
    sed -i "s/if raddr in (\"127.0.0.1\", \"::1\", \"0.0.0.0\"):/if False and raddr in (\"127.0.0.1\", \"::1\", \"0.0.0.0\"): # PATCHED/g" c2_beacon_hunter.py

    # D. Cleanup Function (Reverts EVERYTHING on Exit)
    cleanup() {
        echo -e "\n\n\033[1;32m[*] Cleaning up & Reverting to Production Mode...\033[0m"

        # Restore Originals
        mv c2_beacon_hunter.py.bak c2_beacon_hunter.py
        echo "    - Restored c2_beacon_hunter.py"

        mv config.ini.bak config.ini
        echo "    - Restored config.ini"

        echo "[+] System Ready for Production."
        exit
    }
    trap cleanup SIGINT SIGTERM EXIT

    # E. Run Container (Mounting the patched files)
    # We mount the LOCAL modified files over the container's files
    echo "[*] Starting Container..."

    $RUNTIME run --rm -it --network host --pid host --privileged \
        --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
        -v $(pwd)/config.ini:/app/config.ini \
        -v $(pwd)/output:/app/output \
        -v $(pwd)/c2_beacon_hunter.py:/app/c2_beacon_hunter.py \
        c2-beacon-hunter:latest

    exit 0
fi

# --- 4. RUN (Foreground Production) ---
if [[ "$1" == "run" ]]; then
    if [ -z "$RUNTIME" ]; then echo "Error: Docker or Podman not found."; exit 1; fi
    echo "=== Running in Production Mode (Foreground) ==="

    $RUNTIME run --rm -it --network host --pid host --privileged \
        --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
        -v /etc/timezone:/etc/timezone:ro \
        -v /etc/localtime:/etc/localtime:ro \
        -v $(pwd)/config.ini:/app/config.ini \
        -v $(pwd)/output:/app/output \
        c2-beacon-hunter:latest
    exit 0
fi

# --- 5. START (Background Service) ---
if [[ "$1" == "start" ]]; then
    # Check if we should start Container or Native Service
    # (Simple logic: if config says container.enabled=true, use docker, else systemd)
    USE_CONTAINER=$(grep "enabled = true" config.ini || echo "")

    if [[ -n "$USE_CONTAINER" && -n "$RUNTIME" ]]; then
        echo "=== Starting Container Daemon ==="
        $RUNTIME run -d --name c2-beacon-hunter --restart unless-stopped \
            --network host --pid host --privileged \
            --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
            -v /etc/timezone:/etc/timezone:ro \
            -v /etc/localtime:/etc/localtime:ro \
            -v $(pwd)/config.ini:/app/config.ini \
            -v $(pwd)/output:/app/output \
            c2-beacon-hunter:latest
        echo "[+] Container started in background."
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
    echo "=== Stopping Service ==="
    if [ -n "$RUNTIME" ]; then
        $RUNTIME stop c2-beacon-hunter 2>/dev/null || true
        $RUNTIME rm c2-beacon-hunter 2>/dev/null || true
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