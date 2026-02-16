#!/bin/bash

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=== c2_beacon_hunter  One-Shot Setup ==="

if command -v apt-get >/dev/null; then
    PKG="apt-get"; UPDATE="apt-get update -qq"; INSTALL="$PKG install -y"
elif command -v dnf >/dev/null; then
    PKG="dnf"; UPDATE="$PKG check-update || true"; INSTALL="$PKG install -y"
elif command -v yum >/dev/null; then
    PKG="yum"; UPDATE="$PKG check-update || true"; INSTALL="$PKG install -y"
else
    echo "Unsupported distro"; exit 1
fi

$UPDATE
$INSTALL python3 python3-pip python3-venv auditd curl

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

sudo mkdir -p /etc/audit/rules.d
sudo cp audit_rules.d/c2_beacon.rules /etc/audit/rules.d/
sudo auditctl -R /etc/audit/rules.d/c2_beacon.rules || true
sudo systemctl restart auditd || true

sudo mkdir -p /etc/systemd/system
sudo cp systemd/c2_beacon_hunter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable c2_beacon_hunter.service

echo "=== Setup complete!  ready ==="

case "$1" in
    install) echo "Now run: sudo ./setup.sh run (native) or sudo ./setup.sh container" ;;
    run)
        sudo systemctl start c2_beacon_hunter.service
        echo "Service started. Tailing detections..."
        sleep 4
        sudo ./setup.sh verify
        journalctl -u c2_beacon_hunter -f --no-pager -n 30
        ;;
    verify)
        echo "=== Verification ==="
        systemctl is-active --quiet c2_beacon_hunter && echo "✓ Service RUNNING" || echo "✗ Service NOT running"
        ps aux | grep -v grep | grep -q "c2_beacon_hunter.py" && echo "✓ Python process ACTIVE" || echo "✗ No process"
        [ -f output/detections.log ] && echo "✓ detections.log exists ($(wc -l < output/detections.log 2>/dev/null || echo 0) lines)" || echo "✗ No log yet"
        echo "SIEM files: output/anomalies.csv + output/anomalies.jsonl"
        tail -n 10 output/detections.log 2>/dev/null || echo "(No detections yet — normal)"
        ;;
    watch) tail -f output/detections.log ;;
    stop|shutdown)
        echo "=== Graceful Shutdown () ==="
        sudo ./graceful_shutdown.sh
        ;;
    container)
        echo "=== Docker / Podman Container Mode ==="
        if grep -q "enabled = true" config.ini 2>/dev/null; then
            echo "Container mode enabled"
        else
            read -p "Enable container mode and update config.ini? (y/n): " enable_choice
            if [[ $enable_choice == "y" ]]; then
                cat >> config.ini << EOF

[container]
enabled = true
runtime = auto
EOF
            fi
        fi
        read -p "Choose runtime (docker / podman / auto) [auto]: " runtime_choice
        runtime=${runtime_choice:-auto}
        if [[ $runtime == "auto" ]]; then
            if command -v docker >/dev/null; then runtime="docker"
            elif command -v podman >/dev/null; then runtime="podman"
            else echo "No container runtime found!"; exit 1; fi
        fi
        echo "Using runtime: $runtime"
        read -p "Build image now? (y/n): " build_choice
        if [[ $build_choice == "y" ]]; then
            $runtime build -t c2-beacon-hunter:latest .
        fi
        read -p "Run container now in foreground? (y/n): " runnow
        if [[ $runnow == "y" ]]; then
            $runtime run --name c2-beacon-hunter --rm -it \
              --privileged --pid=host --network=host \
              -v /var/log/audit:/var/log/audit:ro \
              -v /proc:/host/proc:ro \
              -v "$(pwd)/output:/app/output" \
              c2-beacon-hunter:latest
        else
            read -p "Run in background as daemon? (y/n): " daemon
            if [[ $daemon == "y" ]]; then
                $runtime run -d --name c2-beacon-hunter --restart unless-stopped \
                  --privileged --pid=host --network=host \
                  -v /var/log/audit:/var/log/audit:ro \
                  -v /proc:/host/proc:ro \
                  -v "$(pwd)/output:/app/output" \
                  c2-beacon-hunter:latest
                echo "Container started. Logs: $runtime logs -f c2-beacon-hunter"
            fi
        fi
        ;;
    *)
        echo "Usage: sudo ./setup.sh [install|run|verify|watch|stop|shutdown|container]"
        ;;
esac