#!/bin/bash

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=== c2_beacon_hunter Graceful Shutdown ==="

# 1. Container mode (Docker or Podman)
if docker ps --format '{{.Names}}' | grep -q "c2-beacon-hunter"; then
    echo "Stopping Docker container..."
    docker stop -t 30 c2-beacon-hunter || true
    echo "Container stopped gracefully."
    exit 0
elif podman ps --format '{{.Names}}' | grep -q "c2-beacon-hunter"; then
    echo "Stopping Podman container..."
    podman stop -t 30 c2-beacon-hunter || true
    echo "Container stopped gracefully."
    exit 0
fi

# 2. Systemd service
if systemctl is-active --quiet c2_beacon_hunter.service; then
    echo "Stopping systemd service (SIGTERM sent)..."
    sudo systemctl stop c2_beacon_hunter.service
    echo "Service stopped gracefully. Final export completed."
    exit 0
fi

# 3. Standalone Python process
PID=$(pgrep -f "c2_beacon_hunter.py" | head -n 1)
if [ -n "$PID" ]; then
    echo "Found standalone process (PID $PID). Sending SIGTERM..."
    kill -TERM "$PID" 2>/dev/null || true
    echo "Waiting up to 30 seconds for clean shutdown..."
    for i in {1..30}; do
        if ! ps -p "$PID" > /dev/null; then
            echo "Process terminated gracefully. Final export completed."
            exit 0
        fi
        sleep 1
    done
    echo "Process did not exit in time. Forcing SIGKILL..."
    kill -KILL "$PID" 2>/dev/null || true
else
    echo "No running c2_beacon_hunter process or container found."
fi

echo "Shutdown sequence complete."