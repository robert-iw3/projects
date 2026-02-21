#!/bin/bash
# c2_defend/run.sh
cd "$(dirname "$0")"

echo "=== c2_defend ==="

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo "This tool must be run as root (it kills processes and modifies firewall rules)."
    echo "Re-running with sudo..."
    exec sudo "$0" "$@"
fi

# Check parent venv
if [ ! -d "../venv" ]; then
    echo "Error: Parent virtual environment not found."
    echo "Please run '../setup.sh install' first."
    exit 1
fi

source ../venv/bin/activate

echo ""
echo "Available modes:"
echo "   1) Analyzer     - View latest detections (safe, read-only)"
echo "   2) Defender     - Active protection (kill + firewall block)"
echo "   3) Undo         - Reverse previous firewall blocks"
echo ""

read -p "Select mode [2]: " choice
choice=${choice:-2}

case "$choice" in
    1)
        echo "[*] Starting Analyzer..."
        python3 analyzer.py
        ;;
    2)
        echo "[*] Starting Active Defender..."
        python3 defender.py
        ;;
    3)
        echo "[*] Starting Undo Utility..."
        python3 undo.py
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac