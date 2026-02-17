#!/bin/bash

# Configuration
TEST_PORT="1337"
DURATION_SECONDS=300 # Run for 5 minutes to ensure multiple snapshots
# Find the real LAN IP (excludes 127.0.0.1) to bypass localhost filtering
TARGET_IP=$(hostname -I | awk '{print $1}')

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ -z "$TARGET_IP" ]; then
    echo -e "${RED}[!] Could not detect LAN IP. Falling back to 127.0.0.1 (Might be ignored by Hunter)${NC}"
    TARGET_IP="127.0.0.1"
fi

cleanup() {
    echo -e "\n${RED}[*] Stopping Test...${NC}"
    kill $SERVER_PID 2>/dev/null
    exit
}
trap cleanup SIGINT SIGTERM EXIT

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}    ADVANCED C2 SIMULATION (Docker Compatible)${NC}"
echo -e "${CYAN}====================================================${NC}"
echo -e "${YELLOW}[*] Using Interface IP: ${TARGET_IP} (To bypass localhost filters)${NC}"

# 1. Start Python C2 Server (Multi-threaded to handle holds)
echo -e "${GREEN}[+] Starting Python C2 Server on ${TARGET_IP}:${TEST_PORT}...${NC}"

python3 -c "
import socket, threading, time

def handle_client(conn, addr):
    # Hold connection to ensure 'ss' in Docker sees it
    time.sleep(2)
    conn.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$TARGET_IP', $TEST_PORT))
s.listen(5)
print(f'Server listening...')
while True:
    conn, addr = s.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()
" &
SERVER_PID=$!

sleep 2

# 2. Start Beaconing Loop
echo -e "${GREEN}[+] Starting Implant Beaconing...${NC}"
echo -e "    Strategy: Connect -> Hold 3s -> Close -> Sleep ~10s"
echo -e "    This ensures the Docker 'ss' command catches the state 'ESTABLISHED'"

COUNTER=0
START_TIME=$(date +%s)

while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))
    if [ $ELAPSED -ge $DURATION_SECONDS ]; then break; fi

    # Python Client to connect and hold
    # We hold the socket open for 3 seconds so the hunter snapshot hits it
    python3 -c "
import socket, time
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('$TARGET_IP', $TEST_PORT))
    time.sleep(3) # HOLD OPEN FOR SNAPSHOT
    s.close()
except Exception as e:
    print(f'Connection failed: {e}')
"

    COUNTER=$((COUNTER + 1))
    echo -ne "\r${CYAN}[*] Beacon #$COUNTER sent to $TARGET_IP | Active for ${ELAPSED}s${NC}"

    # Jitter sleep (Wait 5-15 seconds)
    # Fast enough to build up volume, slow enough to look suspicious
    sleep $(( 5 + RANDOM % 10 ))
done

echo -e "\n${GREEN}[+] Test Complete.${NC}"