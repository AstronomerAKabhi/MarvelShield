#!/usr/bin/env bash
# MarvelShield x OWASP Juice Shop Quick Setup
# Usage: bash juice_setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JUICE_DIR="$HOME/juice-shop"
JUICE_PORT=3001

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'

ok()   { echo -e "${GREEN}  OK   $*${RESET}"; }
warn() { echo -e "${YELLOW}  WARN $*${RESET}"; }
info() { echo -e "${DIM}  ...  $*${RESET}"; }
die()  { echo -e "${RED}  FAIL $*${RESET}"; exit 1; }

echo
echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}  MarvelShield x OWASP Juice Shop - Quick Setup${RESET}"
echo -e "${CYAN}======================================================${RESET}"
echo

# Step 1: Install Juice Shop
if [ -f "$JUICE_DIR/node_modules/juice-shop/app.js" ]; then
    ok "Juice Shop already installed at $JUICE_DIR"
else
    echo -e "${BOLD}  Step 1/3 - Installing OWASP Juice Shop (2-3 min)...${RESET}"
    mkdir -p "$JUICE_DIR"
    cd "$JUICE_DIR"
    npm install juice-shop 2>&1 | tail -5
    cd "$SCRIPT_DIR"
    ok "Juice Shop installed"
fi
echo

# Step 2: Kill anything on port 3001 and start Juice Shop
PID=$(lsof -ti :"$JUICE_PORT" 2>/dev/null || true)
if [ -n "$PID" ]; then
    warn "Port $JUICE_PORT in use - killing PID $PID"
    kill -9 "$PID" 2>/dev/null || true
    sleep 0.5
fi

echo -e "${BOLD}  Step 2/3 - Starting Juice Shop on port $JUICE_PORT...${RESET}"
cd "$JUICE_DIR"
PORT=$JUICE_PORT node node_modules/juice-shop/app.js > /tmp/juice-shop.log 2>&1 &
JUICE_PID=$!
echo "$JUICE_PID" > /tmp/juice-shop.pid
cd "$SCRIPT_DIR"

info "Waiting for Juice Shop to become healthy (PID $JUICE_PID)..."
MAX=60
ELAPSED=0
while ! curl -sf --max-time 2 "http://127.0.0.1:$JUICE_PORT" >/dev/null 2>&1; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -ne "\r  Waiting... ${ELAPSED}s / ${MAX}s   "
    if [ "$ELAPSED" -ge "$MAX" ]; then
        echo
        die "Juice Shop did not start in ${MAX}s. Check /tmp/juice-shop.log"
    fi
done
echo
ok "Juice Shop is running at http://127.0.0.1:$JUICE_PORT"
echo

# Step 3: Update TARGET_APP in .env
echo -e "${BOLD}  Step 3/3 - Pointing MarvelShield at Juice Shop...${RESET}"
ENV_FILE="$SCRIPT_DIR/.env"
if grep -q "^TARGET_APP=" "$ENV_FILE"; then
    sed -i "s|^TARGET_APP=.*|TARGET_APP=http://127.0.0.1:$JUICE_PORT|" "$ENV_FILE"
else
    echo "TARGET_APP=http://127.0.0.1:$JUICE_PORT" >> "$ENV_FILE"
fi
ok ".env updated: TARGET_APP=http://127.0.0.1:$JUICE_PORT"
echo

# Summary
echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}  All done! MarvelShield is now guarding Juice Shop.${RESET}"
echo -e "${CYAN}======================================================${RESET}"
echo
echo -e "  Juice Shop direct : http://localhost:$JUICE_PORT"
echo -e "  Through gateway   : http://localhost:8000  ${BOLD}(use this for demo)${RESET}"
echo -e "  Dashboard         : http://localhost:3000"
echo
echo -e "  ${YELLOW}Restart gateway:${RESET}"
echo -e "    .venv/bin/uvicorn gateway:app --host 0.0.0.0 --port 8000"
echo
echo -e "  ${YELLOW}Run attacks:${RESET}"
echo -e "    .venv/bin/python3 juice_attack.py"
echo
echo -e "  ${DIM}Stop Juice Shop: kill \$(cat /tmp/juice-shop.pid)${RESET}"
echo
