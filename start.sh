#!/usr/bin/env bash
# =============================================================================
# MarvelShield — One-Click Launcher
# =============================================================================
# Creates a tmux session with 5 panes, one per service, then runs the
# attack simulation automatically once everything is healthy.
#
# Usage:
#   ./start.sh                  # uses GEMINI_API_KEY from .env or env
#   GEMINI_API_KEY=xxx ./start.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="marvelshield"

# ─── Colours ─────────────────────────────────────────────────────────────────
RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'

info()  { echo -e "${DIM}  ·  $*${RESET}"; }
ok()    { echo -e "${GREEN}  ✅  $*${RESET}"; }
warn()  { echo -e "${YELLOW}  ⚠️   $*${RESET}"; }
die()   { echo -e "${RED}  ❌  $*${RESET}"; exit 1; }

# ─── Banner ──────────────────────────────────────────────────────────────────
echo
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}${BOLD}        🛡  MarvelShield — One-Click Launcher                 ${RESET}${CYAN}║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo

# ─── Load .env ───────────────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/.env"
    info "Loaded .env"
fi

# ─── Validate GEMINI_API_KEY ─────────────────────────────────────────────────
if [[ -z "${GEMINI_API_KEY:-}" ]]; then
    echo -e "${YELLOW}  GEMINI_API_KEY is not set.${RESET}"
    read -rp "  Enter your Gemini API key: " GEMINI_API_KEY
    if [[ -z "$GEMINI_API_KEY" ]]; then
        die "GEMINI_API_KEY is required — get one at https://aistudio.google.com/apikey"
    fi
    # Persist for future runs
    echo "GEMINI_API_KEY=$GEMINI_API_KEY" >> "$SCRIPT_DIR/.env"
    ok "Saved key to .env (won't ask again)"
fi
export GEMINI_API_KEY

# ─── Resolve Python / venv ───────────────────────────────────────────────────
# Use relative paths — panes inherit cwd ($SCRIPT_DIR), so no space issues.
if [[ -f "$SCRIPT_DIR/.venv/bin/activate" ]]; then
    VENV_ACTIVATE="source .venv/bin/activate && "
    PYTHON=".venv/bin/python3"
    UVICORN=".venv/bin/uvicorn"
    ok "Using .venv"
else
    VENV_ACTIVATE=""
    PYTHON="python3"
    UVICORN="uvicorn"
    warn "No .venv — using system Python (install deps globally if errors occur)"
fi

# ─── Dependency checks ───────────────────────────────────────────────────────
echo -e "${BOLD}  Checking dependencies…${RESET}"

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        die "'$1' not found. Install it first: $2"
    fi
    ok "$1"
}

check_cmd tmux      "sudo apt install tmux"
check_cmd node      "sudo apt install nodejs npm"
check_cmd python3   "sudo apt install python3"
check_cmd redis-cli "sudo apt install redis-server"

# uvicorn may live only in the venv — check its resolved path
if ! command -v "$UVICORN" &>/dev/null 2>&1 && [[ ! -x "$UVICORN" ]]; then
    die "uvicorn not found at '$UVICORN'. Run: pip install -r requirements.txt"
fi
ok "uvicorn"

echo

# ─── Kill stale session ───────────────────────────────────────────────────────
if tmux has-session -t "$SESSION" 2>/dev/null; then
    warn "Existing tmux session '$SESSION' found — killing it."
    tmux kill-session -t "$SESSION"
fi

# ─── Free ports ───────────────────────────────────────────────────────────────
for PORT in 8000 8080 3000; do
    PID=$(lsof -ti :"$PORT" 2>/dev/null || true)
    if [[ -n "$PID" ]]; then
        warn "Port $PORT in use by PID $PID — killing."
        kill -9 "$PID" 2>/dev/null || true
        sleep 0.3
    fi
done

# ─── Start Redis ──────────────────────────────────────────────────────────────
info "Starting Redis…"
sudo service redis-server start >/dev/null 2>&1 || true
sleep 1
if redis-cli ping 2>/dev/null | grep -q PONG; then
    ok "Redis is up"
else
    die "Redis did not start. Try: sudo service redis-server start"
fi

# ─── Create tmux session ──────────────────────────────────────────────────────
# Layout:
#
#   ┌─────────────────────┬─────────────────────┐
#   │  0: gateway.py      │  1: app.js           │
#   │  (port 8000)        │  (port 8080)         │
#   ├─────────────────────┼─────────────────────┤
#   │  2: brain.py        │  3: bridge.js        │
#   │  (AI engine)        │  (Socket.io relay)   │
#   └─────────────────────┴─────────────────────┘
#   │  4: simulate_attack.py  (bottom full-width) │
#   └─────────────────────────────────────────────┘

info "Building tmux layout…"

cd "$SCRIPT_DIR"

set +e

COLS=$(tput cols 2>/dev/null || echo 220)
ROWS=$(tput lines 2>/dev/null || echo 50)

# -c sets the start directory for each pane — tmux handles spaces in paths correctly
tmux new-session  -d -s "$SESSION" -x "$COLS" -y "$ROWS" -c "$SCRIPT_DIR" 2>/dev/null
tmux split-window -h -t "$SESSION:0.0" -c "$SCRIPT_DIR"          2>/dev/null
tmux split-window -v -t "$SESSION:0.0" -c "$SCRIPT_DIR"          2>/dev/null
tmux split-window -v -t "$SESSION:0.1" -c "$SCRIPT_DIR"          2>/dev/null
tmux new-window   -t "$SESSION:1" -n "Simulation" -c "$SCRIPT_DIR" 2>/dev/null

set -e

# ─── Label panes in window 0 ─────────────────────────────────────────────────
lbl() { tmux select-pane -t "$SESSION:0.$1" -T "$2" 2>/dev/null || true; }
lbl 0 "Gateway  :8000"
lbl 1 "App.js   :8080"
lbl 2 "Brain.py (AI)"
lbl 3 "Bridge.js:3000"

# ─── Launch services ─────────────────────────────────────────────────────────
snd() { tmux send-keys -t "$SESSION:$1" "$2" Enter; }

snd "0.0" "echo -e '\033[96m[ gateway.py — port 8000 ]\033[0m' && ${VENV_ACTIVATE}$UVICORN gateway:app --host 0.0.0.0 --port 8000 --log-level info"
snd "0.1" "echo -e '\033[92m[ app.js — port 8080 ]\033[0m' && node app.js"
snd "0.2" "echo -e '\033[95m[ brain.py — AI engine ]\033[0m' && GEMINI_API_KEY=$GEMINI_API_KEY ${VENV_ACTIVATE}$PYTHON brain.py"
snd "0.3" "echo -e '\033[93m[ bridge.js — port 3000 ]\033[0m' && node bridge.js"

# ─── Wait for services ────────────────────────────────────────────────────────
info "Waiting for all services to become healthy…"
echo
sleep 3

wait_for_http() {
    local url="$1" label="$2" max_wait="${3:-45}" elapsed=0
    # bridge.js serves socket.io — accept any HTTP response, not just 2xx
    local curl_flags="-s --max-time 2 --output /dev/null"
    [[ "$label" != *"bridge"* ]] && curl_flags="-sf --max-time 2"
    while ! curl $curl_flags "$url" >/dev/null 2>&1; do
        sleep 1; elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $max_wait ]]; then
            warn "$label did not respond in ${max_wait}s — check its pane for errors."
            return 0
        fi
        echo -ne "\r  ${DIM}Waiting for $label… ${elapsed}s${RESET}   "
    done
    echo -e "\r  "; ok "$label is healthy"
}

wait_for_http "http://127.0.0.1:8080/health" "app.js (8080)"    45
wait_for_http "http://127.0.0.1:8000/health" "gateway (8000)"   60
wait_for_http "http://127.0.0.1:3000/"       "bridge.js (3000)" 45

echo
ok "All services are up! 🎉"
echo

# ─── Open dashboard AFTER bridge.js is confirmed healthy ──────────────────────
# bridge.js serves dashboard.html at http://localhost:3000 — opening only after
# the health check guarantees socket.io is ready when the page loads.
DASH_URL="http://localhost:3000"
info "Opening dashboard: $DASH_URL"
if powershell.exe -Command "Start-Process '$DASH_URL'" 2>/dev/null; then
    ok "Dashboard opened in browser ✓"
elif cmd.exe /c start "" "$DASH_URL" 2>/dev/null; then
    ok "Dashboard opened in browser ✓"
else
    warn "Could not auto-open. Visit manually: ${CYAN}$DASH_URL${RESET}"
fi
echo

# ─── Run simulation in window 1 ───────────────────────────────────────────────
info "Launching attack simulation (Window 1)…"
sleep 1
snd "1" "${VENV_ACTIVATE}$PYTHON simulate_attack.py"

# ─── Attach to window 0 (services view) ──────────────────────────────────────
echo -e "${CYAN}  Attaching to tmux session '${SESSION}'…${RESET}"
echo -e "${DIM}  Ctrl+B 0 = services  │  Ctrl+B 1 = simulation  │  Ctrl+B D = detach${RESET}"
echo
sleep 0.5
tmux attach-session -t "$SESSION:0"
