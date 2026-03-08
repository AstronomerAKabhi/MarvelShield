#!/usr/bin/env bash
# MarvelShield — Stop all services and clean up tmux session
set -euo pipefail

SESSION="marvelshield"

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; RESET='\033[0m'; DIM='\033[2m'
ok()   { echo -e "${GREEN}  ✅  $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠️   $*${RESET}"; }
info() { echo -e "${DIM}  ·  $*${RESET}"; }

echo
echo -e "${RED}  🛑  MarvelShield — Stopping all services${RESET}"
echo

# Kill tmux session (kills all child processes)
if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux kill-session -t "$SESSION"
    ok "tmux session '$SESSION' terminated"
else
    warn "No tmux session '$SESSION' found"
fi

# Kill anything still on our ports
for PORT in 8000 8080 3000; do
    PID=$(lsof -ti :"$PORT" 2>/dev/null || true)
    if [[ -n "$PID" ]]; then
        kill -9 "$PID" 2>/dev/null && info "Killed process on port $PORT (PID $PID)"
    fi
done

# Optionally clear Redis attack data (but keep active_patches for next run)
if redis-cli ping 2>/dev/null | grep -q PONG; then
    redis-cli del current_trace    >/dev/null 2>&1 || true
    redis-cli del bw_flags         >/dev/null 2>&1 || true
    redis-cli del patch_meta       >/dev/null 2>&1 || true
    redis-cli del threat_timeline  >/dev/null 2>&1 || true
    redis-cli del ip_blocklist     >/dev/null 2>&1 || true
    redis-cli del ms:stats         >/dev/null 2>&1 || true
    # Clear attacker profiles and behavioral watcher keys
    redis-cli --scan --pattern 'attacker_profiles:*' | xargs -r redis-cli del >/dev/null 2>&1 || true
    redis-cli --scan --pattern 'bw:*'                | xargs -r redis-cli del >/dev/null 2>&1 || true
    info "Cleared transient Redis keys (current_trace, bw_flags, patch_meta, threat_timeline, ip_blocklist, ms:stats, attacker_profiles, bw:*)"
fi

echo
ok "All clean. Run ./start.sh to restart."
echo
