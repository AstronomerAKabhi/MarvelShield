"""
MarvelShield × OWASP Juice Shop — Attack Simulation
====================================================
Fires real attacks against Juice Shop endpoints through the MarvelShield
gateway so the AI detects, patches, and blocks them live on the dashboard.

Usage:
    python3 juice_attack.py
    python3 juice_attack.py --gateway http://localhost:8000 --timeout 60
"""

import argparse
import json
import sys
import time
import redis
import redis.exceptions
import httpx

# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET = "\033[0m"; BOLD = "\033[1m"; RED = "\033[91m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; CYAN = "\033[96m"; WHITE = "\033[97m"
DIM = "\033[2m"; MAGENTA = "\033[95m"

def c(col, txt): return f"{col}{txt}{RESET}"
def ok(m):   print(c(GREEN,   f"  ✅  {m}"))
def warn(m): print(c(YELLOW,  f"  ⚠️   {m}"))
def err(m):  print(c(RED,     f"  ❌  {m}"))
def info(m): print(c(DIM,     f"      {m}"))

def banner():
    print()
    print(c(CYAN, "╔══════════════════════════════════════════════════════════════╗"))
    print(c(CYAN, "║") + c(BOLD + WHITE, "   🛡  MarvelShield × OWASP Juice Shop — Attack Demo        ") + c(CYAN, "║"))
    print(c(CYAN, "╚══════════════════════════════════════════════════════════════╝"))
    print()

def result_line(status, label, elapsed):
    colour = GREEN if status == 200 else (RED if status == 403 else YELLOW)
    print(c(colour, f"  HTTP {status}") + f"  {label}" + c(DIM, f"  ({elapsed*1000:.0f} ms)"))

# ── Redis helpers ─────────────────────────────────────────────────────────────
ACTIVE_PATCHES_KEY = "active_patches"

def get_redis():
    try:
        r = redis.Redis(host="127.0.0.1", port=6379, db=0,
                        socket_connect_timeout=2, socket_timeout=2)
        r.ping()
        return r
    except redis.exceptions.RedisError as e:
        err(f"Redis unavailable: {e}")
        sys.exit(1)

def wait_for_patch(r, old_count, timeout=60, poll=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            patches = {m.decode() for m in r.smembers(ACTIVE_PATCHES_KEY)}
            if len(patches) > old_count:
                return True, patches
        except redis.exceptions.RedisError:
            pass
        remaining = deadline - time.time()
        bar = int((timeout - remaining) / timeout * 30)
        print(f"\r      [{'█' * bar}{'░' * (30 - bar)}]  waiting for AI patch…  ", end="", flush=True)
        time.sleep(poll)
    print()
    return False, set()

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def send(client, method, url, body=None, params=None):
    try:
        if method == "GET":
            r = client.get(url, params=params, timeout=10.0)
        else:
            r = client.post(url, json=body, timeout=10.0)
        try:    return r.status_code, r.json()
        except: return r.status_code, r.text
    except httpx.ConnectError:
        err(f"Cannot connect to gateway — is it running?")
        sys.exit(1)

# ── Juice Shop attack vectors ─────────────────────────────────────────────────
# Each: (display_name, method, path, body_or_None, query_params_or_None)
JUICE_ATTACKS = [
    (
        "SQL Injection — Login Bypass",
        "POST", "/rest/user/login",
        {"email": "' OR 1=1--", "password": "anything"},
        None,
        "Bypasses authentication — classic OR 1=1 login injection"
    ),
    (
        "XSS — Search Field Injection",
        "GET", "/rest/products/search",
        None,
        {"q": "<iframe src=\"javascript:alert(`xss`)\">"},
        "Reflected XSS in product search — script injection via query param"
    ),
    (
        "Path Traversal — FTP Directory",
        "GET", "/ftp/../../../etc/passwd",
        None,
        None,
        "Attempts to escape FTP directory via dot-dot-slash traversal"
    ),
    (
        "SQL Injection — Product Search",
        "GET", "/rest/products/search",
        None,
        {"q": "'; DROP TABLE Products--"},
        "SQL injection via product search — attempts destructive DROP TABLE"
    ),
    (
        "Sensitive Data Exposure — Admin Endpoint",
        "GET", "/api/Users/",
        None,
        None,
        "Accesses admin-level user endpoint — authorization bypass attempt"
    ),
]

# ── Pre-flight ────────────────────────────────────────────────────────────────
def preflight(gateway, client):
    print(c(BOLD + WHITE, "  Pre-flight checklist"))
    print(c(DIM, "  " + "─" * 52))

    checks = [
        ("Redis",              lambda: __import__("redis").Redis(host="127.0.0.1", port=6379, socket_connect_timeout=2).ping()),
        ("Juice Shop (3001)",  lambda: client.get("http://127.0.0.1:3001", timeout=3)),
        ("Gateway  (8000)",    lambda: client.get(f"{gateway}/health", timeout=3)),
    ]
    failed = []
    for label, check in checks:
        try:
            check()
            print(c(GREEN, "  ✅ ") + f"{label:<22} " + c(GREEN, "OK"))
        except Exception:
            print(c(RED,   "  ❌ ") + f"{label:<22} " + c(RED, "NOT REACHABLE"))
            failed.append(label)
    print()

    if failed:
        err("Start these services first:")
        if "Juice Shop" in str(failed):
            print(c(YELLOW, "    ./juice_setup.sh"))
        if "Gateway" in str(failed):
            print(c(YELLOW, "    uvicorn gateway:app --host 0.0.0.0 --port 8000"))
        sys.exit(1)

    ok("All services up — starting Juice Shop attack simulation.")
    print()

# ── Run one attack ────────────────────────────────────────────────────────────
def run_attack(client, r, gateway, num, name, method, path, body, params, desc, timeout):
    url = f"{gateway}{path}"

    print(c(MAGENTA, f"  ▶  [{num}] {name}"))
    info(desc)
    if body:   info(f"Payload  : {json.dumps(body)}")
    if params: info(f"Params   : {params}")
    print()

    try:
        before = {m.decode() for m in r.smembers(ACTIVE_PATCHES_KEY)}
    except Exception:
        before = set()

    t0 = time.time()
    status, _ = send(client, method, url, body, params)
    elapsed = time.time() - t0
    result_line(status, f"{method} {path}", elapsed)

    if status == 403:
        ok("Already blocked by an existing patch ✅")
        return True, 0.0

    ok("Attack reached Juice Shop — brain.py analysing with Gemini AI…")

    t_attack = time.time()
    patched, after = wait_for_patch(r, len(before), timeout=timeout)
    ttn = time.time() - t_attack if patched else float(timeout)
    added = after - before
    print()

    if not patched:
        err(f"No patch deployed within {timeout}s.")
        return False, ttn

    print(c(MAGENTA, f"  🧠  Patch deployed in {ttn:.1f}s:"))
    for p in added:
        print(c(YELLOW, f"       regex: {p}"))

    # Replay to confirm block
    time.sleep(0.3)
    t0 = time.time()
    status2, _ = send(client, method, url, body, params)
    elapsed2 = time.time() - t0
    result_line(status2, f"REPLAY  {method} {path}", elapsed2)

    if status2 == 403:
        ok(f"BLOCKED ✨  TTN = {ttn:.1f}s")
    else:
        warn(f"Replay got {status2} — patch may need tuning")

    return status2 == 403, ttn

# ── Main ──────────────────────────────────────────────────────────────────────
def run(gateway, timeout):
    banner()
    gateway = gateway.rstrip("/")
    print(c(WHITE, f"  Gateway    : {gateway}"))
    print(c(WHITE, f"  Target     : OWASP Juice Shop (port 3001)"))
    print(c(WHITE, f"  Attacks    : {len(JUICE_ATTACKS)} vectors"))
    print()

    client = httpx.Client()
    preflight(gateway, client)
    r = get_redis()

    # Reset patches for a clean run
    try:
        existing = r.smembers(ACTIVE_PATCHES_KEY)
        if existing:
            warn(f"{len(existing)} stale patch(es) cleared for clean demo.")
        pipe = r.pipeline()
        pipe.delete(ACTIVE_PATCHES_KEY)
        pipe.delete("patch_meta")
        pipe.delete("threat_timeline")
        pipe.delete("ip_blocklist")
        pipe.delete("ms:stats")
        pipe.execute()
        ok("Environment reset — clean slate.")
    except Exception:
        pass
    print()

    results = []
    for i, (name, method, path, body, params, desc) in enumerate(JUICE_ATTACKS, 1):
        print()
        print(c(CYAN, f"─── Attack {i}/{len(JUICE_ATTACKS)}: {name} " + "─" * max(0, 40 - len(name))))
        blocked, ttn = run_attack(client, r, gateway, i, name, method, path, body, params, desc, timeout)
        results.append((name, blocked, ttn))
        time.sleep(0.5)

    # Summary
    print()
    print(c(CYAN, "═" * 64))
    print(c(BOLD + WHITE, "  JUICE SHOP DEMO COMPLETE"))
    print(c(CYAN, "═" * 64))
    print()
    all_ok = True
    for name, blocked, ttn in results:
        icon    = c(GREEN, "  ✅  BLOCKED") if blocked else c(RED, "  ❌  MISSED ")
        ttn_str = f"TTN {ttn:.1f}s" if ttn > 0 else "pre-patched"
        print(f"{icon}  {name:<40} {c(DIM, ttn_str)}")
        if not blocked:
            all_ok = False
    print()
    if all_ok:
        ok("MarvelShield blocked all Juice Shop attacks in real-time!")
    else:
        warn("Some attacks were not blocked — check brain.py logs.")

    try:
        final = r.smembers(ACTIVE_PATCHES_KEY)
        print(c(DIM, f"\n  Active patches now in Redis: {len(final)}"))
        for p in sorted(m.decode() for m in final):
            print(c(DIM, f"    • {p}"))
    except Exception:
        pass
    print()
    client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MarvelShield × Juice Shop attack demo")
    parser.add_argument("--gateway", default="http://localhost:8000")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    try:
        run(args.gateway, args.timeout)
    except KeyboardInterrupt:
        print(); warn("Interrupted."); sys.exit(0)
