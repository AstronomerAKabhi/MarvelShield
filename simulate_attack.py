"""
MarvelShield — One-Click Attack Simulation
==========================================
Runs a fully automated demo that walks through the entire self-healing pipeline:

  Step 1 — Clean baseline request          (expect 200)
  Step 2 — Multi-vector attack cycle       (4 attack types, each generates its own patch)
            • Command Injection  POST /api/execute  {"cmd": "ls; cat /etc/passwd"}
            • SSRF               POST /api/execute  {"url": "http://169.254.169.254/metadata"}
            • Path Traversal     GET  /api/execute/../../../../etc/passwd
            • SQL Injection      POST /api/execute  {"id": "1; DROP TABLE users--"}
  Step 3 — Summary

Usage:
    python3 simulate_attack.py
    python3 simulate_attack.py --gateway http://localhost:8000 --timeout 60
"""

import argparse
import json
import sys
import time
import redis
import redis.exceptions
import httpx

# ---------------------------------------------------------------------------
# ANSI colour helpers  (no external deps — works in any terminal)
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
MAGENTA = "\033[95m"

def c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"

def banner() -> None:
    print()
    print(c(CYAN, "╔══════════════════════════════════════════════════════════════╗"))
    print(c(CYAN, "║") + c(BOLD + WHITE, "        🛡  MarvelShield — Multi-Vector Attack Simulation      ") + c(CYAN, "║"))
    print(c(CYAN, "╚══════════════════════════════════════════════════════════════╝"))
    print()

def step(n: int, title: str) -> None:
    print()
    print(c(CYAN, f"─── Step {n}: {title} ") + c(DIM, "─" * (50 - len(title))))

def ok(msg: str)   -> None: print(c(GREEN,   f"  ✅  {msg}"))
def warn(msg: str) -> None: print(c(YELLOW,  f"  ⚠️   {msg}"))
def err(msg: str)  -> None: print(c(RED,     f"  ❌  {msg}"))
def info(msg: str) -> None: print(c(DIM,     f"      {msg}"))

def result_line(status: int, label: str, elapsed: float) -> None:
    colour = GREEN if status == 200 else (RED if status == 403 else YELLOW)
    print(c(colour, f"  HTTP {status}") + f"  {label}" + c(DIM, f"  ({elapsed*1000:.0f} ms)"))

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def send(client: httpx.Client, method: str, url: str,
         body: dict | None = None) -> tuple[int, dict | str]:
    """Send a request and return (status_code, parsed_body)."""
    try:
        if method == "GET":
            r = client.get(url, timeout=10.0)
        else:
            r = client.post(url, json=body, timeout=10.0)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except httpx.ConnectError:
        err(f"Cannot connect to {url} — is the gateway running?")
        sys.exit(1)
    except httpx.TimeoutException:
        err(f"Request timed out ({url})")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

ACTIVE_PATCHES_KEY = "active_patches"

def get_redis(host: str = "127.0.0.1", port: int = 6379) -> redis.Redis:
    try:
        r: redis.Redis = redis.Redis(  # type: ignore[assignment]
            host=host, port=port, db=0,
            socket_connect_timeout=2, socket_timeout=2,
        )
        r.ping()
        return r
    except redis.exceptions.RedisError as e:
        err(f"Redis unavailable ({host}:{port}): {e}")
        sys.exit(1)


def wait_for_patch(r: redis.Redis, old_count: int, timeout: float, poll: float = 1.0) -> tuple[bool, float, set[str]]:
    """
    Poll active_patches until its cardinality grows (new patch deployed).

    Returns:
        (patched, elapsed_seconds, patches_set)
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw: set[bytes] = r.smembers(ACTIVE_PATCHES_KEY)  # type: ignore[assignment]
            patches = {m.decode() for m in raw}
            if len(patches) > old_count:
                return True, time.time(), patches
        except redis.exceptions.RedisError:
            pass
        remaining = deadline - time.time()
        bar = int((timeout - remaining) / timeout * 30)
        print(f"\r      [{'█' * bar}{'░' * (30 - bar)}]  waiting for AI patch…  ", end="", flush=True)
        time.sleep(poll)
    print()
    return False, time.time(), set()


# ---------------------------------------------------------------------------
# Attack vector definitions
# ---------------------------------------------------------------------------
# Each vector: (display_name, method, path_suffix, payload, variants)
# variants: list of (label, method, path_suffix, payload)
# ---------------------------------------------------------------------------

ATTACK_VECTORS = [
    (
        "Command Injection",
        "POST", "/api/execute", {"cmd": "ls; cat /etc/passwd"},
        [
            ("pipe",       "POST", "/api/execute", {"cmd": "ls | cat /etc/shadow"}),
            ("backtick",   "POST", "/api/execute", {"cmd": "echo `whoami`"}),
            ("&&",         "POST", "/api/execute", {"cmd": "ls && id"}),
            ("subshell",   "POST", "/api/execute", {"cmd": "$(id)"}),
        ],
    ),
    (
        "SSRF — cloud metadata fishing",
        "POST", "/api/execute", {"url": "http://169.254.169.254/metadata"},
        [
            ("internal admin",  "POST", "/api/execute", {"url": "http://localhost/admin"}),
            ("file read",       "POST", "/api/execute", {"url": "file:///etc/passwd"}),
            ("AWS metadata",    "POST", "/api/execute", {"url": "http://169.254.169.254/latest/meta-data/iam"}),
        ],
    ),
    (
        "Path Traversal",
        "GET", "/api/execute/../../../../etc/passwd", None,
        [
            ("windows style",  "GET",  "/api/execute/..%5C..%5C..%5Cwindows%5Csystem32", None),
            ("encoded dots",   "GET",  "/api/execute/%2e%2e/%2e%2e/etc/shadow",          None),
            ("safe path",      "GET",  "/api/execute/reports/summary",                   None),
        ],
    ),
    (
        "SQL Injection",
        "POST", "/api/execute", {"id": "1; DROP TABLE users--"},
        [
            ("UNION select",   "POST", "/api/execute", {"id": "1 UNION SELECT * FROM secrets"}),
            ("OR 1=1",         "POST", "/api/execute", {"id": "' OR '1'='1"}),
            ("comment bypass", "POST", "/api/execute", {"id": "admin'--"}),
        ],
    ),
]

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def check_http(url: str, label: str, client: httpx.Client) -> bool:
    """Return True if the service responds (any HTTP status counts as alive)."""
    try:
        client.get(url, timeout=2.0)
        return True
    except Exception:
        return False


def _check_redis_silent() -> bool:
    try:
        tmp = redis.Redis(host="127.0.0.1", port=6379, db=0,
                          socket_connect_timeout=2, socket_timeout=2)
        tmp.ping()
        return True
    except Exception:
        return False


def _check_brain_redis() -> bool:
    """
    brain.py has no HTTP port — detect it via the 'brain:alive' heartbeat key
    it writes to Redis every poll cycle (30 s TTL).  Falls back to checking for
    existing trace:* keys or active_patches so demos still pass after the first run.
    """
    try:
        tmp = redis.Redis(host="127.0.0.1", port=6379, db=0,
                          socket_connect_timeout=2, socket_timeout=2)
        if tmp.exists("brain:alive"):
            return True
        has_patches = tmp.exists(ACTIVE_PATCHES_KEY)
        cursor, keys = tmp.scan(0, match="trace:*", count=5)  # type: ignore[misc]
        return bool(has_patches or keys)
    except Exception:
        return False


def preflight(gateway: str, client: httpx.Client) -> None:
    target = gateway.rstrip("/")

    print(c(BOLD + WHITE, "  Pre-flight checklist"))
    print(c(DIM, "  " + "─" * 52))

    services = [
        ("Redis",          lambda: _check_redis_silent()),
        ("app.js  (8080)", lambda: check_http("http://127.0.0.1:8080/health", "app.js", client)),
        ("gateway (8000)", lambda: check_http(f"{target}/health", "gateway", client)),
        ("brain.py",       lambda: _check_brain_redis()),
    ]

    failed = []
    for label, check in services:
        alive = check()
        icon  = c(GREEN, "  ✅ ") if alive else c(RED, "  ❌ ")
        status_str = c(GREEN, "OK") if alive else c(RED, "NOT REACHABLE")
        print(f"{icon} {label:<20} {status_str}")
        if not alive:
            failed.append(label)

    print()

    if failed:
        err("Some services are not running.  Start them before re-running the script:")
        print()
        if "brain.py" in failed:
            print(c(YELLOW, "    GEMINI_API_KEY=<your-key> python3 brain.py"))
        if any("gateway" in f for f in failed):
            print(c(YELLOW, "    uvicorn gateway:app --port 8000"))
        if any("app.js" in f for f in failed):
            print(c(YELLOW, "    node app.js"))
        print()
        warn("Optional but recommended:  node bridge.js   (port 3000 — live dashboard)")
        sys.exit(1)

    ok("All services up — starting simulation.")
    print()


# ---------------------------------------------------------------------------
# Single attack-vector cycle
# ---------------------------------------------------------------------------

def run_vector(
    client: httpx.Client,
    r: redis.Redis,
    target: str,
    vec_num: int,
    name: str,
    method: str,
    path: str,
    payload: dict | None,
    variants: list,
    patch_timeout: int,
) -> tuple[bool, float, set[str], set[str]]:
    """
    Run one full attack/patch/verify cycle for a single vector.
    Returns (blocked, ttn_seconds, all_patches, added_patches).
    """
    url = f"{target}{path}"
    payload_str = json.dumps(payload) if payload else f"GET {path}"

    # ── Attack ────────────────────────────────────────────────────────────────
    print()
    print(c(MAGENTA, f"  ▶  [{vec_num}] {name}"))
    info(f"Payload: {payload_str}")
    print()

    # Snapshot current patch count before attack
    try:
        raw: set[bytes] = r.smembers(ACTIVE_PATCHES_KEY)  # type: ignore[assignment]
        before = {m.decode() for m in raw}
    except redis.exceptions.RedisError:
        before = set()
    before_count = len(before)

    t0 = time.time()
    status, _ = send(client, method, url, payload)
    elapsed = time.time() - t0
    result_line(status, f"{method} {path}  {payload_str}", elapsed)

    already_patched = status == 403

    if already_patched:
        ok("Already blocked by an existing patch — skipping wait.")
        try:
            raw2: set[bytes] = r.smembers(ACTIVE_PATCHES_KEY)  # type: ignore[assignment]
            after = {m.decode() for m in raw2}
        except redis.exceptions.RedisError:
            after = before
        return True, 0.0, after, set()

    ok(f"Attack reached backend — brain.py analysing…")

    # ── Wait for patch ────────────────────────────────────────────────────────
    t_attack = time.time()
    patched, t_patched, after = wait_for_patch(r, before_count, timeout=patch_timeout)
    ttn = t_patched - t_attack if patched else float(patch_timeout)
    added = after - before
    print()

    if not patched:
        err(f"No patch deployed within {patch_timeout}s for {name}.")
        return False, ttn, after, added

    print(c(MAGENTA, f"  🧠  Patch deployed in {ttn:.1f}s:"))
    for p in added:
        print(c(YELLOW, f"       regex: {p}"))

    # ── Replay (expect 403) ───────────────────────────────────────────────────
    time.sleep(0.3)
    t0 = time.time()
    status2, _ = send(client, method, url, payload)
    elapsed2 = time.time() - t0
    result_line(status2, f"REPLAY  {method} {path}", elapsed2)

    if status2 == 403:
        ok(f"BLOCKED ✨  TTN = {ttn:.1f}s")
    else:
        err(f"Expected 403 but got {status2} — patch may be too narrow.")

    # ── Variants ──────────────────────────────────────────────────────────────
    if variants:
        print(c(DIM, "      Variant tests:"))
        for vlabel, vmethod, vpath, vpayload in variants:
            vurl = f"{target}{vpath}"
            t0 = time.time()
            vs, _ = send(client, vmethod, vurl, vpayload)
            el = time.time() - t0
            vpayload_str = json.dumps(vpayload) if vpayload else f"GET {vpath}"
            icon   = "🛡️  BLOCKED" if vs == 403 else "⚠️  ALLOWED"
            colour = GREEN if vs == 403 else YELLOW
            print(c(colour, f"        {icon}") + c(DIM, f"  ({el*1000:.0f} ms)  ") + vlabel)
            info(f"         {vpayload_str}")

    return status2 == 403, ttn, after, added


# ---------------------------------------------------------------------------
# Main simulation
# ---------------------------------------------------------------------------

def run(gateway: str, patch_timeout: int) -> None:
    banner()

    target = gateway.rstrip("/")
    execute_url = f"{target}/api/execute"

    print(c(WHITE, f"  Gateway  : {target}"))
    print(c(WHITE, f"  Vectors  : Command Injection · SSRF · Path Traversal · SQL Injection"))
    print()

    client = httpx.Client()
    preflight(gateway, client)

    r = get_redis()

    # Flush stale patches, IP bans, and counters for a clean demo run
    try:
        existing: set[bytes] = r.smembers(ACTIVE_PATCHES_KEY)  # type: ignore[assignment]
        if existing:
            warn(f"{len(existing)} existing patch(es) found — flushing for clean demo.")
        # Count banned IPs before clearing
        banned: set[bytes] = r.smembers("ip_blocklist")  # type: ignore[assignment]
        if banned:
            warn(f"{len(banned)} banned IP(s) cleared so simulation can run fresh: {', '.join(b.decode() for b in banned)}")
        pipe = r.pipeline()
        pipe.delete(ACTIVE_PATCHES_KEY)   # remove active regex set
        pipe.delete("patch_meta")         # remove metadata hash
        pipe.delete("threat_timeline")    # clear persisted event history
        pipe.delete("ip_blocklist")       # unban all IPs — essential for fresh demo
        pipe.delete("ms:stats")           # reset gateway stat counters
        # Clear attacker_profiles:{ip} and bw:{...} keys via SCAN
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="attacker_profiles:*", count=100)  # type: ignore[misc]
            if keys:
                pipe.delete(*keys)
            if cursor == 0:
                break
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="bw:*", count=100)   # type: ignore[misc]
            if keys:
                pipe.delete(*keys)
            if cursor == 0:
                break
        pipe.execute()
        ok("Environment reset — ready for clean simulation.")
    except redis.exceptions.RedisError:
        pass

    # ── Step 1: Clean baseline ─────────────────────────────────────────────
    step(1, "Clean baseline request")
    t0 = time.time()
    status, _ = send(client, "POST", execute_url, {"cmd": "echo hello"})
    elapsed = time.time() - t0
    result_line(status, "POST /api/execute  {\"cmd\": \"echo hello\"}", elapsed)
    if status == 200:
        ok("Clean request allowed through — pipeline is live.")
    elif status == 403:
        warn("Got 403 on a clean request — a stale patch may be too broad.")
    else:
        warn(f"Unexpected status {status}.")

    # ── Step 2: Multi-vector attack cycles ────────────────────────────────
    step(2, "Multi-vector attack cycle")

    results: list[tuple[str, bool, float]] = []

    for i, (name, method, path, payload, variants) in enumerate(ATTACK_VECTORS, start=1):
        blocked, ttn, _, _ = run_vector(
            client, r, target, i, name, method, path, payload, variants, patch_timeout
        )
        results.append((name, blocked, ttn))
        time.sleep(0.5)  # brief pause between vectors

    # ── Step 3: Summary ───────────────────────────────────────────────────
    step(3, "Summary")
    print()
    print(c(CYAN, "═" * 64))
    print(c(BOLD + WHITE, "  SIMULATION COMPLETE — Multi-Vector Results"))
    print(c(CYAN, "═" * 64))
    print()

    all_blocked = True
    for name, blocked, ttn in results:
        icon   = c(GREEN, "  ✅  BLOCKED") if blocked else c(RED, "  ❌  MISSED ")
        ttn_str = f"TTN {ttn:.1f}s" if ttn > 0 else "pre-patched"
        print(f"{icon}  {name:<35} {c(DIM, ttn_str)}")
        if not blocked:
            all_blocked = False

    print()
    if all_blocked:
        ok("All 4 attack vectors detected and neutralized — system is generalised!")
    else:
        warn("Some vectors were not blocked — check brain.py logs for details.")

    try:
        final: set[bytes] = r.smembers(ACTIVE_PATCHES_KEY)  # type: ignore[assignment]
        print()
        print(c(DIM, f"  Active patches in Redis: {len(final)}"))
        for p in sorted(m.decode() for m in final):
            print(c(DIM, f"    • {p}"))
    except redis.exceptions.RedisError:
        pass

    print()
    client.close()


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MarvelShield multi-vector attack simulation"
    )
    parser.add_argument(
        "--gateway",
        default="http://localhost:8000",
        help="Gateway base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Max seconds to wait for patch deployment per vector (default: 60)",
    )
    args = parser.parse_args()

    try:
        run(gateway=args.gateway, patch_timeout=args.timeout)
    except KeyboardInterrupt:
        print()
        warn("Simulation interrupted by user.")
        sys.exit(0)


