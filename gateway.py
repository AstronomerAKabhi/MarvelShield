from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
import asyncio
import httpx
import re
import uuid
import redis
import redis.exceptions
import json
import logging
import time
import uvicorn
import os
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gateway")

# ---------------------------------------------------------------------------
# Behavioral Watcher — Sliding-Window Rate Monitor
# ---------------------------------------------------------------------------
# Uses a Redis sorted set per IP ("bw:<ip>") where each member is a unique
# request key and the score is the Unix timestamp (float).
# On every request we:
#   1. Add the current request (score = now)
#   2. Remove entries older than the window
#   3. Count what remains
# If count > RATE_LIMIT the Trace ID is flagged in a Redis list ("bw_flags")
# and a warning is logged.  The request is still forwarded so the watcher
# stays passive / non-blocking — easy to promote to a blocker later.
# ---------------------------------------------------------------------------

RATE_LIMIT   = 10          # maximum requests allowed …
RATE_WINDOW  = 5.0         # … within this many seconds (sliding window)
BW_KEY_TTL   = 10          # Redis key TTL (seconds) — auto-cleanup after inactivity


class BehavioralWatcher:
    """Passive sliding-window rate watcher.  Thread-safe via Redis atomics."""

    def __init__(self, redis_client: redis.Redis,
                 limit: int = RATE_LIMIT,
                 window: float = RATE_WINDOW):
        self.r      = redis_client
        self.limit  = limit
        self.window = window

    def check(self, ip: str, trace_id: str) -> bool:
        """
        Record this request from *ip* and return True if the IP has exceeded
        the rate limit (i.e. should be flagged).  Never raises — fails open so
        a Redis outage does not block traffic.
        """
        try:
            now       = time.time()
            cutoff    = now - self.window
            redis_key = f"bw:{ip}"

            pipe = self.r.pipeline()
            # Add current request; member is "<trace_id>:<now>" for uniqueness
            pipe.zadd(redis_key, {f"{trace_id}:{now}": now})
            # Evict entries outside the sliding window
            pipe.zremrangebyscore(redis_key, "-inf", cutoff)
            # Count remaining entries (requests inside the window)
            pipe.zcard(redis_key)
            # Reset TTL so idle keys expire automatically
            pipe.expire(redis_key, BW_KEY_TTL)
            results = pipe.execute()

            request_count = results[2]   # result of ZCARD

            if request_count > self.limit:
                flag_data = {
                    "trace_id":      trace_id,
                    "ip":            ip,
                    "request_count": request_count,
                    "window_sec":    self.window,
                    "flagged_at":    now,
                }
                self.r.lpush("bw_flags", json.dumps(flag_data))
                logger.warning(
                    f"[BehavioralWatcher] FLAGGED trace_id={trace_id} | "
                    f"ip={ip} | {request_count} requests in {self.window}s"
                )
                return True

            return False

        except (redis.exceptions.ConnectionError,
                redis.exceptions.TimeoutError) as e:
            logger.warning(f"[BehavioralWatcher] Redis unavailable — skipping check: {e}")
            return False   # fail open


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: verify Redis is reachable
    try:
        r.ping()
        logger.info("Redis connection OK (127.0.0.1:6379)")
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
        logger.warning(f"Redis unavailable at startup — request logging disabled: {e}")
    yield

app = FastAPI(lifespan=lifespan)

# Connect to local Redis instance — 127.0.0.1 avoids WSL2 DNS resolution
# delays that 'localhost' can trigger. Short timeouts ensure a Redis outage
# causes an immediate fail-open rather than blocking the request pipeline.
r = redis.Redis(host='127.0.0.1', port=6379, db=0,
                socket_connect_timeout=1, socket_timeout=1)

watcher = BehavioralWatcher(r)

TARGET_URL = os.getenv("TARGET_APP", "http://127.0.0.1:8080").rstrip("/")
logger.info("MarvelShield proxying to: %s", TARGET_URL)

# Management API paths — bypass all security checks (IP-ban, logging, patching).
# These are internal endpoints consumed by the extension and export tools;
# they must never be analysed or blocked by the WAF itself.
MANAGEMENT_PATHS = frozenset({
    "/health", "/api/patches", "/api/stats",
})

# Redis HASH key for persistent gateway stat counters (survives process restarts).
MS_STATS_KEY = "ms:stats"

# Shared hash-key prefix — must match loader.py so both processes write into
# the same Redis hash for a given Trace-ID:  trace:<uuid>
TRACE_KEY_PREFIX = "trace:"

# Key written by brain.py — set of compiled regex patterns that block requests
ACTIVE_PATCHES_KEY = "active_patches"

# Hash: regex → JSON metadata (attack_type, severity, confidence, reasoning…)
PATCH_META_KEY = "patch_meta"

# SET of permanently banned IPs (written by brain.py after BAN_THRESHOLD attacks)
IP_BLOCKLIST_KEY = "ip_blocklist"

# Channel consumed by bridge.js → frontend clients
SECURITY_EVENTS_CHANNEL = "security_events"

_BLOCK_RESPONSE_BODY = json.dumps({
    "detail": "MarvelShield: This attack has been neutralized by a self-healing virtual patch."
})


# ---------------------------------------------------------------------------
# WAF rule exporters
# ---------------------------------------------------------------------------

def _load_patch_meta() -> list[dict]:
    """
    Return a list of patch metadata dicts from Redis.
    Each dict is guaranteed to have at least 'regex_patch' and 'attack_type'.
    Falls back to regex-only entries when no metadata is stored.
    """
    try:
        raw_patches: set[bytes] = r.smembers(ACTIVE_PATCHES_KEY)  # type: ignore[assignment]
        if not raw_patches:
            return []
        meta_raw: dict[bytes, bytes] = r.hgetall(PATCH_META_KEY)  # type: ignore[assignment]
        result: list[dict] = []
        for raw in raw_patches:
            regex = raw.decode("utf-8")
            meta_bytes = meta_raw.get(raw) or meta_raw.get(regex.encode())
            if meta_bytes:
                try:
                    meta = json.loads(meta_bytes)
                    result.append(meta)
                    continue
                except (json.JSONDecodeError, AttributeError):
                    pass
            # No metadata stored — create a minimal entry
            result.append({"regex_patch": regex, "attack_type": "Unknown",
                            "severity": "UNKNOWN", "confidence": 1.0,
                            "cve_reference": "", "reasoning": ""})
        return result
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        return []


def _safe_metric_name(attack_type: str, idx: int) -> str:
    """Convert an attack_type string to a valid AWS CloudWatch metric name."""
    name = re.sub(r"[^A-Za-z0-9]", "", attack_type.title().replace(" ", ""))
    return f"MarvelShield{name or 'Patch'}{idx}"


def export_nginx(patches: list[dict]) -> str:
    lines = [
        "# ── MarvelShield — Auto-generated Nginx WAF rules ──────────────────",
        f"# Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"# Active patches: {len(patches)}",
        "# Place inside your Nginx server {} or location {} block.",
        "",
    ]
    for meta in patches:
        regex   = meta.get("regex_patch", "")
        atype   = meta.get("attack_type", "Unknown")
        conf    = meta.get("confidence", 1.0)
        cve     = meta.get("cve_reference", "")
        escaped = regex.replace("\\", "\\\\").replace('"', '\\"')
        lines += [
            f"# {atype}{' · ' + cve if cve else ''} (confidence: {float(conf):.0%})",
            f'if ($request_body ~* "{escaped}") {{',
            '    return 403 \'{"detail":"Blocked by MarvelShield virtual patch"}\';',
            "}",
            f'if ($request_uri ~* "{escaped}") {{',
            '    return 403 \'{"detail":"Blocked by MarvelShield virtual patch"}\';',
            "}",
            "",
        ]
    return "\n".join(lines)


def export_modsecurity(patches: list[dict]) -> str:
    lines = [
        "# ── MarvelShield — Auto-generated ModSecurity rules ────────────────",
        f"# Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"# Active patches: {len(patches)}",
        "# Compatible with ModSecurity v2/v3 and OWASP CRS.",
        "",
        'SecRuleEngine On',
        "",
    ]
    base_id = 9001  # high base to avoid CRS collisions
    for i, meta in enumerate(patches):
        regex  = meta.get("regex_patch", "")
        atype  = meta.get("attack_type", "Unknown")
        conf   = meta.get("confidence", 1.0)
        cve    = meta.get("cve_reference", "")
        tag    = atype.upper().replace(" ", "_")
        msg    = f"MarvelShield: {atype} blocked (confidence: {float(conf):.0%})"
        rule_id = base_id + i
        lines += [
            f"# {atype}{' · ' + cve if cve else ''}",
            f'SecRule REQUEST_BODY|ARGS|REQUEST_URI "@rx {regex}" \\',
            f'    "id:{rule_id},\\',
            f"    phase:2,\\",
            f"    deny,\\",
            f"    status:403,\\",
            f"    log,\\",
            f'    msg:\\"{msg}\\",\\',
            f'    tag:\\"{tag}\\",\\',
            f'    tag:\\"MarvelShield\\",\\',
            f'    rev:1,\\',
            f'    ver:\\"MarvelShield/1.0\\"',
            f'    "',
            "",
        ]
    return "\n".join(lines)


def export_aws_waf(patches: list[dict]) -> dict:
    rules = []
    for i, meta in enumerate(patches, start=1):
        regex  = meta.get("regex_patch", "")
        atype  = meta.get("attack_type", "Unknown")
        conf   = meta.get("confidence", 1.0)
        metric = _safe_metric_name(atype, i)
        rules.append({
            "Name":     metric,
            "Priority": i,
            "Action":   {"Block": {}},
            "Statement": {
                "OrStatement": {
                    "Statements": [
                        {
                            "RegexMatchStatement": {
                                "RegexString": regex,
                                "FieldToMatch": {"Body": {"OversizeHandling": "CONTINUE"}},
                                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                            }
                        },
                        {
                            "RegexMatchStatement": {
                                "RegexString": regex,
                                "FieldToMatch": {"UriPath": {}},
                                "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}],
                            }
                        },
                    ]
                }
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled":    True,
                "CloudWatchMetricsEnabled":  True,
                "MetricName":                metric,
            },
            "_marvelshield_meta": {
                "attack_type": atype,
                "confidence":  float(conf),
                "cve":         meta.get("cve_reference", ""),
                "reasoning":   meta.get("reasoning", ""),
            },
        })
    return {
        "Name":        "MarvelShieldAutoPatches",
        "Scope":       "REGIONAL",
        "Description": (
            f"Auto-generated by MarvelShield AI gateway — "
            f"{len(patches)} active virtual patch(es). "
            f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
        ),
        "DefaultAction": {"Allow": {}},
        "Rules":       rules,
        "VisibilityConfig": {
            "SampledRequestsEnabled":   True,
            "CloudWatchMetricsEnabled": True,
            "MetricName":               "MarvelShieldRuleGroup",
        },
    }


# ---------------------------------------------------------------------------
# Browser-extension endpoint
# ---------------------------------------------------------------------------

@app.get("/api/patches")
async def api_patches():
    """
    Return active patches in a simple JSON format consumed by the
    MarvelShield browser extension.

    Response shape:
      {
        "gateway_status": "running",
        "generated_at":   "<ISO-8601>",
        "patches": [
          {
            "regex":         "...",
            "attack_type":   "Command Injection",
            "severity":      "CRITICAL",
            "confidence":    0.95,
            "cve_reference": "CWE-78",
            "reasoning":     "..."
          }
        ],
        "ip_blocklist": ["192.168.1.100", ...]
      }
    """
    patches = _load_patch_meta()
    try:
        raw_blocklist: set[bytes] = r.smembers(IP_BLOCKLIST_KEY)  # type: ignore[assignment]
        ip_blocklist = [ip.decode("utf-8") for ip in raw_blocklist]
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        ip_blocklist = []

    return JSONResponse(
        content={
            "gateway_status": "running",
            "generated_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "patches": [
                {
                    "regex":         p.get("regex_patch", ""),
                    "attack_type":   p.get("attack_type", "Unknown"),
                    "severity":      p.get("severity", "UNKNOWN"),
                    "confidence":    float(p.get("confidence", 1.0)),
                    "cve_reference": p.get("cve_reference", ""),
                    "reasoning":     p.get("reasoning", ""),
                }
                for p in patches
            ],
            "ip_blocklist": ip_blocklist,
        },
        headers={"Access-Control-Allow-Origin": "*"},
    )


@app.get("/api/stats")
async def api_stats():
    """
    Return live gateway statistics for the browser extension.

    Reads persistent Redis counters written by the middleware and live set
    sizes so the extension popup can display real gateway-level data without
    subscribing to the Socket.IO event stream.
    """
    try:
        pipe = r.pipeline()
        pipe.hgetall(MS_STATS_KEY)
        pipe.scard(ACTIVE_PATCHES_KEY)
        pipe.scard(IP_BLOCKLIST_KEY)
        raw_counters, patch_count, banned_count = pipe.execute()
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        raw_counters, patch_count, banned_count = {}, 0, 0

    counters: dict = raw_counters or {}
    return JSONResponse(
        content={
            "gateway_status": "running",
            "generated_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_requests": int(counters.get(b"total_requests", 0)),
            "blocked_count":  int(counters.get(b"blocked_count",  0)),
            "active_patches": patch_count,
            "banned_ips":     banned_count,
        },
        headers={"Access-Control-Allow-Origin": "*"},
    )


# ---------------------------------------------------------------------------
# Export endpoint
# ---------------------------------------------------------------------------

@app.get("/patches/export")
async def patches_export(format: str | None = None):
    """
    Export active AI-generated patches as production-ready WAF rules.

    Query params:
      ?format=nginx        → Nginx location-block deny rules (text/plain)
      ?format=modsecurity  → ModSecurity SecRule directives  (text/plain)
      ?format=aws_waf      → AWS WAF v2 rule group JSON      (application/json)
      (no format param)    → all three in a single JSON object
    """
    patches = _load_patch_meta()

    if format == "nginx":
        return Response(
            content=export_nginx(patches),
            media_type="text/plain",
            headers={"Content-Disposition": 'attachment; filename="marvelshield_nginx.conf"'},
        )

    if format == "modsecurity":
        return Response(
            content=export_modsecurity(patches),
            media_type="text/plain",
            headers={"Content-Disposition": 'attachment; filename="marvelshield_modsec.conf"'},
        )

    if format == "aws_waf":
        return Response(
            content=json.dumps(export_aws_waf(patches), indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="marvelshield_aws_waf.json"'},
        )

    # Default: return all three plus a summary
    return {
        "patch_count":       len(patches),
        "generated_at":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "nginx_rules":       export_nginx(patches),
        "modsecurity_rules": export_modsecurity(patches),
        "aws_waf":           export_aws_waf(patches),
    }


def fetch_active_patches() -> list[re.Pattern[str]]:
    """
    Fetch all regex strings from the Redis set 'active_patches' and return
    them as compiled Pattern objects.  Returns an empty list if Redis is
    unavailable or the set is empty — always fails open.
    """
    try:
        raw_patches: set[bytes] = r.smembers(ACTIVE_PATCHES_KEY)  # type: ignore[assignment]
        compiled: list[re.Pattern[str]] = []
        for raw in raw_patches:
            try:
                compiled.append(re.compile(raw.decode("utf-8")))
            except re.error as e:
                logger.warning(f"[SelfHeal] Invalid regex in active_patches, skipping: {e}")
        return compiled
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
        logger.warning(f"[SelfHeal] Could not fetch active_patches from Redis: {e}")
        return []


@app.middleware("http")
async def marvel_shield_interceptor(request: Request, call_next):
    # ── Management & health endpoints ──────────────────────────────────────────
    # These internal APIs must never be IP-banned, logged, or patch-enforced.
    # Call FastAPI's own route handler directly and return.
    if request.url.path in MANAGEMENT_PATHS or request.url.path.startswith("/patches/"):
        return await call_next(request)

    # 1. Generate a Trace ID to link API logs with system events
    trace_id = str(uuid.uuid4())

    # 2. Resolve client IP (honour X-Forwarded-For when behind a load balancer)
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )

    # FP-Test bypass — brain.py sends probes with this header after every patch.
    # We still enforce active patches (that's the test!) but skip Redis logging
    # and all event publishing so the probes are never re-analysed by brain.py
    # and don't appear in the dashboard event feed.
    is_fp_test = request.headers.get("x-fp-test") == "1"

    # Increment the persistent total-request counter (best-effort).
    if not is_fp_test:
        try:
            r.hincrby(MS_STATS_KEY, "total_requests", 1)
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
            pass

    # 3. IP Blocklist check — permanently banned attackers are stopped here,
    # before any further processing.  Fail open if Redis is unavailable.
    try:
        if r.sismember(IP_BLOCKLIST_KEY, client_ip):
            logger.warning(
                f"[Fingerprint] BANNED IP {client_ip} blocked instantly "
                f"(trace_id={trace_id}, path={request.url.path})"
            )
            if not is_fp_test:
                try:
                    r.hincrby(MS_STATS_KEY, "blocked_count", 1)
                    r.publish(SECURITY_EVENTS_CHANNEL, json.dumps({
                        "type":       "blocked",
                        "reason":     "ip_banned",
                        "trace_id":   trace_id,
                        "method":     request.method,
                        "path":       request.url.path,
                        "client_ip":  client_ip,
                        "timestamp":  time.time(),
                    }))
                except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
                    pass
            return Response(
                content=json.dumps({
                    "detail": (
                        "MarvelShield: Your IP has been permanently banned "
                        "after repeated attack attempts."
                    )
                }),
                status_code=403,
                headers={"content-type": "application/json"},
            )
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        pass  # fail open — a Redis outage should never block legitimate traffic

    # 4. Behavioral Watcher — flag if IP exceeds rate threshold
    if not is_fp_test:
        watcher.check(client_ip, trace_id)

    # 5. Capture Request "Symptoms"
    body = await request.body()

    # 5. Store full request details in a Redis hash keyed by Trace-ID.
    # Each field is stored individually so callers can HGET a single field
    # without deserialising the whole entry. Headers are JSON-encoded since
    # Redis hash values must be strings. The key expires after 60 seconds.
    # Failing silently if Redis is absent (to allow proxy core function to run)
    # FP-test probes skip this block entirely — they must not be re-analysed.
    if not is_fp_test:
        try:
            hash_key = f"{TRACE_KEY_PREFIX}{trace_id}"
            pipe = r.pipeline()
            pipe.hset(hash_key, mapping={
                "method":    request.method,
                "path":      request.url.path,
                "headers":   json.dumps(dict(request.headers)),
                "body":      body.decode("utf-8", errors="ignore") if body else "",
                "client_ip": client_ip,
            })
            pipe.expire(hash_key, 60)
            # Publish the active Trace-ID so the eBPF loader can correlate kernel
            # events with this request without scanning the full api_logs list.
            pipe.set("current_trace", trace_id, ex=60)
            # Notify the dashboard of every incoming request in real time
            body_preview = body.decode("utf-8", errors="ignore")[:200] if body else ""
            pipe.publish(SECURITY_EVENTS_CHANNEL, json.dumps({
                "type":         "incoming",
                "trace_id":     trace_id,
                "method":       request.method,
                "path":         request.url.path,
                "client_ip":    client_ip,
                "body_preview": body_preview,
                "timestamp":    time.time(),
            }))
            pipe.execute()
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
            logger.warning(f"Redis log failed (trace_id={trace_id}): {e}")

    # 6. Self-Healing Surgery — enforce AI-generated virtual patches.
    # Fetch regex patterns from Redis in a thread so the async event loop
    # is not blocked by the synchronous Redis call.
    patches = await asyncio.get_event_loop().run_in_executor(None, fetch_active_patches)
    if patches:
        body_text = body.decode("utf-8", errors="ignore")
        for pattern in patches:
            if pattern.search(request.url.path) or pattern.search(body_text):
                logger.warning(
                    f"[SelfHeal] {'[FP-TEST] ' if is_fp_test else ''}BLOCKED trace_id={trace_id} | "
                    f"pattern={pattern.pattern!r} matched "
                    f"path={request.url.path!r}"
                )
                # Only publish blocked event for real (non-probe) requests
                if not is_fp_test:
                    try:
                        r.hincrby(MS_STATS_KEY, "blocked_count", 1)
                        r.publish(SECURITY_EVENTS_CHANNEL, json.dumps({
                            "type":       "blocked",
                            "trace_id":   trace_id,
                            "pattern":    pattern.pattern,
                            "method":     request.method,
                            "path":       request.url.path,
                            "client_ip":  client_ip,
                            "timestamp":  time.time(),
                        }))
                    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
                        pass  # bridge.js notification is best-effort
                return Response(
                    content=_BLOCK_RESPONSE_BODY,
                    status_code=403,
                    headers={"content-type": "application/json"},
                )

    # 7. Forward the request to the backend using httpx
    # Removing 'host' header to allow proxying to target URL seamlessly
    headers: dict[str, str] = {k: v for k, v in request.headers.items()}
    headers["X-Marvel-Trace-ID"] = trace_id
    headers.pop("host", None)

    url = f"{TARGET_URL}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"

    try:
        async with httpx.AsyncClient() as client:
            proxy_response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body
            )
    except httpx.RequestError as e:
        logger.error(f"Backend unreachable (trace_id={trace_id}): {e}")
        return Response(
            content=json.dumps({"detail": "Backend unreachable", "trace_id": trace_id}),
            status_code=502,
            headers={"content-type": "application/json"},
        )

    response_headers: dict[str, str] = {k: v for k, v in proxy_response.headers.items()}

    # Let FastAPI/Uvicorn manage content encoding & transfer encoding headers
    response_headers.pop("content-encoding", None)
    response_headers.pop("content-length", None)

    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=response_headers
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
