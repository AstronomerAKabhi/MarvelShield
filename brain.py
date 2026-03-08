import hashlib
import json
import re
import threading
import time
import logging
import os
import redis
import redis.exceptions
import httpx
from google import genai  # type: ignore[import-untyped]
from google.genai import types  # type: ignore[import-untyped]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [brain] %(levelname)s %(message)s",
)
logger = logging.getLogger("brain")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Must match the prefix used in gateway.py and loader.py
TRACE_KEY_PREFIX  = "trace:"
ACTIVE_PATCHES_KEY      = "active_patches"
PATCH_META_KEY          = "patch_meta"   # Redis hash: regex → JSON metadata
IP_BLOCKLIST_KEY        = "ip_blocklist" # SET of permanently banned IPs
ATTACKER_PROFILES_PREFIX = "attacker_profiles:"  # HASH per IP: attack history
BAN_THRESHOLD           = 3  # malicious requests before auto-ban

POLL_INTERVAL  = 2.0   # seconds between full Redis SCAN cycles
PROCESSED_TTL  = 120   # seconds — evict processed entries after 2× the 60s trace TTL

# Seconds to wait for loader.py kernel events before diagnosing on HTTP data alone.
# Set to 0 to diagnose immediately without waiting for eBPF data.
KERNEL_EVENT_WAIT = 3.0

# Redis pub/sub channel consumed by bridge.js → frontend clients
SECURITY_EVENTS_CHANNEL = "security_events"

# Payload guards — prevent token-limit exhaustion and billing spikes on large inputs
BODY_MAX_CHARS    = 2000   # truncate request body before sending to AI
HEADERS_MAX_COUNT = 20     # cap number of headers forwarded to AI
EVENTS_MAX_COUNT  = 20     # cap number of kernel execve events forwarded to AI

# AI model — gemini-2.5-flash: latest Flash model, best reasoning for security analysis
AI_MODEL = "gemini-2.5-flash"

# Cooldown in seconds after a quota/rate-limit error before retrying Gemini.
# Brain falls back to the built-in rule engine during this window.
QUOTA_COOLDOWN = 60.0

SYSTEM_PROMPT = (
    "You are an AppSec Expert. Analyze this HTTP request and kernel syscalls.\n"
    "Respond ONLY with a JSON object — no markdown, no explanation outside the JSON.\n\n"
    "If the request is an attack, return:\n"
    "{\n"
    '  "status": "malicious",\n'
    '  "attack_type": "<e.g. Command Injection, SSRF, SQL Injection, Path Traversal>",\n'
    '  "severity": "<CRITICAL | HIGH | MEDIUM | LOW>",\n'
    '  "cve_reference": "<most relevant CWE or CVE, e.g. CWE-78>",\n'
    '  "reasoning": "<one sentence explaining why this is malicious>",\n'
    '  "regex_patch": "<regex pattern to block this attack class>",\n'
    '  "confidence": <float 0.0-1.0 — how certain you are this is truly malicious and the regex is well-scoped. '
    "Use < 0.7 when the evidence is ambiguous or the regex may be too broad.>\n"
    "}\n\n"
    'If the request is clean, return: {"status": "clean"}'
)

# Patches with confidence below this threshold are provisional and auto-expire.
CONFIDENCE_THRESHOLD  = 0.7
# TTL in seconds for provisional (low-confidence) patches.
PATCH_EXPIRY_SECONDS  = 300   # 5 minutes

# ---------------------------------------------------------------------------
# Redis + Gemini clients
# ---------------------------------------------------------------------------

r = redis.Redis(
    host="127.0.0.1", port=6379, db=0,
    socket_connect_timeout=1, socket_timeout=1,
)

# Initialised at startup in main() once the env var is validated
gemini_client: genai.Client | None = None

# Tracks the unix timestamp of the last quota/rate-limit error so we can
# skip Gemini calls and use the rule engine during the cooldown window.
_quota_error_at: float = 0.0


# ---------------------------------------------------------------------------
# Built-in rule engine — fallback when Gemini quota is exhausted
# ---------------------------------------------------------------------------

_RULES: list[tuple[str, str, str, str, str]] = [
    # (pattern, attack_type, severity, cve, regex_patch)
    (r'(;|\||&&|`|\$\()',
     "Command Injection",    "CRITICAL", "CWE-78",  r"(?i)(;|\||&&|`|\$\()"),
    (r"(?i)(union\s+select|'\s*or\s+'1|drop\s+table|insert\s+into|select\s+\*)",
     "SQL Injection",        "CRITICAL", "CWE-89",  r"(?i)(union\s+select|'\s*or\s+'1|drop\s+table)"),
    (r"(?i)(169\.254|localhost|127\.0\.0\.1|file://|0\.0\.0\.0)",
     "SSRF",                 "HIGH",     "CWE-918", r"(?i)(169\.254|file://|0\.0\.0\.0)"),
    (r"(\.\./|\.\.\\)",
     "Path Traversal",       "HIGH",     "CWE-22",  r"(\.\./|\.\.\/)"),
    (r"(?i)(<script|onerror\s*=|javascript:|on\w+\s*=)",
     "XSS",                  "HIGH",     "CWE-79",  r"(?i)(<script|onerror\s*=|javascript:)"),
    (r"(?i)(eval\(|exec\(|system\(|passthru\(|shell_exec\()",
     "Code Injection",       "CRITICAL", "CWE-94",  r"(?i)(eval\(|exec\(|system\(|passthru\()"),
]

def rule_engine_diagnose(request_data: dict) -> dict:
    """
    Fast built-in detector used when Gemini quota is exhausted.
    Scans only attacker-controlled data (path + body) — headers are excluded
    because they contain internal IPs (Host: 127.0.0.1) that would cause false
    positive SSRF matches on every legitimate request.
    Confidence is fixed at 0.85: rules are deterministic but not AI-reasoned.
    """
    haystack = " ".join([
        request_data.get("path", ""),
        request_data.get("body", ""),
    ])
    for pattern, attack_type, severity, cve, regex_patch in _RULES:
        if re.search(pattern, haystack):
            return {
                "status":        "malicious",
                "attack_type":   attack_type,
                "severity":      severity,
                "cve_reference": cve,
                "reasoning":     f"[Rule engine] Pattern matched: {attack_type} signature detected in request.",
                "regex_patch":   regex_patch,
                "confidence":    0.85,
            }
    return {"status": "clean"}


# ---------------------------------------------------------------------------
# Data extraction
# ---------------------------------------------------------------------------

def extract_trace_data(
    fields: dict[bytes, bytes],
) -> tuple[dict | None, list[dict]]:
    """
    Deserialise a raw Redis hash into structured request_data and kernel_events.

    Gateway writes these fields:  method, path, headers, body
    Loader  writes these fields:  execve:<iso-timestamp>:<pid>  (one per event)

    Returns:
        request_data   — dict of HTTP context, or None if gateway fields absent
        kernel_events  — list of execve event dicts (may be empty)
    """
    str_fields = {k.decode(): v.decode() for k, v in fields.items()}

    request_data: dict | None = None
    if "method" in str_fields:
        try:
            headers = json.loads(str_fields.get("headers", "{}"))
        except json.JSONDecodeError:
            headers = {}
        request_data = {
            "method":    str_fields.get("method", ""),
            "path":      str_fields.get("path", ""),
            "headers":   headers,
            "body":      str_fields.get("body", ""),
            "client_ip": str_fields.get("client_ip", "unknown"),
        }

    kernel_events: list[dict] = []
    for key, val in str_fields.items():
        if key.startswith("execve:"):
            try:
                kernel_events.append(json.loads(val))
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping malformed kernel event field {key!r}: {e}")

    return request_data, kernel_events


# ---------------------------------------------------------------------------
# AI diagnosis
# ---------------------------------------------------------------------------

def diagnose(trace_id: str, request_data: dict, kernel_events: list[dict]) -> dict | None:
    """
    Send the combined HTTP + kernel context to Gemini and return the parsed JSON
    diagnosis.  Falls back to the built-in rule engine when:
      • Gemini quota / rate-limit error (429 / ResourceExhausted)
      • Within QUOTA_COOLDOWN seconds of a previous quota error
    Returns None only on unexpected failures that should trigger a retry.
    """
    global _quota_error_at

    # Apply size guards before sending to the external API
    safe_request = {
        **request_data,
        "body":    request_data["body"][:BODY_MAX_CHARS],
        "headers": dict(list(request_data["headers"].items())[:HEADERS_MAX_COUNT]),
    }
    safe_events = kernel_events[:EVENTS_MAX_COUNT]

    # Use rule engine during quota cooldown to keep the demo running
    in_cooldown = (time.time() - _quota_error_at) < QUOTA_COOLDOWN
    if gemini_client is None or in_cooldown:
        if in_cooldown:
            logger.warning(f"[{trace_id}] Gemini quota cooldown active — using rule engine")
        result = rule_engine_diagnose(safe_request)
        logger.info(f"[{trace_id}] Rule engine → {result['status']}")
        return result

    user_message = json.dumps(
        {"http_request": safe_request, "kernel_syscalls": safe_events},
        indent=2,
    )

    try:
        response = gemini_client.models.generate_content(
            model=AI_MODEL,
            contents=user_message,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                temperature=0,
            ),
        )
        raw = response.text or "{}"
        logger.info(f"[{trace_id}] Gemini raw response: {raw[:300]}")
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"[{trace_id}] Gemini returned non-JSON: {e} — raw: {(response.text or '')[:200]}")
        return None
    except Exception as e:
        err_str = str(e).lower()
        if "quota" in err_str or "429" in err_str or "resource" in err_str or "exhausted" in err_str:
            _quota_error_at = time.time()
            logger.warning(
                f"[{trace_id}] Gemini quota exceeded — switching to rule engine "
                f"for {QUOTA_COOLDOWN:.0f}s.  Full error: {e}"
            )
            result = rule_engine_diagnose(safe_request)
            logger.info(f"[{trace_id}] Rule engine → {result['status']}")
            return result
        logger.error(f"[{trace_id}] AI call failed: {type(e).__name__}: {e}")
        return None


def publish_event(payload: dict) -> None:
    """Publish a JSON payload to the security_events channel for bridge.js."""
    try:
        r.publish(SECURITY_EVENTS_CHANNEL, json.dumps(payload))
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
        logger.warning(f"[brain] Could not publish security event: {e}")


# ---------------------------------------------------------------------------
# Healing loop
# ---------------------------------------------------------------------------

def update_attacker_profile(ip: str, attack_type: str) -> None:
    """
    Maintain a per-IP attack history in Redis.
    - Increments total_attacks atomically via HINCRBY.
    - Appends the normalised attack type to the attack_types list.
    - Sets first_seen on first hit; always updates last_seen.
    - When total_attacks reaches BAN_THRESHOLD: marks status=banned, adds IP
      to ip_blocklist SET (gateway picks this up on the next request), and
      publishes an attacker_banned event for the dashboard.
    - Publishes attacker_profile_update on every non-ban update.
    """
    if not ip or ip in ("", "unknown"):
        return
    key     = f"{ATTACKER_PROFILES_PREFIX}{ip}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        # Atomically get the new count
        total = int(r.hincrby(key, "total_attacks", 1))

        # Read the rest of the profile for context
        raw = r.hgetall(key)
        profile = {k.decode(): v.decode() for k, v in raw.items()}

        # Maintain attack_types list (deduped)
        try:
            types_list: list[str] = json.loads(profile.get("attack_types", "[]"))
        except json.JSONDecodeError:
            types_list = []
        norm = attack_type.lower().replace(" ", "_").replace("-", "_")
        if norm not in types_list:
            types_list.append(norm)

        was_banned = profile.get("status") == "banned"
        now_banned = total >= BAN_THRESHOLD

        updates: dict[str, str] = {
            "attack_types": json.dumps(types_list),
            "last_seen":    now_iso,
            "total_attacks": str(total),
        }
        if "first_seen" not in profile:
            updates["first_seen"] = now_iso
        updates["status"] = "banned" if now_banned else profile.get("status", "active")

        pipe = r.pipeline()
        pipe.hset(key, mapping=updates)
        if now_banned and not was_banned:
            pipe.sadd(IP_BLOCKLIST_KEY, ip)
        pipe.execute()

        first_seen = updates.get("first_seen") or profile.get("first_seen", now_iso)

        if now_banned and not was_banned:
            logger.warning(
                f"[Fingerprint] 🚨 IP {ip} BANNED after {total} attacks — "
                f"types: {types_list}"
            )
            publish_event({
                "type":          "attacker_banned",
                "ip":            ip,
                "total_attacks": total,
                "attack_types":  types_list,
                "first_seen":    first_seen,
                "last_seen":     now_iso,
                "timestamp":     time.time(),
            })
        else:
            logger.info(
                f"[Fingerprint] {ip} profile updated — "
                f"{total} attack(s), status={updates['status']}, types={types_list}"
            )
            publish_event({
                "type":          "attacker_profile_update",
                "ip":            ip,
                "total_attacks": total,
                "attack_types":  types_list,
                "status":        updates["status"],
                "first_seen":    first_seen,
                "last_seen":     now_iso,
                "timestamp":     time.time(),
            })

    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
        logger.warning(f"[Fingerprint] Redis error for {ip}: {e}")
    except Exception as e:
        logger.error(f"[Fingerprint] Unexpected error for {ip}: {type(e).__name__}: {e}")


def _patch_id(regex: str) -> str:
    """Stable short ID for a patch derived from its regex string."""
    return hashlib.md5(regex.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# False Positive Tester
# ---------------------------------------------------------------------------

# Benign payloads sent to the gateway after each patch to verify no legit
# traffic is blocked.  Keyed by normalised attack_type (lower-case, spaces
# replaced with underscores).  Each entry is a list of
# (method, path, json_body_or_None) tuples.
_FP_PAYLOADS: dict[str, list[tuple[str, str, dict | None]]] = {
    "command_injection": [
        ("POST", "/api/execute", {"cmd": "echo MarvelShield"}),
        ("POST", "/api/execute", {"cmd": "date"}),
        ("POST", "/api/execute", {"cmd": "ls /tmp"}),
    ],
    "ssrf": [
        ("POST", "/api/execute", {"url": "https://example.com/api"}),
        ("POST", "/api/execute", {"url": "https://api.github.com"}),
        ("POST", "/api/execute", {"url": "https://httpbin.org/get"}),
    ],
    "path_traversal": [
        ("GET", "/api/files/readme.txt", None),
        ("GET", "/api/reports/summary.json", None),
        ("GET", "/api/data/user-profile.csv", None),
    ],
    "sql_injection": [
        ("POST", "/api/execute", {"id": "42"}),
        ("POST", "/api/execute", {"query": "SELECT name FROM users WHERE id = 1"}),
        ("POST", "/api/execute", {"user": "alice"}),
    ],
}
_FP_DEFAULT: list[tuple[str, str, dict | None]] = [
    ("GET", "/health", None),
    ("GET", "/health", None),
    ("GET", "/health", None),
]

GATEWAY_URL = "http://127.0.0.1:8000"


def run_false_positive_test(
    trace_id: str,
    patch_id: str,
    regex: str,
    attack_type: str,
    method: str,
    path: str,
) -> None:
    """
    Send 3 benign requests to the gateway to verify the new patch doesn't
    block legitimate traffic.  Results are published as a
    'false_positive_result' event consumed by the dashboard.

    The test runs AFTER the patch is stored in Redis so the gateway will
    evaluate the regex on these requests.  A response of 403 from the
    gateway (not app.js) indicates a false positive.
    """
    # Small delay to ensure the gateway's in-memory patch cache (active_patches
    # SET in Redis) is populated before we fire the probes.
    time.sleep(0.2)

    norm_type = attack_type.lower().replace(" ", "_").replace("-", "_")
    payloads  = _FP_PAYLOADS.get(norm_type, _FP_DEFAULT)

    passed  = 0
    failed  = 0
    details: list[dict] = []

    try:
        with httpx.Client(
            base_url=GATEWAY_URL,
            timeout=5.0,
            # Mark test requests so they don't re-trigger analysis
            headers={"X-FP-Test": "1"},
        ) as client:
            for method_p, path_p, body in payloads:
                try:
                    if method_p.upper() == "GET":
                        resp = client.get(path_p)
                    else:
                        resp = client.post(path_p, json=body)

                    # 403 from gateway = regex blocked a benign request → FP
                    is_fp = resp.status_code == 403
                    if is_fp:
                        failed += 1
                        details.append({
                            "method":  method_p,
                            "path":    path_p,
                            "body":    body,
                            "status":  resp.status_code,
                            "blocked": True,
                        })
                        logger.warning(
                            f"[FP-Test] [{trace_id}] ⚠ FALSE POSITIVE — "
                            f"{method_p} {path_p} body={body} → HTTP {resp.status_code}"
                        )
                    else:
                        passed += 1
                        details.append({
                            "method":  method_p,
                            "path":    path_p,
                            "body":    body,
                            "status":  resp.status_code,
                            "blocked": False,
                        })
                except Exception as e:
                    # Connection error / timeout — treat as inconclusive, not FP
                    logger.warning(f"[FP-Test] [{trace_id}] Probe error: {e}")
                    details.append({
                        "method":  method_p,
                        "path":    path_p,
                        "body":    body,
                        "status":  -1,
                        "blocked": False,
                        "error":   str(e),
                    })

        total = passed + failed
        logger.info(
            f"[FP-Test] [{trace_id}] {passed}/{total} benign requests passed — "
            f"{failed} false positive(s) detected"
        )
        publish_event({
            "type":            "false_positive_result",
            "trace_id":        trace_id,
            "patch_id":        patch_id,
            "regex_patch":     regex,
            "attack_type":     attack_type,
            "passed":          passed,
            "failed":          failed,
            "total":           total,
            "details":         details,
            "timestamp":       time.time(),
        })

    except Exception as e:
        logger.error(f"[FP-Test] [{trace_id}] Unexpected error: {type(e).__name__}: {e}")


def apply_patch(trace_id: str, diagnosis: dict, request_data: dict) -> None:
    """
    If the diagnosis is malicious and includes a regex_patch, add it to the
    Redis set 'active_patches' and store full explainability metadata in
    'patch_meta' hash so the dashboard can show why the patch was created.

    Confidence handling:
      • confidence >= 0.7 → permanent patch (no expiry)
      • confidence <  0.7 → provisional patch: a 'patch_alive:{id}' sentinel
        key is created with a 300 s TTL; cleanup_expired_patches() removes the
        patch from active_patches once the sentinel disappears.

    Always publishes a security event to bridge.js regardless of verdict.
    """
    status = diagnosis.get("status", "unknown")
    confidence = float(diagnosis.get("confidence", 1.0))
    confidence = max(0.0, min(1.0, confidence))   # clamp to [0, 1]

    event: dict = {
        "type":        "diagnosis",
        "trace_id":    trace_id,
        "status":      status,
        "method":      request_data.get("method", ""),
        "path":        request_data.get("path", ""),
        "attack_type": diagnosis.get("attack_type", ""),
        "severity":    diagnosis.get("severity", ""),
        "cve":         diagnosis.get("cve_reference", ""),
        "reasoning":   diagnosis.get("reasoning", ""),
        "confidence":  confidence,
        "timestamp":   time.time(),
    }

    if status != "malicious":
        publish_event(event)
        return

    patch = diagnosis.get("regex_patch", "").strip()
    if not patch:
        logger.warning(f"[{trace_id}] Malicious verdict but no regex_patch — skipping")
        publish_event(event)
        return

    patch_id       = _patch_id(patch)
    low_confidence = confidence < CONFIDENCE_THRESHOLD

    try:
        meta = {
            "attack_type":    diagnosis.get("attack_type", "Unknown"),
            "severity":       diagnosis.get("severity", "UNKNOWN"),
            "cve_reference":  diagnosis.get("cve_reference", ""),
            "reasoning":      diagnosis.get("reasoning", ""),
            "regex_patch":    patch,
            "confidence":     confidence,
            "low_confidence": low_confidence,
            "patch_id":       patch_id,
            "trace_id":       trace_id,
            "created_at":     time.time(),
        }
        pipe = r.pipeline()
        pipe.sadd(ACTIVE_PATCHES_KEY, patch)
        pipe.hset(PATCH_META_KEY, patch, json.dumps(meta))
        if low_confidence:
            # Sentinel key — when it expires, cleanup_expired_patches() rolls back the patch
            pipe.setex(f"patch_alive:{patch_id}", PATCH_EXPIRY_SECONDS, "1")
        pipe.execute()

        # Add patch-specific fields to the event without clobbering existing fields
        event["regex_patch"]    = patch
        event["patch_id"]       = patch_id
        event["attack_type"]    = meta["attack_type"]
        event["severity"]       = meta["severity"]
        event["cve"]            = meta["cve_reference"]
        event["reasoning"]      = meta["reasoning"]
        event["low_confidence"] = low_confidence

        if low_confidence:
            logger.warning(
                f"[{trace_id}] ⚠ MALICIOUS [{meta['severity']}] {meta['attack_type']} "
                f"confidence={confidence:.2f} — PROVISIONAL patch (auto-expires {PATCH_EXPIRY_SECONDS}s): {patch}"
            )
        else:
            logger.warning(
                f"[{trace_id}] ⚠ MALICIOUS [{meta['severity']}] {meta['attack_type']} "
                f"confidence={confidence:.2f} — permanent patch stored: {patch}"
            )

        # Update attacker fingerprint for the source IP
        client_ip = request_data.get("client_ip", "unknown")
        update_attacker_profile(client_ip, meta["attack_type"])

        # Run false-positive tests asynchronously (non-blocking for the main loop)
        threading.Thread(
            target=run_false_positive_test,
            args=(trace_id, patch_id, patch, meta["attack_type"],
                  request_data.get("method", "POST"),
                  request_data.get("path", "/api/execute")),
            daemon=True,
        ).start()

    except Exception as e:
        logger.error(f"[{trace_id}] Failed to store patch in Redis: {type(e).__name__}: {e}")

    publish_event(event)


# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------

def scan_and_correlate(processed: dict[str, float]) -> None:
    """
    One full SCAN pass over all trace:* keys.  Processes a key as soon as
    gateway fields are present.  Kernel events (from loader.py) are treated as
    enrichment: brain.py waits up to KERNEL_EVENT_WAIT seconds for them, then
    diagnoses on HTTP data alone so the pipeline works even without eBPF.
    """
    try:
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match=f"{TRACE_KEY_PREFIX}*", count=100)  # type: ignore[assignment]
            cursor = int(cursor)  # guard against unexpected return types causing infinite loop
            for raw_key in keys:
                key      = raw_key.decode()
                trace_id = key[len(TRACE_KEY_PREFIX):]

                if trace_id in processed:
                    continue

                fields: dict[bytes, bytes] = r.hgetall(key)  # type: ignore[assignment]
                if not fields:
                    continue

                request_data, kernel_events = extract_trace_data(fields)

                # Skip until gateway has written the HTTP fields
                if request_data is None:
                    continue

                # If no kernel events yet, wait briefly then proceed without them
                if not kernel_events:
                    if f"seen:{trace_id}" not in processed:
                        # First time we see this trace — start the wait timer
                        processed[f"seen:{trace_id}"] = time.time()
                        continue
                    age = time.time() - processed[f"seen:{trace_id}"]
                    if age < KERNEL_EVENT_WAIT:
                        continue
                    logger.info(f"[{trace_id}] No kernel events after {KERNEL_EVENT_WAIT}s — diagnosing on HTTP data only")

                # Clean up the "seen" sentinel before registering as processed
                processed.pop(f"seen:{trace_id}", None)

                # Register before the AI call to prevent double-processing within
                # this scan cycle. Removed on failure so the trace can be retried
                # next cycle rather than silently dropped.
                processed[trace_id] = time.time()

                logger.info(
                    f"[{trace_id}] Correlated — "
                    f"{len(kernel_events)} kernel event(s) with request "
                    f"{request_data['method']} {request_data['path']}"
                )

                diagnosis = diagnose(trace_id, request_data, kernel_events)
                if diagnosis is None:
                    del processed[trace_id]  # allow retry on next scan cycle
                    continue

                status = diagnosis.get("status", "unknown")
                logger.info(f"[{trace_id}] Diagnosis → {status}")

                apply_patch(trace_id, diagnosis, request_data)

            if cursor == 0:
                break  # completed a full scan cycle

    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
        logger.warning(f"Redis scan failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in scan loop: {type(e).__name__}: {e}")


def cleanup_expired_patches() -> None:
    """
    Remove low-confidence patches whose 'patch_alive:{id}' sentinel key has
    expired.  Called every poll cycle so rollbacks happen within ~POLL_INTERVAL
    seconds of the Redis TTL firing.
    """
    try:
        raw_patches: set[bytes] = r.smembers(ACTIVE_PATCHES_KEY)  # type: ignore[assignment]
        for raw in raw_patches:
            patch = raw.decode()
            meta_raw = r.hget(PATCH_META_KEY, patch)
            if not meta_raw:
                continue
            try:
                meta = json.loads(meta_raw)
            except json.JSONDecodeError:
                continue
            if not meta.get("low_confidence"):
                continue  # permanent patch — leave it alone
            patch_id = meta.get("patch_id") or _patch_id(patch)
            if r.exists(f"patch_alive:{patch_id}"):
                continue  # sentinel still alive — not expired yet
            # Sentinel gone → roll back
            pipe = r.pipeline()
            pipe.srem(ACTIVE_PATCHES_KEY, patch)
            pipe.hdel(PATCH_META_KEY, patch)
            pipe.execute()
            logger.info(
                f"[cleanup] Auto-expired low-confidence patch "
                f"(confidence={meta.get('confidence', '?'):.2f}): {patch[:80]}"
            )
            publish_event({
                "type":        "patch_expired",
                "patch_id":    patch_id,
                "regex_patch": patch,
                "attack_type": meta.get("attack_type", ""),
                "confidence":  meta.get("confidence", 0.0),
                "timestamp":   time.time(),
            })
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
        logger.warning(f"[cleanup] Redis error during patch expiry sweep: {e}")
    except Exception as e:
        logger.error(f"[cleanup] Unexpected error: {type(e).__name__}: {e}")


def evict_processed(processed: dict[str, float]) -> None:
    """
    Remove entries older than PROCESSED_TTL so the in-memory registry doesn't
    grow unboundedly during long-running sessions.
    """
    cutoff = time.time() - PROCESSED_TTL
    stale  = [tid for tid, ts in processed.items() if ts < cutoff]
    for tid in stale:
        del processed[tid]


def main() -> None:
    logger.info("MarvelShield Brain active — polling Redis for trace:* keys")

    if not os.environ.get("GEMINI_API_KEY"):
        logger.error("GEMINI_API_KEY environment variable is not set — exiting")
        raise SystemExit(1)

    # Configure the Gemini client once at startup, after the API key is confirmed present
    global gemini_client
    gemini_client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

    # Write a heartbeat key so simulate_attack.py can confirm brain.py is alive
    r.set("brain:alive", "1", ex=30)
    logger.info("Heartbeat key 'brain:alive' written to Redis")

    # trace_id -> unix timestamp of when it was processed
    processed: dict[str, float] = {}

    while True:
        r.set("brain:alive", "1", ex=30)  # refresh heartbeat every poll cycle
        scan_and_correlate(processed)
        evict_processed(processed)
        cleanup_expired_patches()
        try:
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Shutting down — goodbye.")
            raise SystemExit(0)


if __name__ == "__main__":
    main()
