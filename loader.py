import json
import ctypes
import datetime
import sys
import redis
import redis.exceptions
from bcc import BPF  # type: ignore  # bcc is Linux-only; IDE lint on Windows is a false positive

# 1. Load the eBPF C program
b = BPF(src_file="sensor.c")

# 2. Attach kprobe to the execve syscall
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

# 3. Mirror the kernel-side struct data_t in Python
class DataEvent(ctypes.Structure):
    _fields_ = [
        ("pid",  ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),  # type: ignore  # valid ctypes array syntax; Pyright false positive
    ]

# 4. Connect to Redis (same instance as the Gateway)
# 127.0.0.1 avoids WSL2 DNS delays; short timeouts keep the perf-buffer
# callback from blocking if Redis is temporarily unreachable.
r = redis.Redis(host="127.0.0.1", port=6379, db=0,
                socket_connect_timeout=1, socket_timeout=1)

# Shared hash-key prefix — must match gateway.py: trace:<uuid>
TRACE_KEY_PREFIX = "trace:"

# Timezone constant — created once at module level instead of on every event
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


def get_current_trace_id() -> str | None:
    """
    Return the most recent Gateway Trace-ID, or None if unavailable.

    Resolution order:
      1. 'current_trace' key — set by the Gateway on every request (preferred).
      2. Head of the 'api_logs' list — legacy / alternative gateway modes that
         still push JSON blobs with a 'trace_id' field.
    """
    try:
        value: bytes | None = r.get("current_trace")  # type: ignore[assignment]
        if value:
            return value.decode("utf-8")

        raw: bytes | None = r.lindex("api_logs", 0)  # type: ignore[assignment]
        if raw:
            return json.loads(raw).get("trace_id")
    except (redis.exceptions.ConnectionError,
            redis.exceptions.TimeoutError,
            json.JSONDecodeError,
            AttributeError):
        pass

    return None


# 5. Callback: fired once per perf buffer event
def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(DataEvent)).contents
    record = {
        "timestamp": datetime.datetime.now(IST).isoformat(),
        "pid":  event.pid,
        "comm": event.comm.decode("utf-8", errors="replace"),
    }
    print(json.dumps(record), flush=True)

    # Correlate this kernel event with the active Gateway request.
    # Each execve event is stored as a separate hash field so multiple
    # events on the same request don't overwrite each other.
    try:
        trace_id = get_current_trace_id()
        if not trace_id:
            return  # No active request to correlate with — skip silently

        hash_key  = f"{TRACE_KEY_PREFIX}{trace_id}"
        # Field name is unique per event: execve:<iso-timestamp>:<pid>
        field     = f"execve:{record['timestamp']}:{record['pid']}"
        r.hset(hash_key, field, json.dumps(record))
    except (redis.exceptions.ConnectionError,
            redis.exceptions.TimeoutError) as e:
        print(f"[loader] Redis write failed: {e}", flush=True)


# 6. Open the perf buffer and start polling
b["events"].open_perf_buffer(handle_event)

print("MarvelShield Sensor Active... Press Ctrl+C to stop.", flush=True)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    sys.exit(0)
