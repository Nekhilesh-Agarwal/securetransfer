"""Local Sentinel Monitor.

PyShark/Wireshark capture is optional on Windows (Npcap required).
The monitor always tracks application-level security events so flood
and suspicious-activity signals remain available without sniffing.
"""

from collections import deque
from datetime import datetime, timezone
from threading import Lock

_EVENTS: deque[dict] = deque(maxlen=200)
_LOCK = Lock()


def record_local_event(kind: str, detail: str) -> None:
    with _LOCK:
        _EVENTS.append(
            {
                "kind": kind,
                "detail": detail,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )


def _pyshark_available() -> tuple[bool, str]:
    try:
        import pyshark  # noqa: F401
    except Exception as exc:  # pragma: no cover - environment dependent
        return False, f"PyShark is not available: {exc}"

    return True, "PyShark imported. Start scripts/sentinel_monitor.py for live capture."


def get_monitor_status() -> dict:
    available, note = _pyshark_available()
    with _LOCK:
        events = list(_EVENTS)

    suspicious = [
        event
        for event in events
        if event["kind"]
        in {"flood", "replay", "tamper", "failed_auth", "untrusted"}
    ]

    return {
        "name": "Sentinel Monitor",
        "pyshark_available": available,
        "note": note,
        "suspicious_count": len(suspicious),
        "recent_events": events[-25:],
        "alert": (
            "Suspicious activity detected."
            if suspicious
            else "No suspicious application events recorded."
        ),
    }
