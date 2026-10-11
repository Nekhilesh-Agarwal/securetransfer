import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from app.storage_paths import data_path


DEMO_LOG_PATH = data_path("logs", "encryption_demo.log")


def demo_log_enabled() -> bool:
    return os.environ.get("ENABLE_ENCRYPTION_DEMO_LOG", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def include_plaintext() -> bool:
    return demo_log_enabled() and os.environ.get(
        "ENCRYPTION_DEMO_INCLUDE_PLAINTEXT",
        "false",
    ).lower() in {"1", "true", "yes", "on"}


def log_encryption_demo(entry: dict) -> None:
    """Append one encryption demonstration record. Disabled by default."""

    if not demo_log_enabled():
        return

    DEMO_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **entry,
    }
    with DEMO_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def file_content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
