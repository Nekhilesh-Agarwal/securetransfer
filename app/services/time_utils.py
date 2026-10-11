from datetime import datetime, timezone


def to_utc_isoformat(value: datetime | None) -> str | None:
    """Serialize stored datetimes as timezone-aware UTC for browser clients."""
    if value is None:
        return None
    if value.tzinfo is None:
        # SQLite drops timezone metadata from DateTime columns. App timestamps
        # are written in UTC, so restore that meaning before serializing.
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat()
