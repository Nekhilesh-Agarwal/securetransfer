import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database.models import AuditLog


def _canonical_timestamp(value: datetime) -> str:
    """Return a stable UTC timestamp representation."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return value.isoformat()


def _calculate_hash(
    event_type: str,
    session_id: str | None,
    details: str,
    created_at: datetime,
    previous_hash: str | None,
) -> str:
    payload = {
        "event_type": event_type,
        "session_id": session_id,
        "details": details,
        "created_at": _canonical_timestamp(created_at),
        "previous_hash": previous_hash,
    }

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def record_event(
    db: Session,
    event_type: str,
    details: str,
    session_id: str | None = None,
    actor_id: str | None = None,
    status: str | None = "success",
) -> AuditLog:
    """Record a security event in a tamper-evident hash chain."""

    if not event_type:
        raise ValueError("Event type is required.")

    if not details:
        raise ValueError("Event details are required.")

    previous_entry = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .first()
    )

    previous_hash = (
        previous_entry.entry_hash
        if previous_entry is not None
        else None
    )

    created_at = datetime.now(timezone.utc)

    entry_hash = _calculate_hash(
        event_type=event_type,
        session_id=session_id,
        details=details,
        created_at=created_at,
        previous_hash=previous_hash,
    )

    record = AuditLog(
        event_type=event_type,
        session_id=session_id,
        details=details,
        actor_id=actor_id,
        status=status,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        created_at=created_at,
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return record


def list_events(db: Session, limit: int = 100) -> list[AuditLog]:
    return (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .limit(limit)
        .all()
    )


def verify_audit_chain(
    db: Session,
) -> bool:
    """Verify the integrity of the complete audit-log chain."""

    entries = (
        db.query(AuditLog)
        .order_by(AuditLog.id)
        .all()
    )

    previous_hash = None

    for entry in entries:
        if entry.previous_hash != previous_hash:
            return False

        expected_hash = _calculate_hash(
            event_type=entry.event_type,
            session_id=entry.session_id,
            details=entry.details,
            created_at=entry.created_at,
            previous_hash=entry.previous_hash,
        )

        if entry.entry_hash != expected_hash:
            return False

        previous_hash = entry.entry_hash

    return True
