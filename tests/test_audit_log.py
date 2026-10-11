import pytest

from app.database.connection import (
    Base,
    SessionLocal,
    engine,
)
from app.database.models import AuditLog
from app.services.audit_log import (
    record_event,
    verify_audit_chain,
)
Base.metadata.create_all(bind=engine)


def test_audit_log_hash_chain():
    db = SessionLocal()

    try:
        db.query(AuditLog).delete()
        db.commit()

        first = record_event(
            db=db,
            event_type="session_created",
            details="Test session created.",
            session_id="audit-test",
        )

        second = record_event(
            db=db,
            event_type="message_sent",
            details="Test message sent.",
            session_id="audit-test",
        )

        assert first.previous_hash is None
        assert first.entry_hash

        assert second.previous_hash == first.entry_hash
        assert second.entry_hash != first.entry_hash

        assert verify_audit_chain(db) is True

    finally:
        db.query(AuditLog).delete()
        db.commit()
        db.close()


def test_audit_log_detects_tampering():
    db = SessionLocal()

    try:
        db.query(AuditLog).delete()
        db.commit()

        record_event(
            db=db,
            event_type="session_created",
            details="Original details.",
        )

        assert verify_audit_chain(db) is True

        entry = (
            db.query(AuditLog)
            .order_by(AuditLog.id)
            .first()
        )

        entry.details = "Tampered details."
        db.commit()

        assert verify_audit_chain(db) is False

    finally:
        db.query(AuditLog).delete()
        db.commit()
        db.close()


def test_audit_log_requires_event_type():
    db = SessionLocal()

    try:
        with pytest.raises(
            ValueError,
            match="Event type is required",
        ):
            record_event(
                db=db,
                event_type="",
                details="test",
            )
    finally:
        db.close()


def test_audit_log_requires_details():
    db = SessionLocal()

    try:
        with pytest.raises(
            ValueError,
            match="Event details are required",
        ):
            record_event(
                db=db,
                event_type="test",
                details="",
            )
    finally:
        db.close()
