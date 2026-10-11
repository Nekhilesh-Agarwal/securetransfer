from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.audit_log import list_events, verify_audit_chain
from app.services.auth import get_admin_user
from app.services.time_utils import to_utc_isoformat


router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/events")
def get_audit_events(
    db: Session = Depends(get_db),
    current_user=Depends(get_admin_user),
):
    events = list_events(db)
    return {
        "count": len(events),
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "session_id": event.session_id,
                "details": event.details,
                "actor_id": event.actor_id,
                "status": event.status,
                "previous_hash": event.previous_hash,
                "entry_hash": event.entry_hash,
                "created_at": to_utc_isoformat(event.created_at),
            }
            for event in events
        ],
    }


@router.get("/verify")
def verify_audit(
    db: Session = Depends(get_db),
    current_user=Depends(get_admin_user),
):
    valid = verify_audit_chain(db)
    return {
        "valid": valid,
        "message": (
            "Audit chain intact."
            if valid
            else "Audit chain verification failed."
        ),
    }
