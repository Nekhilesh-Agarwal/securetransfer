from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import TrustedDevice
from app.security.device_identity import (
    get_public_key_base64,
    get_public_key_fingerprint,
)
from app.services.auth import get_current_user
from app.services.user_identity import ensure_user_identity
from app.services.time_utils import to_utc_isoformat


router = APIRouter(prefix="/security", tags=["Security"])


@router.get("/dashboard")
def security_dashboard(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    trusted = (
        db.query(TrustedDevice)
        .filter(TrustedDevice.trusted.is_(True))
        .all()
    )
    identity = ensure_user_identity(db, current_user)
    return {
        "device": {
            "name": current_user.username,
            "public_key": identity.public_key,
            "fingerprint": identity.fingerprint,
            "server_fingerprint": get_public_key_fingerprint(),
            "server_public_key": get_public_key_base64(),
        },
        "user": current_user.username,
        "trusted_devices": [
            {
                "device_name": device.device_name,
                "fingerprint": device.fingerprint,
                "public_key": device.public_key,
                "paired_at": to_utc_isoformat(device.paired_at),
            }
            for device in trusted
        ],
    }
