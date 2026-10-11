import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import TrustedDevice
from app.security.device_identity import (
    get_public_key_base64,
    get_public_key_fingerprint,
)
from app.security.pairing import create_pairing_payload
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.pairing import (
    confirm_pairing,
    prepare_pairing,
)
from app.services.qr import pairing_qr_png_bytes
from app.services.user_identity import ensure_user_identity


router = APIRouter(
    prefix="/devices",
    tags=["Devices"],
)


class PairingPayloadRequest(BaseModel):
    payload: str


class ConfirmPairingRequest(BaseModel):
    payload: str
    fingerprint: str


def _pairing_body() -> dict:
    payload = create_pairing_payload()
    return {
        "payload": payload,
        "fingerprint": get_public_key_fingerprint(),
        "public_key": get_public_key_base64(),
        "device": os.environ.get(
            "SENTINEL_DEVICE_NAME",
            "SecureTransfer",
        ),
    }


@router.get("/identity")
def get_device_identity():
    """Public device identity used for QR pairing and fingerprints."""

    body = _pairing_body()
    return {
        "device": body["device"],
        "public_key": body["public_key"],
        "fingerprint": body["fingerprint"],
    }


@router.get("/pairing")
def get_pairing_payload():
    """Public pairing payload shown on the receiver QR screen."""

    return _pairing_body()


@router.get("/pairing/qr")
def get_pairing_qr():
    """PNG QR code containing this device's pairing payload."""

    return Response(content=pairing_qr_png_bytes(), media_type="image/png")


def _user_pairing_body(db: Session, current_user) -> dict:
    identity = ensure_user_identity(db, current_user)
    device_name = current_user.username
    payload = create_pairing_payload(
        device_name=device_name,
        public_key=identity.public_key,
        fingerprint=identity.fingerprint,
    )
    return {
        "payload": payload,
        "fingerprint": identity.fingerprint,
        "public_key": identity.public_key,
        "device": device_name,
    }


@router.get("/me/pairing")
def get_my_pairing_payload(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Authenticated pairing payload for this signed-in client."""

    return _user_pairing_body(db, current_user)


@router.get("/me/pairing/qr")
def get_my_pairing_qr(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    body = _user_pairing_body(db, current_user)
    return Response(
        content=pairing_qr_png_bytes(payload=body["payload"]),
        media_type="image/png",
    )


@router.get("/trusted")
def list_trusted_devices(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    devices = (
        db.query(TrustedDevice)
        .filter(TrustedDevice.trusted.is_(True))
        .all()
    )
    return {
        "devices": [
            {
                "device_name": device.device_name,
                "fingerprint": device.fingerprint,
                "public_key": device.public_key,
            }
            for device in devices
        ]
    }


@router.post("/pairing/prepare")
def prepare_device_pairing(
    request: PairingPayloadRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return prepare_pairing(request.payload)

    except ValueError as exc:
        record_event(
            db=db,
            event_type="DEVICE_PAIRING_FAILURE",
            details=str(exc),
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.post("/pairing/confirm")
def confirm_device_pairing(
    request: ConfirmPairingRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    identity = ensure_user_identity(db, current_user)
    try:
        preview = prepare_pairing(request.payload)
        if preview["public_key"] == identity.public_key:
            raise ValueError("Cannot pair a device with itself.")
        device = confirm_pairing(
            db=db,
            payload=request.payload,
            confirmed_fingerprint=request.fingerprint,
        )

    except ValueError as exc:
        record_event(
            db=db,
            event_type="DEVICE_PAIRING_FAILURE",
            details=str(exc),
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    record_event(
        db=db,
        event_type="DEVICE_PAIRING_SUCCESS",
        details=f"Trusted {device.device_name} ({device.fingerprint}).",
        actor_id=current_user.username,
        status="success",
    )

    return {
        "message": "Device trusted successfully.",
        "device": device.device_name,
        "fingerprint": device.fingerprint,
        "public_key": device.public_key,
    }
