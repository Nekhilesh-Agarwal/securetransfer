from sqlalchemy.orm import Session

from app.security.pairing import verify_pairing_payload
from app.services.trusted_devices import add_trusted_device


def prepare_pairing(payload: str) -> dict:
    """
    Validate a scanned pairing payload.

    This does not trust the device.
    It only verifies the pairing payload.
    """
    data = verify_pairing_payload(payload)

    return {
        "version": data["version"],
        "device": data["device"],
        "public_key": data["public_key"],
        "fingerprint": data["fingerprint"],
    }


def confirm_pairing(
    db: Session,
    payload: str,
    confirmed_fingerprint: str,
):
    """
    Trust a device after the user confirms its fingerprint.
    """
    data = prepare_pairing(payload)

    if data["fingerprint"] != confirmed_fingerprint:
        raise ValueError(
            "Fingerprint confirmation does not match the pairing payload."
        )

    return add_trusted_device(
        db=db,
        device_name=data["device"],
        public_key=data["public_key"],
        fingerprint=data["fingerprint"],
    )