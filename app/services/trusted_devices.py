from sqlalchemy.orm import Session

from app.database.models import TrustedDevice


def add_trusted_device(
    db: Session,
    device_name: str,
    public_key: str,
    fingerprint: str,
) -> TrustedDevice:
    """Store a device as trusted."""

    existing_device = (
        db.query(TrustedDevice)
        .filter(TrustedDevice.public_key == public_key)
        .first()
    )

    if existing_device is not None:
        existing_device.device_name = device_name
        existing_device.fingerprint = fingerprint
        existing_device.trusted = True

        db.commit()
        db.refresh(existing_device)

        return existing_device

    device = TrustedDevice(
        device_name=device_name,
        public_key=public_key,
        fingerprint=fingerprint,
        trusted=True,
    )

    db.add(device)
    db.commit()
    db.refresh(device)

    return device


def get_trusted_device(
    db: Session,
    public_key: str,
) -> TrustedDevice | None:
    """Find a trusted device by its public key."""

    return (
        db.query(TrustedDevice)
        .filter(
            TrustedDevice.public_key == public_key,
            TrustedDevice.trusted.is_(True),
        )
        .first()
    )


def revoke_trusted_device(
    db: Session,
    public_key: str,
) -> bool:
    """Revoke trust for a device."""

    device = (
        db.query(TrustedDevice)
        .filter(TrustedDevice.public_key == public_key)
        .first()
    )

    if device is None:
        return False

    device.trusted = False

    db.commit()

    return True