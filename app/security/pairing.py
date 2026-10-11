import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
)


def create_pairing_payload(
    device_name: str | None = None,
    public_key: str | None = None,
    fingerprint: str | None = None,
) -> str:
    """Create the data that will be encoded into a pairing QR code."""
    if device_name is None:
        device_name = os.environ.get(
            "SENTINEL_DEVICE_NAME",
            "SecureTransfer",
        )
    from app.security.device_identity import (
        get_public_key_base64,
        get_public_key_fingerprint,
    )

    payload = {
        "version": 1,
        "device": device_name,
        "public_key": public_key or get_public_key_base64(),
        "fingerprint": fingerprint or get_public_key_fingerprint(),
    }

    return json.dumps(
        payload,
        separators=(",", ":"),
    )


def parse_pairing_payload(payload: str) -> dict:
    """Parse and validate a pairing payload."""
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid pairing payload.") from exc

    required_fields = {
        "version",
        "device",
        "public_key",
        "fingerprint",
    }

    if not required_fields.issubset(data):
        raise ValueError("Pairing payload is missing required fields.")

    return data


def verify_pairing_payload(payload: str) -> dict:
    """
    Validate a pairing payload and verify that the fingerprint
    matches the supplied X25519 public key.
    """
    data = parse_pairing_payload(payload)

    try:
        public_key_bytes = base64.b64decode(
            data["public_key"],
            validate=True,
        )
    except Exception as exc:
        raise ValueError("Invalid public key encoding.") from exc

    try:
        X25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError as exc:
        raise ValueError("Invalid X25519 public key.") from exc

    digest = hashlib.sha256(public_key_bytes).hexdigest()

    calculated_fingerprint = ":".join(
        digest[i:i + 2]
        for i in range(0, len(digest), 2)
    )

    if calculated_fingerprint != data["fingerprint"]:
        raise ValueError("Pairing fingerprint verification failed.")

    return data
