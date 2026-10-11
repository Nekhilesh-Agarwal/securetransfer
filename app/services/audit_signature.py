"""Server signatures for immutable message-audit metadata."""

import base64
import binascii
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.storage_paths import data_path


PRIVATE_KEY_PATH = data_path("keys", "audit_signing_private.key")


def _load_or_create_private_key() -> Ed25519PrivateKey:
    PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists():
        return Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY_PATH.read_bytes())

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    PRIVATE_KEY_PATH.write_bytes(private_bytes)
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
    except OSError:
        pass
    return private_key


def canonical_audit_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_audit_payload(payload: dict) -> str:
    """Sign canonical audit metadata; this is a server attestation, not a client signature."""
    return base64.b64encode(_load_or_create_private_key().sign(canonical_audit_bytes(payload))).decode("ascii")


def get_audit_signing_public_key() -> str:
    public_bytes = _load_or_create_private_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("ascii")


def verify_audit_signature(payload: dict, signature: str | None) -> bool:
    """Verify an audit attestation with the public half of the server key."""
    if not signature:
        return False
    try:
        public_key = _load_or_create_private_key().public_key()
        public_key.verify(
            base64.b64decode(signature, validate=True),
            canonical_audit_bytes(payload),
        )
    except (InvalidSignature, binascii.Error, ValueError, TypeError):
        return False
    return True
