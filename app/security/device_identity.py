from pathlib import Path
import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from app.storage_paths import data_path


KEY_DIRECTORY = data_path("keys")
PRIVATE_KEY_FILE = KEY_DIRECTORY / "device_private.key"
PUBLIC_KEY_FILE = KEY_DIRECTORY / "device_public.key"


def generate_device_identity() -> None:
    """Generate and persist an X25519 device key pair."""
    KEY_DIRECTORY.mkdir(exist_ok=True)

    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists():
        return

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    PRIVATE_KEY_FILE.write_bytes(private_bytes)
    PUBLIC_KEY_FILE.write_bytes(public_bytes)


def load_private_key() -> X25519PrivateKey:
    """Load the device's X25519 private key."""
    private_bytes = PRIVATE_KEY_FILE.read_bytes()

    return X25519PrivateKey.from_private_bytes(private_bytes)


def load_public_key() -> bytes:
    """Load the device's X25519 public key."""
    return PUBLIC_KEY_FILE.read_bytes()


def get_public_key_fingerprint() -> str:
    """Return a SHA-256 fingerprint of the device public key."""
    public_key = load_public_key()
    digest = hashlib.sha256(public_key).hexdigest()

    return ":".join(
        digest[i : i + 2]
        for i in range(0, len(digest), 2)
    )


def get_public_key_base64() -> str:
    """Return the public key as Base64 for pairing payloads."""
    return base64.b64encode(load_public_key()).decode("ascii")
