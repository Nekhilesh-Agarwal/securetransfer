from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_key_pair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an X25519 private/public key pair."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def serialize_public_key(public_key: X25519PublicKey) -> bytes:
    """Serialize an X25519 public key to raw bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_public_key(public_key_bytes: bytes) -> X25519PublicKey:
    """Reconstruct an X25519 public key from raw bytes."""
    return X25519PublicKey.from_public_bytes(public_key_bytes)


def derive_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """Perform X25519 key agreement."""
    return private_key.exchange(peer_public_key)


def derive_session_key(
    shared_secret: bytes,
    salt: bytes | None = None,
) -> bytes:
    """Derive a 256-bit session key using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"SentinelDrop session key",
    ).derive(shared_secret)
