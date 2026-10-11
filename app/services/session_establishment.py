from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from app.security.key_exchange import (
    deserialize_public_key,
    derive_session_key,
    derive_shared_secret,
    generate_key_pair,
    serialize_public_key,
)
from app.security.session import SecureSession, create_session


def generate_ephemeral_key_pair() -> tuple[
    X25519PrivateKey,
    bytes,
]:
    """Generate an ephemeral X25519 key pair for session establishment."""
    private_key, public_key = generate_key_pair()

    return private_key, serialize_public_key(public_key)


def establish_session(
    private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
    session_id: str,
    salt: bytes | None = None,
) -> SecureSession:
    """
    Establish a secure session using ephemeral X25519 and HKDF.

    This function is retained for the existing low-level session tests.
    """
    peer_public_key = deserialize_public_key(peer_public_key_bytes)

    shared_secret = derive_shared_secret(
        private_key,
        peer_public_key,
    )

    session_key = derive_session_key(
        shared_secret,
        salt,
    )

    return create_session(
        session_key,
        session_id=session_id,
    )


def establish_authenticated_session(
    local_static_private_key: X25519PrivateKey,
    peer_static_public_key_bytes: bytes,
    local_ephemeral_private_key: X25519PrivateKey,
    peer_ephemeral_public_key_bytes: bytes,
    session_id: str,
    salt: bytes | None = None,
) -> SecureSession:
    """
    Establish an authenticated session using static and ephemeral X25519 keys.

    The static device key represents the already-paired device identity.
    The ephemeral keys provide fresh session material.

    Both peers derive the same key from:
      1. ephemeral-local <-> static-peer
      2. static-local <-> ephemeral-peer
      3. ephemeral-local <-> ephemeral-peer

    The first two shared secrets are sorted before combination so that
    both sides construct the same input regardless of which side is
    performing the calculation.
    """
    peer_static_public_key = deserialize_public_key(
        peer_static_public_key_bytes
    )

    peer_ephemeral_public_key = deserialize_public_key(
        peer_ephemeral_public_key_bytes
    )

    ephemeral_static_secret = derive_shared_secret(
        local_ephemeral_private_key,
        peer_static_public_key,
    )

    static_ephemeral_secret = derive_shared_secret(
        local_static_private_key,
        peer_ephemeral_public_key,
    )

    ephemeral_ephemeral_secret = derive_shared_secret(
        local_ephemeral_private_key,
        peer_ephemeral_public_key,
    )

    first, second = sorted(
        (
            ephemeral_static_secret,
            static_ephemeral_secret,
        )
    )

    combined_secret = (
        first
        + second
        + ephemeral_ephemeral_secret
    )

    session_key = derive_session_key(
        combined_secret,
        salt,
    )

    return create_session(
        session_key,
        session_id=session_id,
    )
