import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12
KEY_SIZE = 32


def encrypt_data(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM.

    Returns:
        ciphertext: encrypted data including the GCM authentication tag
        nonce: unique nonce used for this encryption
    """
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        associated_data,
    )

    return ciphertext, nonce


def decrypt_data(
    ciphertext: bytes,
    nonce: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate AES-256-GCM encrypted data."""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be 12 bytes.")

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        associated_data,
    )
