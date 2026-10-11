from dataclasses import dataclass

from app.security.encryption import decrypt_data, encrypt_data
from app.security.session import SecureSession


@dataclass
class EncryptedMessage:
    session_id: str
    sequence_number: int
    message_type: str
    nonce: bytes
    ciphertext: bytes


def _build_associated_data(
    session_id: str,
    sequence_number: int,
    message_type: str,
) -> bytes:
    """Build authenticated metadata for an encrypted message."""
    return (
        f"{session_id}:{sequence_number}:{message_type}"
    ).encode("utf-8")


def encrypt_message(
    session: SecureSession,
    plaintext: bytes,
    message_type: str = "text",
) -> EncryptedMessage:
    """Encrypt a message and advance the send sequence number."""
    sequence_number = session.send_sequence

    associated_data = _build_associated_data(
        session.session_id,
        sequence_number,
        message_type,
    )

    ciphertext, nonce = encrypt_data(
        plaintext,
        session.session_key,
        associated_data,
    )

    session.send_sequence += 1

    return EncryptedMessage(
        session_id=session.session_id,
        sequence_number=sequence_number,
        message_type=message_type,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def decrypt_message(
    session: SecureSession,
    message: EncryptedMessage,
) -> bytes:
    """Decrypt and authenticate a message."""
    if message.session_id != session.session_id:
        raise ValueError("Message belongs to a different session.")

    if message.sequence_number != session.receive_sequence:
        if message.sequence_number < session.receive_sequence:
            raise ValueError("Replay detected.")

        raise ValueError("Message received out of order.")

    associated_data = _build_associated_data(
        message.session_id,
        message.sequence_number,
        message.message_type,
    )

    plaintext = decrypt_data(
        message.ciphertext,
        message.nonce,
        session.session_key,
        associated_data,
    )

    session.receive_sequence = message.sequence_number + 1

    return plaintext