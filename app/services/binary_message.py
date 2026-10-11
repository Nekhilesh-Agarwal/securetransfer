from dataclasses import dataclass

from app.security.encryption import decrypt_data, encrypt_data
from app.security.session import SecureSession


@dataclass
class EncryptedBinaryMessage:
    session_id: str
    sequence_number: int
    message_type: str
    nonce: bytes
    ciphertext: bytes
    filename: str | None = None
    mime_type: str | None = None
    file_size: int | None = None


def _build_associated_data(
    session_id: str,
    sequence_number: int,
    message_type: str,
    filename: str | None = None,
    mime_type: str | None = None,
    file_size: int | None = None,
) -> bytes:
    """Build authenticated metadata for a binary message."""

    return (
        f"{session_id}:"
        f"{sequence_number}:"
        f"{message_type}:"
        f"{filename or ''}:"
        f"{mime_type or ''}:"
        f"{file_size if file_size is not None else ''}"
    ).encode("utf-8")


def encrypt_binary_message(
    session: SecureSession,
    data: bytes,
    message_type: str,
    filename: str | None = None,
    mime_type: str | None = None,
) -> EncryptedBinaryMessage:
    """Encrypt arbitrary binary data using the secure session."""

    if not data:
        raise ValueError(
            "Binary message cannot be empty."
        )

    if not message_type:
        raise ValueError(
            "Message type is required."
        )

    if filename is not None and not filename:
        raise ValueError(
            "Filename cannot be empty."
        )

    if mime_type is not None and not mime_type:
        raise ValueError(
            "MIME type cannot be empty."
        )

    file_size = len(data)

    sequence_number = session.send_sequence

    associated_data = _build_associated_data(
        session.session_id,
        sequence_number,
        message_type,
        filename,
        mime_type,
        file_size,
    )

    ciphertext, nonce = encrypt_data(
        data,
        session.session_key,
        associated_data,
    )

    session.send_sequence += 1

    return EncryptedBinaryMessage(
        session_id=session.session_id,
        sequence_number=sequence_number,
        message_type=message_type,
        nonce=nonce,
        ciphertext=ciphertext,
        filename=filename,
        mime_type=mime_type,
        file_size=file_size,
    )


def decrypt_binary_message(
    session: SecureSession,
    message: EncryptedBinaryMessage,
) -> bytes:
    """Decrypt and authenticate a binary message."""

    if message.session_id != session.session_id:
        raise ValueError(
            "Message belongs to a different session."
        )

    if message.sequence_number != session.receive_sequence:
        if message.sequence_number < session.receive_sequence:
            raise ValueError(
                "Replay detected."
            )

        raise ValueError(
            "Message received out of order."
        )

    if (
        message.file_size is not None
        and message.file_size < 0
    ):
        raise ValueError(
            "File size cannot be negative."
        )

    associated_data = _build_associated_data(
        message.session_id,
        message.sequence_number,
        message.message_type,
        message.filename,
        message.mime_type,
        message.file_size,
    )

    plaintext = decrypt_data(
        message.ciphertext,
        message.nonce,
        session.session_key,
        associated_data,
    )

    if (
        message.file_size is not None
        and len(plaintext) != message.file_size
    ):
        raise ValueError(
            "Binary message size does not match metadata."
        )

    session.receive_sequence = (
        message.sequence_number + 1
    )

    return plaintext