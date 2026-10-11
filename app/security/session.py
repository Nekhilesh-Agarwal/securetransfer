import secrets
from dataclasses import dataclass


@dataclass
class SecureSession:
    session_id: str
    session_key: bytes
    send_sequence: int = 0
    receive_sequence: int = 0


def create_session(
    session_key: bytes,
    session_id: str | None = None,
) -> SecureSession:
    """Create a new secure communication session."""
    if len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes.")

    if session_id is None:
        session_id = secrets.token_urlsafe(32)

    return SecureSession(
        session_id=session_id,
        session_key=session_key,
    )
