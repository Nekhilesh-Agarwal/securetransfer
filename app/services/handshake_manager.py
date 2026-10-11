from dataclasses import dataclass, field
from time import monotonic

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

HANDSHAKE_TTL_SECONDS = 120


@dataclass
class PendingHandshake:
    session_id: str
    peer_static_public_key: bytes
    local_ephemeral_private_key: X25519PrivateKey
    created_at: float = field(default_factory=monotonic)


class HandshakeManager:
    """Store short-lived handshake state in memory."""

    def __init__(self, ttl_seconds: int = HANDSHAKE_TTL_SECONDS):
        self._pending: dict[str, PendingHandshake] = {}
        self.ttl_seconds = ttl_seconds

    def _expire(self) -> None:
        now = monotonic()
        expired = [
            session_id
            for session_id, handshake in self._pending.items()
            if now - handshake.created_at > self.ttl_seconds
        ]
        for session_id in expired:
            self._pending.pop(session_id, None)

    def add(self, handshake: PendingHandshake) -> None:
        self._expire()
        self._pending[handshake.session_id] = handshake

    def get(self, session_id: str) -> PendingHandshake | None:
        self._expire()
        return self._pending.get(session_id)

    def remove(self, session_id: str) -> PendingHandshake | None:
        self._expire()
        return self._pending.pop(session_id, None)


handshake_manager = HandshakeManager()
