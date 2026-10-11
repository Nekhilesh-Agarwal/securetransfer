from app.security.session import create_session
from app.services.handshake_manager import HandshakeManager, PendingHandshake
from app.services.session_establishment import generate_ephemeral_key_pair
from app.services.session_manager import SessionManager


def test_add_and_get_session():
    manager = SessionManager()
    session = create_session(b"a" * 32, session_id="test-session")

    manager.add_session(session)

    assert manager.has_session("test-session")
    assert manager.get_session("test-session") is session


def test_remove_session():
    manager = SessionManager()
    session = create_session(b"a" * 32, session_id="test-session")

    manager.add_session(session)
    manager.remove_session("test-session")

    assert not manager.has_session("test-session")
    assert manager.get_session("test-session") is None


def test_get_missing_session():
    manager = SessionManager()

    assert manager.get_session("missing-session") is None
    assert not manager.has_session("missing-session")


def test_pending_handshake_expires():
    manager = HandshakeManager(ttl_seconds=0)
    private_key, _ = generate_ephemeral_key_pair()
    manager.add(
        PendingHandshake(
            session_id="expired-handshake",
            peer_static_public_key=b"x" * 32,
            local_ephemeral_private_key=private_key,
            created_at=0,
        )
    )

    assert manager.get("expired-handshake") is None