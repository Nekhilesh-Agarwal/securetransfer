from app.services.message import decrypt_message, encrypt_message
from app.services.session_establishment import (
    establish_session,
    generate_ephemeral_key_pair,
)


def test_two_devices_establish_same_session_key():
    # Device A generates its ephemeral key pair.
    private_a, public_a = generate_ephemeral_key_pair()

    # Device B generates its ephemeral key pair.
    private_b, public_b = generate_ephemeral_key_pair()

    session_id = "test-session-001"

    # Each device establishes a session using the other device's public key.
    session_a = establish_session(
        private_a,
        public_b,
        session_id,
    )

    session_b = establish_session(
        private_b,
        public_a,
        session_id,
    )

    # Both devices must derive the same session key.
    assert session_a.session_key == session_b.session_key

    # Both devices must use the same session identifier.
    assert session_a.session_id == session_b.session_id


def test_established_session_can_encrypt_and_decrypt():
    # Simulate two devices.
    private_a, public_a = generate_ephemeral_key_pair()
    private_b, public_b = generate_ephemeral_key_pair()

    session_id = "test-session-002"

    session_a = establish_session(
        private_a,
        public_b,
        session_id,
    )

    session_b = establish_session(
        private_b,
        public_a,
        session_id,
    )

    plaintext = b"Hello from Device A"

    encrypted_message = encrypt_message(
        session_a,
        plaintext,
        message_type="text",
    )

    decrypted_message = decrypt_message(
        session_b,
        encrypted_message,
    )

    assert decrypted_message == plaintext


def test_different_peer_key_produces_different_session_key():
    private_a, public_a = generate_ephemeral_key_pair()

    private_b, public_b = generate_ephemeral_key_pair()
    private_c, public_c = generate_ephemeral_key_pair()

    session_id = "test-session-003"

    session_ab = establish_session(
        private_a,
        public_b,
        session_id,
    )

    session_ac = establish_session(
        private_a,
        public_c,
        session_id,
    )

    assert session_ab.session_key != session_ac.session_key