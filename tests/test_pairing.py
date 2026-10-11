import json

import pytest

from app.security.pairing import (
    create_pairing_payload,
    parse_pairing_payload,
    verify_pairing_payload,
)


def test_pairing_payload_round_trip():
    payload = create_pairing_payload()

    data = parse_pairing_payload(payload)

    assert data["version"] == 1
    assert data["device"]
    assert "public_key" in data
    assert "fingerprint" in data


def test_pairing_fingerprint_verification():
    payload = create_pairing_payload()

    data = verify_pairing_payload(payload)

    assert data["device"]


def test_pairing_rejects_tampered_fingerprint():
    payload = create_pairing_payload()

    data = json.loads(payload)
    data["fingerprint"] = "00:" * 31 + "00"

    tampered_payload = json.dumps(data)

    with pytest.raises(ValueError, match="fingerprint"):
        verify_pairing_payload(tampered_payload)


def test_pairing_rejects_invalid_public_key():
    payload = create_pairing_payload()

    data = json.loads(payload)
    data["public_key"] = "invalid"

    tampered_payload = json.dumps(data)

    with pytest.raises(ValueError):
        verify_pairing_payload(tampered_payload)