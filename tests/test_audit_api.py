from fastapi.testclient import TestClient

from app.main import app
from tests.test_messages_api import _auth_headers


client = TestClient(app)


def test_audit_verify_requires_auth():
    response = client.get("/audit/verify")
    assert response.status_code == 401


def test_audit_verify_and_events():
    headers = _auth_headers()
    verify = client.get("/audit/verify", headers=headers)
    assert verify.status_code == 200
    assert verify.json()["valid"] is True

    events = client.get("/audit/events", headers=headers)
    assert events.status_code == 200
    assert "events" in events.json()


def test_security_dashboard():
    headers = _auth_headers()
    response = client.get("/security/dashboard", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert "fingerprint" in body["device"]
    assert "monitor" in body
    assert "trusted_devices" in body
