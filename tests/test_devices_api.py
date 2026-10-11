from fastapi.testclient import TestClient

from app.main import app
from tests.test_messages_api import _auth_headers


client = TestClient(app)


def test_pairing_payload_is_public():
    response = client.get("/devices/pairing")
    assert response.status_code == 200
    body = response.json()
    assert body["payload"]
    assert body["fingerprint"]
    assert body["public_key"]


def test_pairing_qr_png_is_public():
    response = client.get("/devices/pairing/qr")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content[:8] == b"\x89PNG\r\n\x1a\n"


def test_confirm_pairing_requires_auth():
    response = client.post(
        "/devices/pairing/confirm",
        json={"payload": "{}", "fingerprint": "aa"},
    )
    assert response.status_code == 401


def test_trusted_devices_list():
    headers = _auth_headers()
    response = client.get("/devices/trusted", headers=headers)
    assert response.status_code == 200
    assert "devices" in response.json()
