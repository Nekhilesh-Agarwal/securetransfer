import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    register = client.post(
        "/auth/register",
        json={"username": username, "password": password},
    )
    assert register.status_code == 200
    login = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
