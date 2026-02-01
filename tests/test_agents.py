import types

import pytest

from orchestrator.agents import tools as agent_tools


class DummyResponse:
    def __init__(self, status_code=200, text="ok", headers=None, json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self._json = json_data

    def json(self):
        return self._json


def test_http_get(monkeypatch):
    def fake_get(url, params=None, headers=None, timeout=5.0):
        return DummyResponse(status_code=200, text="hello", headers={"x": "y"})

    monkeypatch.setattr(agent_tools.httpx, "get", fake_get)
    resp = agent_tools._http_get_impl("http://example.com")
    assert resp["status_code"] == 200
    assert "hello" in resp["body"]


def test_http_post(monkeypatch):
    captured = {}

    def fake_post(url, data=None, json=None, headers=None, files=None, timeout=5.0):
        captured["url"] = url
        captured["data"] = data
        captured["json"] = json
        captured["files"] = files
        return DummyResponse(status_code=201, text="created")

    monkeypatch.setattr(agent_tools.httpx, "post", fake_post)
    resp = agent_tools._http_post_impl("http://example.com", json_body_json='{\"a\": 1}')
    assert resp["status_code"] == 201
    assert captured["json"] == {"a": 1}


def test_get_recent_logs(monkeypatch):
    def fake_get(url, params=None, timeout=5.0):
        return DummyResponse(json_data={"logs": [{"path": "/api"}]})

    monkeypatch.setattr(agent_tools.httpx, "get", fake_get)
    resp = agent_tools._get_recent_logs_impl("2024-01-01T00:00:00")
    assert resp["logs"][0]["path"] == "/api"


def test_get_source_file(monkeypatch):
    def fake_get(url, params=None, timeout=5.0):
        return DummyResponse(json_data={"filename": "app.py", "content": "print('hi')"})

    monkeypatch.setattr(agent_tools.httpx, "get", fake_get)
    resp = agent_tools._get_source_file_impl("app.py")
    assert "print" in resp["content"]


def test_apply_patch(monkeypatch):
    def fake_get_source_file(filename):
        return {"filename": filename, "content": "a\nb\n"}

    captured = {}

    def fake_post(url, json=None, timeout=5.0):
        captured["json"] = json
        return DummyResponse(status_code=200, text="ok")

    diff = """--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n-a\n-b\n+a\n+c\n"""
    monkeypatch.setattr(agent_tools, "_get_source_file_impl", fake_get_source_file)
    monkeypatch.setattr(agent_tools.httpx, "post", fake_post)
    resp = agent_tools._apply_patch_impl("app.py", diff)
    assert resp["status_code"] == 200
    assert "c" in captured["json"]["content"]
