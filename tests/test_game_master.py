import types

import asyncio

from orchestrator.agents import game_master


class DummyResult:
    def __init__(self, output):
        self.final_output = output


def test_score_exploit_success(monkeypatch):
    async def fake_run(agent, input=None):
        return DummyResult('{"score_change": 100, "team": "red", "reason": "exploit", "allowed": true}')

    monkeypatch.setattr(game_master.Runner, "run", fake_run)
    result = asyncio.run(game_master.score_event("exploit success"))
    assert result["score_change"] == 100
    assert result["team"] == "red"


def test_score_patch_applied(monkeypatch):
    async def fake_run(agent, input=None):
        return DummyResult('{"score_change": 150, "team": "blue", "reason": "patch", "allowed": true}')

    monkeypatch.setattr(game_master.Runner, "run", fake_run)
    result = asyncio.run(game_master.score_event("patch applied"))
    assert result["score_change"] == 150
    assert result["team"] == "blue"


def test_safety_rule_data_deletion(monkeypatch):
    async def fake_run(agent, input=None):
        return DummyResult('{"score_change": 0, "team": "red", "reason": "blocked", "allowed": false}')

    monkeypatch.setattr(game_master.Runner, "run", fake_run)
    result = asyncio.run(game_master.score_event("delete database"))
    assert result["allowed"] is False


def test_safety_rule_external_url(monkeypatch):
    async def fake_run(agent, input=None):
        return DummyResult('{"score_change": 0, "team": "red", "reason": "blocked", "allowed": false}')

    monkeypatch.setattr(game_master.Runner, "run", fake_run)
    result = asyncio.run(game_master.score_event("request http://example.com"))
    assert result["allowed"] is False
