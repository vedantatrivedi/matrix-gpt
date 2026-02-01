import asyncio
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from orchestrator import db
from orchestrator import battle_manager
from orchestrator.battle_manager import BattleManager
from orchestrator import main


class DummyStream:
    def __init__(self, final_output="ok"):
        self.final_output = final_output

    async def stream_events(self):
        if False:
            yield None


def _dummy_run_streamed(agent, input=None):
    return DummyStream(final_output="SQL Injection exploited")


def test_battle_creates_and_records(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "matrixGPT.db")
    db.init_db()

    events = []

    async def sink(msg):
        events.append(msg)

    monkeypatch.setattr(battle_manager.Runner, "run_streamed", _dummy_run_streamed)

    async def fake_score_event(desc):
        return {"score_change": 0, "team": "red", "reason": "", "allowed": True}

    monkeypatch.setattr(battle_manager, "score_event", fake_score_event)

    async def run_flow():
        manager = BattleManager(sink)
        await manager.start_battle("http://localhost:8001")
        await asyncio.sleep(0.2)
        await manager.stop_battle("stopped")

    asyncio.run(run_flow())

    conn = db.get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM events")
    count = cur.fetchone()["c"]
    conn.close()
    assert count >= 1


def test_websocket_receives_events(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "matrixGPT.db")
    db.init_db()

    async def fake_start_battle(target_url):
        await main.ws_manager.broadcast(
            {
                "type": "battle_start",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"battle_id": "test", "target_url": target_url},
            }
        )
        return "test"

    monkeypatch.setattr(main.battle_manager, "start_battle", fake_start_battle)

    client = TestClient(main.app)
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        client.post("/api/battle/start")
        msg = ws.receive_json()
        assert msg["type"] == "battle_start"


def test_battle_stops_after_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "matrixGPT.db")
    db.init_db()

    async def sink(msg):
        pass

    monkeypatch.setattr(battle_manager.Runner, "run_streamed", _dummy_run_streamed)

    async def fake_score_event(desc):
        return {"score_change": 0, "team": "red", "reason": "", "allowed": True}

    monkeypatch.setattr(battle_manager, "score_event", fake_score_event)

    async def run_flow():
        manager = BattleManager(sink)
        await manager.start_battle("http://localhost:8001")
        manager._start_time = datetime.utcnow() - timedelta(minutes=11)
        await asyncio.sleep(0.1)
        await manager._red_loop()
        return manager

    manager = asyncio.run(run_flow())
    assert manager.battle_id is None
