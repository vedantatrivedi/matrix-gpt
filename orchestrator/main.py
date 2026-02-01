import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent
if str(PARENT) not in sys.path:
    sys.path.insert(0, str(PARENT))

from orchestrator.battle_manager import BattleManager
from orchestrator.db import (
    get_battle,
    get_events,
    init_db,
    list_battles,
    list_vulnerabilities,
    mark_battle_status,
)

load_dotenv()

app = FastAPI()

FRONTEND_PATH = Path(__file__).parent / "frontend" / "index.html"
TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:8001")


class WebSocketManager:
    def __init__(self) -> None:
        self._connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        async with self._lock:
            stale = []
            for ws in self._connections:
                try:
                    await ws.send_json(message)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                self._connections.remove(ws)


ws_manager = WebSocketManager()


async def event_sink(message: Dict[str, Any]) -> None:
    await ws_manager.broadcast(message)


battle_manager = BattleManager(event_sink)


def _reconcile_running_battles(active_id: str | None) -> None:
    for battle in list_battles(limit=50):
        if battle.get("status") != "running":
            continue
        if active_id and battle.get("id") == active_id:
            continue
        mark_battle_status(battle["id"], "stopped")


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    if FRONTEND_PATH.exists():
        return HTMLResponse(FRONTEND_PATH.read_text())
    return HTMLResponse("<h1>MatrixGPT</h1><p>Frontend not found.</p>")


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    await ws.send_json(
        {
            "type": "system",
            "team": "system",
            "agent": "WebSocket",
            "timestamp": datetime.utcnow().isoformat(),
            "data": {"message": "WebSocket connected"},
        }
    )
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)


@app.post("/api/battle/start")
async def start_battle(mode: str = "live"):
    if mode == "mock":
        os.environ["MOCK_MODE"] = "true"
    else:
        os.environ["MOCK_MODE"] = "false"
    battle_id = await battle_manager.start_battle(TARGET_URL)
    return {
        "battle_id": battle_id,
        "target_url": TARGET_URL,
        "vulnerabilities": list_vulnerabilities(battle_id),
    }


@app.post("/api/battle/stop")
async def stop_battle():
    await battle_manager.stop_battle("stopped")
    return {"status": "stopped"}


@app.post("/api/battle/force-stop")
async def force_stop_battle(battle_id: str):
    if battle_manager.battle_id == battle_id:
        await battle_manager.stop_battle("stopped")
        return {"status": "stopped"}
    mark_battle_status(battle_id, "stopped")
    return {"status": "stopped"}


@app.get("/api/battle/status")
async def battle_status():
    battle_id = battle_manager.battle_id
    _reconcile_running_battles(battle_id)
    if not battle_id:
        return {"status": "idle"}
    return {
        "status": "running",
        "battle": get_battle(battle_id),
        "vulnerabilities": list_vulnerabilities(battle_id),
    }


@app.get("/api/battles")
async def battles(limit: int = 20):
    _reconcile_running_battles(battle_manager.battle_id)
    return {"battles": list_battles(limit=limit)}


@app.get("/api/battle/events")
async def battle_events(battle_id: str, limit: int = 200):
    return {"events": get_events(battle_id, limit=limit)}
