import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

DB_PATH = Path(__file__).parent / "matrixGPT.db"


VULN_LIST = [
    (1, "SQL Injection", "/api/products"),
    (2, "Stored XSS", "/api/reviews"),
    (3, "Broken Authentication (JWT bypass)", "/api/admin/*"),
    (4, "IDOR", "/api/orders/:id"),
    (5, "Unrestricted File Upload", "/api/users/avatar"),
    (6, "SSRF", "/api/image-proxy"),
    (7, "Hardcoded Credentials", "database.py"),
    (8, "No Rate Limit", "/api/auth/login"),
    (9, "Information Disclosure", "all error responses"),
    (10, "CSRF", "/api/orders"),
]


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS battles (
            id TEXT PRIMARY KEY,
            started_at TIMESTAMP,
            ended_at TIMESTAMP,
            status TEXT,
            red_score INTEGER DEFAULT 0,
            blue_score INTEGER DEFAULT 0,
            target_url TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            battle_id TEXT,
            timestamp TIMESTAMP,
            event_type TEXT,
            team TEXT,
            agent_name TEXT,
            description TEXT,
            details JSON,
            score_delta INTEGER DEFAULT 0
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            battle_id TEXT,
            name TEXT,
            endpoint TEXT,
            status TEXT DEFAULT 'unknown',
            found_at TIMESTAMP,
            exploited_at TIMESTAMP,
            patched_at TIMESTAMP,
            patch_diff TEXT
        );
        """
    )
    conn.commit()
    conn.close()


def create_battle(target_url: str) -> str:
    battle_id = str(uuid4())
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO battles (id, started_at, status, target_url) VALUES (?, ?, ?, ?)",
        (battle_id, datetime.utcnow().isoformat(), "running", target_url),
    )
    conn.commit()
    conn.close()
    init_vulnerabilities(battle_id)
    return battle_id


def end_battle(battle_id: str, status: str) -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE battles SET ended_at = ?, status = ? WHERE id = ?",
        (datetime.utcnow().isoformat(), status, battle_id),
    )
    conn.commit()
    conn.close()


def mark_battle_status(battle_id: str, status: str) -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE battles SET status = ?, ended_at = COALESCE(ended_at, ?) WHERE id = ?",
        (status, datetime.utcnow().isoformat(), battle_id),
    )
    conn.commit()
    conn.close()


def init_vulnerabilities(battle_id: str) -> None:
    limit_raw = os.environ.get("VULN_LIMIT")
    limit = int(limit_raw) if limit_raw else None
    vuln_list = VULN_LIST[:limit] if limit else VULN_LIST
    conn = get_conn()
    cur = conn.cursor()
    for vuln_id, name, endpoint in vuln_list:
        cur.execute(
            "INSERT OR IGNORE INTO vulnerabilities (id, battle_id, name, endpoint, status) VALUES (?, ?, ?, ?, 'unknown')",
            (vuln_id, battle_id, name, endpoint),
        )
    conn.commit()
    conn.close()


def insert_event(
    battle_id: str,
    event_type: str,
    team: str,
    agent_name: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
    score_delta: int = 0,
) -> str:
    event_id = str(uuid4())
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events (id, battle_id, timestamp, event_type, team, agent_name, description, details, score_delta)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            battle_id,
            datetime.utcnow().isoformat(),
            event_type,
            team,
            agent_name,
            description,
            json.dumps(details or {}),
            score_delta,
        ),
    )
    conn.commit()
    conn.close()
    return event_id


def update_scores(battle_id: str, red_delta: int = 0, blue_delta: int = 0) -> Dict[str, int]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE battles SET red_score = red_score + ?, blue_score = blue_score + ? WHERE id = ?",
        (red_delta, blue_delta, battle_id),
    )
    conn.commit()
    cur.execute("SELECT red_score, blue_score FROM battles WHERE id = ?", (battle_id,))
    row = cur.fetchone()
    conn.close()
    return {"red_score": row["red_score"], "blue_score": row["blue_score"]}


def update_vuln_status(
    battle_id: str,
    name: str,
    status: str,
    patch_diff: Optional[str] = None,
) -> None:
    field_map = {
        "found": "found_at",
        "exploited": "exploited_at",
        "patched": "patched_at",
    }
    ts_field = field_map.get(status)
    conn = get_conn()
    cur = conn.cursor()
    if ts_field:
        cur.execute(
            f"UPDATE vulnerabilities SET status = ?, {ts_field} = ?, patch_diff = COALESCE(?, patch_diff) WHERE battle_id = ? AND name = ?",
            (status, datetime.utcnow().isoformat(), patch_diff, battle_id, name),
        )
    else:
        cur.execute(
            "UPDATE vulnerabilities SET status = ? WHERE battle_id = ? AND name = ?",
            (status, battle_id, name),
        )
    conn.commit()
    conn.close()


def get_battle(battle_id: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM battles WHERE id = ?", (battle_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def list_battles(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM battles ORDER BY started_at DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_events(battle_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM events WHERE battle_id = ? ORDER BY timestamp ASC LIMIT ?",
        (battle_id, limit),
    )
    rows = cur.fetchall()
    conn.close()
    events = []
    for r in rows:
        item = dict(r)
        try:
            item["details"] = json.loads(item.get("details") or "{}")
        except json.JSONDecodeError:
            item["details"] = {}
        events.append(item)
    return events


def list_vulnerabilities(battle_id: str) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vulnerabilities WHERE battle_id = ? ORDER BY id ASC", (battle_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
