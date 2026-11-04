"""SQLite audit store for Phase 3 decisions and anomaly events.

Keeps JSONL for backwards-compatible streaming reads, and SQLite for
feature queries / anomaly history.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_PROJECT = Path(__file__).resolve().parents[2]
_AUDIT_DIR = _PROJECT / "results" / "audit"
_DB_PATH = _AUDIT_DIR / "phase3.db"
_JSONL_PATH = _AUDIT_DIR / "tool_decisions.jsonl"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  user_id TEXT,
  department TEXT,
  tool_name TEXT,
  status TEXT,
  session_id TEXT,
  reason TEXT,
  argument_keys TEXT,
  sensitive INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS anomaly_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  session_id TEXT,
  user_id TEXT,
  department TEXT,
  risk_level TEXT,
  anomaly_score REAL,
  is_anomaly INTEGER,
  recommended_action TEXT,
  message TEXT,
  features_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_decisions_session ON decisions(session_id);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);
CREATE INDEX IF NOT EXISTS idx_anomaly_ts ON anomaly_events(ts);
"""


def _connect() -> sqlite3.Connection:
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def append_decision(record: dict, *, sensitive: bool = False) -> dict:
    """Persist one decision to SQLite + JSONL. Never stores secrets/bodies."""
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    with _JSONL_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO decisions
              (ts, user_id, department, tool_name, status, session_id, reason, argument_keys, sensitive)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.get("timestamp"),
                record.get("user_id"),
                record.get("department"),
                record.get("tool_name"),
                record.get("status"),
                record.get("session_id"),
                record.get("reason"),
                json.dumps(record.get("argument_keys") or []),
                1 if sensitive else 0,
            ),
        )
        conn.commit()
    return record


def append_anomaly(event: dict) -> dict:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO anomaly_events
              (ts, session_id, user_id, department, risk_level, anomaly_score,
               is_anomaly, recommended_action, message, features_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("timestamp"),
                event.get("session_id"),
                event.get("user_id"),
                event.get("department"),
                event.get("risk_level"),
                event.get("anomaly_score"),
                1 if event.get("is_anomaly") else 0,
                event.get("recommended_action"),
                event.get("message"),
                json.dumps(event.get("features") or {}),
            ),
        )
        conn.commit()
    return event


def recent_decisions(limit: int = 200) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT ts AS timestamp, user_id, department, tool_name, status,
                   session_id, reason, argument_keys, sensitive
            FROM decisions
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    out = []
    for row in reversed(rows):
        item = dict(row)
        try:
            item["argument_keys"] = json.loads(item.get("argument_keys") or "[]")
        except json.JSONDecodeError:
            item["argument_keys"] = []
        out.append(item)
    # Fallback to JSONL if SQLite empty (legacy runs).
    if not out and _JSONL_PATH.is_file():
        lines = _JSONL_PATH.read_text(encoding="utf-8").splitlines()
        for line in lines[-limit:]:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                out.append(item)
    return out


def decisions_for_session(session_id: str, limit: int = 500) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT ts AS timestamp, user_id, department, tool_name, status,
                   session_id, reason, argument_keys, sensitive
            FROM decisions
            WHERE session_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (session_id, int(limit)),
        ).fetchall()
    out = []
    for row in reversed(rows):
        item = dict(row)
        try:
            item["argument_keys"] = json.loads(item.get("argument_keys") or "[]")
        except json.JSONDecodeError:
            item["argument_keys"] = []
        out.append(item)
    return out


def recent_anomalies(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT ts AS timestamp, session_id, user_id, department, risk_level,
                   anomaly_score, is_anomaly, recommended_action, message, features_json
            FROM anomaly_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["features"] = json.loads(item.pop("features_json") or "{}")
        except json.JSONDecodeError:
            item["features"] = {}
            item.pop("features_json", None)
        item["is_anomaly"] = bool(item.get("is_anomaly"))
        out.append(item)
    return out


def all_decisions(limit: int = 5000) -> list[dict]:
    return recent_decisions(limit)
