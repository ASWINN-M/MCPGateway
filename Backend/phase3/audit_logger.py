"""Phase 3 — append-only audit trail of authorization decisions (no secrets)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

_PROJECT = Path(__file__).resolve().parents[2]
_AUDIT_DIR = _PROJECT / "results" / "audit"
_AUDIT_FILE = _AUDIT_DIR / "tool_decisions.jsonl"


def log_decision(
    *,
    user_id: str,
    department: str | None,
    tool_name: str,
    status: str,
    session_id: str,
    reason: str = "",
    arguments_keys: list[str] | None = None,
) -> dict:
    record = {
        "user_id": user_id,
        "department": department,
        "tool_name": tool_name,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "reason": reason[:300],
        "argument_keys": list(arguments_keys or []),
    }
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    with _AUDIT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return record


def recent_decisions(limit: int = 200) -> list[dict]:
    if not _AUDIT_FILE.is_file():
        return []
    lines = _AUDIT_FILE.read_text(encoding="utf-8").splitlines()
    out: list[dict] = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out
