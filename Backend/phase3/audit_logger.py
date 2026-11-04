"""Phase 3 — append-only audit trail of authorization decisions (no secrets)."""

from __future__ import annotations

from datetime import datetime, timezone

from .audit_store import append_decision, recent_decisions as _store_recent


def log_decision(
    *,
    user_id: str,
    department: str | None,
    tool_name: str,
    status: str,
    session_id: str,
    reason: str = "",
    arguments_keys: list[str] | None = None,
    sensitive: bool = False,
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
    return append_decision(record, sensitive=sensitive)


def recent_decisions(limit: int = 200) -> list[dict]:
    return _store_recent(limit)
