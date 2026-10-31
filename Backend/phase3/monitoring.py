"""Phase 3 — monitoring facade used by the gateway after each decision."""

from __future__ import annotations

from .anomaly_detector import detect_repeated_unauthorized
from .audit_logger import log_decision


def record_and_monitor(
    *,
    user_id: str,
    department: str | None,
    tool_name: str,
    status: str,
    session_id: str,
    reason: str = "",
    arguments: dict | None = None,
) -> dict:
    keys = sorted((arguments or {}).keys())
    record = log_decision(
        user_id=user_id,
        department=department,
        tool_name=tool_name,
        status=status,
        session_id=session_id,
        reason=reason,
        arguments_keys=keys,
    )
    alert = None
    if status.upper() == "DENIED" and session_id:
        alert = detect_repeated_unauthorized(session_id=session_id)
    return {"record": record, "alert": alert}
