"""Phase 2 central enforcement: inspect every tool request before execution."""

from __future__ import annotations

from phase1.identity_manager import resolve_identity
from phase3.monitoring import record_and_monitor

from . import _engine


def enforce_tool_request(
    *,
    tool: str,
    fields: dict | None,
    user_email: str,
    execution_token: str = "",
    require_execution_token: bool = False,
) -> str | None:
    """Return None if ALLOW, else a DENY reason string. Logs Phase 3 audit events."""
    fields = fields or {}
    session = _engine.current_session_id()
    identity = resolve_identity(user_email)
    department = identity.get("department") if isinstance(identity, dict) else None

    denied = _engine.caller_auth_error()
    if denied:
        _audit(user_email, department, tool, "DENIED", session, denied, fields)
        return denied

    denied = _engine.authorize_session_tool(user_email, tool, fields)
    if denied:
        result = _audit(user_email, department, tool, "DENIED", session, denied, fields)
        if result.get("alert"):
            return f"{denied}\n{result['alert']['message']}"
        return denied

    denied = _engine.check_execution_lock(tool, fields, session=session)
    if denied:
        result = _audit(user_email, department, tool, "DENIED", session, denied, fields)
        if result.get("alert"):
            return f"{denied}\n{result['alert']['message']}"
        return denied

    denied = _engine.check_volume_limits(tool, fields, session=session)
    if denied:
        result = _audit(user_email, department, tool, "DENIED", session, denied, fields)
        if result.get("alert"):
            return f"{denied}\n{result['alert']['message']}"
        return denied

    if require_execution_token or tool in _engine.HIGH_RISK_TOOLS:
        presented = str(execution_token or "").strip().lower()
        if len(presented) != 64:
            denied = "Blocked: protected action requires an execution token. A plan id is not enough."
            _audit(user_email, department, tool, "DENIED", session, denied, fields)
            return denied
        denied = _engine.verify_execution_token(
            presented,
            user=user_email,
            session=session,
            action=tool,
            fields=fields,
        )
        if denied:
            result = _audit(user_email, department, tool, "DENIED", session, denied, fields)
            if result.get("alert"):
                return f"{denied}\n{result['alert']['message']}"
            return denied

    _audit(user_email, department, tool, "ALLOWED", session, "authorized", fields)
    return None


def _audit(user, department, tool, status, session, reason, fields) -> dict:
    return record_and_monitor(
        user_id=user,
        department=department,
        tool_name=tool,
        status=status,
        session_id=session or "",
        reason=reason,
        arguments=fields,
    )
