"""Phase 3 — detect repeated unauthorized tool attempts."""

from __future__ import annotations

from .audit_logger import recent_decisions

# Threshold: N DENY events for the same session within the recent window.
DEFAULT_DENY_THRESHOLD = 3


def detect_repeated_unauthorized(
    *,
    session_id: str,
    threshold: int = DEFAULT_DENY_THRESHOLD,
) -> dict | None:
    denies = [
        row
        for row in recent_decisions(300)
        if row.get("session_id") == session_id and str(row.get("status", "")).upper() == "DENIED"
    ]
    if len(denies) < threshold:
        return None
    tools = sorted({str(row.get("tool_name")) for row in denies[-threshold:]})
    return {
        "alert": True,
        "type": "repeated_unauthorized_tools",
        "session_id": session_id,
        "deny_count": len(denies),
        "recent_tools": tools,
        "message": (
            f"ALERT: session {session_id[:12]}… has {len(denies)} DENIED tool attempts "
            f"(recent tools: {', '.join(tools)}). Notify authorities / consider revoke."
        ),
    }
