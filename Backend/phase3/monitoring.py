"""Phase 3 — monitoring facade used by the gateway after each decision."""

from __future__ import annotations

from .anomaly_detector import analyze_session
from .audit_logger import log_decision
from .audit_store import append_anomaly

_SENSITIVE = frozenset(
    {
        "send_email",
        "create_calendar_event",
        "db_insert",
        "file_write_sandbox",
        "slack_post_message",
        "payment_transfer",
        "fetch_finance_records",
        "run_shell",
        "run_shell_command",
        "run_command",
        "export_secrets",
        "export_env_secrets",
        "dump_env",
        "render_template",
        "admin_grant_role",
    }
)


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
        sensitive=tool_name in _SENSITIVE,
    )

    anomaly = None
    alert = None
    if session_id:
        anomaly = analyze_session(
            session_id=session_id,
            user_id=user_id,
            department=department,
        )
        # Persist only when something is noteworthy (anomaly or medium+ risk).
        if anomaly.get("is_anomaly") or anomaly.get("risk_level") in {"medium", "high", "critical"}:
            append_anomaly(anomaly)
        if anomaly.get("is_anomaly") or anomaly.get("risk_level") != "low":
            alert = {
                "alert": True,
                "type": "phase3_anomaly",
                "risk_level": anomaly.get("risk_level"),
                "risk_score": anomaly.get("risk_score"),
                "recommended_action": anomaly.get("recommended_action"),
                "message": anomaly.get("message"),
                "features": anomaly.get("features"),
                "algorithm": anomaly.get("algorithm"),
            }
            # Keep legacy shape for repeated-deny message consumers.
            if anomaly.get("rule_alert"):
                alert["rule_alert"] = anomaly["rule_alert"]

    return {"record": record, "alert": alert, "anomaly": anomaly}
