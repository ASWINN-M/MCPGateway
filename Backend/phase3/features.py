"""Convert tool-decision logs into numerical behavioral features.

Never includes email bodies, passwords, tokens, or document contents.
"""

from __future__ import annotations

from datetime import datetime, timezone

FEATURE_NAMES = [
    "tool_calls_per_minute",
    "failed_authorizations",
    "unique_tools_accessed",
    "department_mismatch_attempts",
    "sensitive_actions",
    "night_hour_calls",
    "session_duration_minutes",
    "allow_count",
    "deny_count",
    "deny_ratio",
]

# Heuristic markers that an authorization deny was dept/resource related.
_MISMATCH_MARKERS = (
    "not permitted",
    "belongs to",
    "restricted to",
    "unknown tool",
    "not on the gateway allowlist",
    "department",
)


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def extract_session_features(rows: list[dict]) -> dict[str, float]:
    """Build one feature vector from a session's recent decisions."""
    if not rows:
        return {name: 0.0 for name in FEATURE_NAMES}

    times = [t for t in (_parse_ts(r.get("timestamp")) for r in rows) if t is not None]
    now = datetime.now(timezone.utc)
    if times:
        span_seconds = max(60.0, (max(times) - min(times)).total_seconds())
        duration_minutes = max(1.0, (now - min(times)).total_seconds() / 60.0)
    else:
        span_seconds = 60.0
        duration_minutes = 1.0

    allow_count = sum(1 for r in rows if str(r.get("status", "")).upper() == "ALLOWED")
    deny_count = sum(1 for r in rows if str(r.get("status", "")).upper() == "DENIED")
    total = max(1, len(rows))
    tools = {str(r.get("tool_name") or "") for r in rows}
    sensitive = sum(
        1
        for r in rows
        if r.get("sensitive")
        or str(r.get("tool_name") or "")
        in {
            "send_email",
            "create_calendar_event",
            "db_insert",
            "file_write_sandbox",
            "slack_post_message",
            "payment_transfer",
        }
    )
    mismatch = 0
    night = 0
    for r in rows:
        reason = str(r.get("reason") or "").lower()
        if any(m in reason for m in _MISMATCH_MARKERS) and str(r.get("status", "")).upper() == "DENIED":
            mismatch += 1
        ts = _parse_ts(r.get("timestamp"))
        if ts is not None and ts.hour < 5:
            night += 1

    calls_per_minute = (len(rows) / span_seconds) * 60.0
    return {
        "tool_calls_per_minute": round(calls_per_minute, 3),
        "failed_authorizations": float(deny_count),
        "unique_tools_accessed": float(len(tools)),
        "department_mismatch_attempts": float(mismatch),
        "sensitive_actions": float(sensitive),
        "night_hour_calls": float(night),
        "session_duration_minutes": round(duration_minutes, 3),
        "allow_count": float(allow_count),
        "deny_count": float(deny_count),
        "deny_ratio": round(deny_count / total, 3),
    }


def feature_vector(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


def normal_baseline_samples() -> list[dict[str, float]]:
    """Synthetic representative normal behavior (not attack labels)."""
    samples = []
    # Quiet read-heavy sessions
    for calls in (2, 3, 4, 5, 6, 8):
        samples.append(
            {
                "tool_calls_per_minute": float(calls),
                "failed_authorizations": 0.0,
                "unique_tools_accessed": 2.0,
                "department_mismatch_attempts": 0.0,
                "sensitive_actions": 0.0,
                "night_hour_calls": 0.0,
                "session_duration_minutes": 10.0,
                "allow_count": float(calls),
                "deny_count": 0.0,
                "deny_ratio": 0.0,
            }
        )
    # Mild mixed sessions with rare denies
    for denies in (0, 1):
        samples.append(
            {
                "tool_calls_per_minute": 5.0,
                "failed_authorizations": float(denies),
                "unique_tools_accessed": 3.0,
                "department_mismatch_attempts": float(denies),
                "sensitive_actions": 1.0,
                "night_hour_calls": 0.0,
                "session_duration_minutes": 20.0,
                "allow_count": 8.0,
                "deny_count": float(denies),
                "deny_ratio": round(denies / 9.0, 3),
            }
        )
    # Longer but still normal engineering/marketing work
    samples.append(
        {
            "tool_calls_per_minute": 7.0,
            "failed_authorizations": 1.0,
            "unique_tools_accessed": 4.0,
            "department_mismatch_attempts": 0.0,
            "sensitive_actions": 2.0,
            "night_hour_calls": 0.0,
            "session_duration_minutes": 45.0,
            "allow_count": 20.0,
            "deny_count": 1.0,
            "deny_ratio": 0.05,
        }
    )
    return samples
