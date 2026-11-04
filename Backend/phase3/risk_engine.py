"""Map anomaly scores + rule hits to risk levels and recommended responses.

Phase 3 never silently bypasses Phase 2. These are advisory protective actions.
"""

from __future__ import annotations

RISK_ORDER = ("low", "medium", "high", "critical")

RESPONSES = {
    "low": "Record the event only.",
    "medium": "Generate an alert and increase monitoring for this session.",
    "high": "Require additional verification or human approval for sensitive tools.",
    "critical": "Recommend temporary session suspension and notify an administrator.",
}


def score_to_risk(
    *,
    anomaly_score: float,
    is_anomaly: bool,
    features: dict[str, float],
    rule_alert: dict | None = None,
) -> dict:
    """
    anomaly_score: Isolation Forest decision_function style — lower = more anomalous.
    We also accept a normalized 0..1 risk_raw where higher means more risk.
    """
    deny = float(features.get("failed_authorizations") or 0)
    mismatch = float(features.get("department_mismatch_attempts") or 0)
    rate = float(features.get("tool_calls_per_minute") or 0)
    sensitive = float(features.get("sensitive_actions") or 0)
    deny_ratio = float(features.get("deny_ratio") or 0)

    # Convert IF score (typically negative for outliers) into 0..1 risk hint.
    # decision_function: normal ~ positive/near 0, anomalies more negative.
    if_risk = max(0.0, min(1.0, (-anomaly_score) / 0.35)) if is_anomaly else max(0.0, min(0.45, (-anomaly_score) / 0.5))

    rule_boost = 0.0
    if rule_alert:
        rule_boost += 0.25
    if deny >= 5 or mismatch >= 3:
        rule_boost += 0.25
    if rate >= 40:
        rule_boost += 0.2
    if sensitive >= 8 and deny_ratio >= 0.3:
        rule_boost += 0.2
    if deny >= 10 or rate >= 80:
        rule_boost += 0.3

    risk_raw = max(0.0, min(1.0, 0.55 * if_risk + 0.45 * min(1.0, rule_boost + deny_ratio)))

    if risk_raw >= 0.85 or deny >= 12 or rate >= 100:
        level = "critical"
    elif risk_raw >= 0.65 or (is_anomaly and deny >= 5):
        level = "high"
    elif risk_raw >= 0.4 or is_anomaly or deny >= 3:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_level": level,
        "risk_score": round(risk_raw, 3),
        "recommended_action": RESPONSES[level],
        "phase2_note": "Authorization remains enforced by Phase 2; Phase 3 only advises.",
    }
