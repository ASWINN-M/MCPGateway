"""Phase 3 anomaly detection: Isolation Forest + rule heuristics.

Phase 2 decides allow/deny. Phase 3 flags suspicious *patterns*, including
high-volume allowed activity and repeated unauthorized attempts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .features import (
    FEATURE_NAMES,
    extract_session_features,
    feature_vector,
    normal_baseline_samples,
)
from .risk_engine import score_to_risk

_PROJECT = Path(__file__).resolve().parents[2]
_MODEL_DIR = _PROJECT / "results" / "audit"
_MODEL_META = _MODEL_DIR / "isolation_forest_meta.json"

DEFAULT_DENY_THRESHOLD = 3

_model = None
_model_error: str | None = None


def detect_repeated_unauthorized(
    *,
    session_id: str,
    threshold: int = DEFAULT_DENY_THRESHOLD,
    rows: list[dict] | None = None,
) -> dict | None:
    from .audit_store import decisions_for_session, recent_decisions

    if rows is None:
        rows = decisions_for_session(session_id, 300) if session_id else recent_decisions(300)
        rows = [r for r in rows if r.get("session_id") == session_id]
    denies = [r for r in rows if str(r.get("status", "")).upper() == "DENIED"]
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
            f"ALERT: session {session_id[:12]}... has {len(denies)} DENIED tool attempts "
            f"(recent tools: {', '.join(tools)}). Notify authorities / consider revoke."
        ),
    }


def _fit_isolation_forest():
    global _model, _model_error
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        _model = None
        _model_error = f"scikit-learn unavailable ({exc}); using heuristic detector"
        return None

    samples = [feature_vector(s) for s in normal_baseline_samples()]
    # Include recent real sessions that look calm (deny_ratio low) as extra normals.
    try:
        from .audit_store import recent_decisions

        hist = recent_decisions(800)
        by_session: dict[str, list] = {}
        for row in hist:
            sid = str(row.get("session_id") or "")
            if not sid:
                continue
            by_session.setdefault(sid, []).append(row)
        for sid, rows in list(by_session.items())[:40]:
            feats = extract_session_features(rows)
            if feats["deny_ratio"] <= 0.15 and feats["tool_calls_per_minute"] <= 20:
                samples.append(feature_vector(feats))
    except Exception:
        pass

    X = np.array(samples, dtype=float)
    if len(X) < 8:
        X = np.vstack([X, X])  # tiny bootstrap
    model = IsolationForest(
        n_estimators=100,
        contamination=0.12,
        random_state=42,
        n_jobs=1,
    )
    model.fit(X)
    _model = model
    _model_error = None
    _MODEL_DIR.mkdir(parents=True, exist_ok=True)
    _MODEL_META.write_text(
        json.dumps(
            {
                "algorithm": "IsolationForest",
                "trained_at": datetime.now(timezone.utc).isoformat(),
                "n_samples": int(len(X)),
                "features": FEATURE_NAMES,
                "contamination": 0.12,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return model


def get_model():
    global _model
    if _model is None and _model_error is None:
        _fit_isolation_forest()
    elif _model is None and _model_error and "unavailable" not in (_model_error or ""):
        _fit_isolation_forest()
    return _model


def _heuristic_score(features: dict[str, float]) -> tuple[bool, float]:
    """Fallback when sklearn is missing: distance from normal centroids."""
    rate = features["tool_calls_per_minute"]
    deny = features["failed_authorizations"]
    mismatch = features["department_mismatch_attempts"]
    sensitive = features["sensitive_actions"]
    # More negative => more anomalous (mirrors IF decision_function vibe).
    score = 0.2
    score -= min(1.5, rate / 40.0)
    score -= min(1.2, deny / 6.0)
    score -= min(1.0, mismatch / 4.0)
    score -= min(0.8, sensitive / 10.0)
    is_anom = score < -0.35 or rate >= 40 or deny >= 5
    return is_anom, score


def analyze_session(
    *,
    session_id: str,
    user_id: str = "",
    department: str | None = None,
) -> dict:
    from .audit_store import decisions_for_session

    rows = decisions_for_session(session_id, 500) if session_id else []
    features = extract_session_features(rows)
    rule_alert = detect_repeated_unauthorized(session_id=session_id, rows=rows)

    model = get_model()
    algorithm = "IsolationForest"
    if model is not None:
        try:
            import numpy as np

            vec = np.array([feature_vector(features)], dtype=float)
            pred = int(model.predict(vec)[0])  # -1 anomaly, 1 normal
            raw_score = float(model.decision_function(vec)[0])
            is_anomaly = pred == -1
        except Exception as exc:  # noqa: BLE001
            is_anomaly, raw_score = _heuristic_score(features)
            algorithm = f"heuristic(fallback:{exc.__class__.__name__})"
    else:
        is_anomaly, raw_score = _heuristic_score(features)
        algorithm = "heuristic"

    risk = score_to_risk(
        anomaly_score=raw_score,
        is_anomaly=is_anomaly,
        features=features,
        rule_alert=rule_alert,
    )

    message_parts = []
    if is_anomaly:
        message_parts.append(
            f"Behavioral anomaly detected ({algorithm}) for session {session_id[:12]}..."
        )
    if rule_alert:
        message_parts.append(rule_alert["message"])
    if not message_parts:
        message_parts.append(
            f"Session {session_id[:12] if session_id else 'n/a'}... within normal behavioral range."
        )

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "user_id": user_id,
        "department": department,
        "algorithm": algorithm,
        "is_anomaly": is_anomaly or bool(rule_alert),
        "anomaly_score": round(raw_score, 4),
        "features": features,
        "feature_names": FEATURE_NAMES,
        "rule_alert": rule_alert,
        "risk_level": risk["risk_level"],
        "risk_score": risk["risk_score"],
        "recommended_action": risk["recommended_action"],
        "phase2_note": risk["phase2_note"],
        "message": " ".join(message_parts),
        "model_error": _model_error,
    }
    return event


def retrain() -> dict:
    global _model, _model_error
    _model = None
    _model_error = None
    model = _fit_isolation_forest()
    meta = {}
    if _MODEL_META.is_file():
        meta = json.loads(_MODEL_META.read_text(encoding="utf-8"))
    return {
        "ok": model is not None,
        "algorithm": meta.get("algorithm", "heuristic"),
        "n_samples": meta.get("n_samples"),
        "error": _model_error,
    }
