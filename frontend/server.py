"""Local explainer UI for the three-phase MCP Security Gateway.

Serves the frontend and a small JSON API that exercises Phase 1-3 policy
checks (no Gmail send, no Cursor LLM, no real names/emails in the UI).

  python frontend/server.py
  -> http://127.0.0.1:8760
"""

from __future__ import annotations

import json
import re
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = Path(__file__).resolve().parent
BACKEND = ROOT / "Backend"
EXTRACTED = ROOT / "testcases" / "extracted"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(EXTRACTED))

from phase1.identity_manager import resolve_identity  # noqa: E402
from phase1.permission_manager import authorize_tool, load_policy  # noqa: E402
from phase1.tool_selector import HIGH_RISK_TOOLS, tools_for_user  # noqa: E402
from phase3.monitoring import record_and_monitor  # noqa: E402
from demo_testrun import catalog as testcase_catalog  # noqa: E402
from demo_testrun import run_from_prompt, run_tests  # noqa: E402
from layer_eval import build_evaluation  # noqa: E402

HOST = "127.0.0.1"
PORT = 8760

# Stable trial personas. Real directory emails stay server-side only.
_PERSONAS = [
    {
        "id": "persona-engineering",
        "label": "Trial User A",
        "department": "engineering",
        "department_label": "Engineering",
        "blurb": "Projects, dummy DB eng_tickets, sandbox files, Slack stub.",
    },
    {
        "id": "persona-marketing",
        "label": "Trial User B",
        "department": "marketing",
        "department_label": "Marketing",
        "blurb": "Campaigns, marketing_leads DB read, Slack stub.",
    },
    {
        "id": "persona-finance",
        "label": "Trial User C",
        "department": "finance",
        "department_label": "Finance",
        "blurb": "Finance reports, ledger DB, payment_transfer (high-risk).",
    },
    {
        "id": "persona-hr",
        "label": "Trial User D",
        "department": "hr",
        "department_label": "HR",
        "blurb": "Salary records and hr_employees DB read.",
    },
]


def _email_for_persona(persona_id: str) -> str | None:
    policy = load_policy(force=True)
    wanted = None
    for row in _PERSONAS:
        if row["id"] == persona_id:
            wanted = row["department"]
            break
    if not wanted:
        return None
    users = policy.get("users") or {}
    # Prefer synthetic trial identities so the UI never binds to real mailboxes.
    for email, meta in users.items():
        if (
            str((meta or {}).get("department", "")).lower() == wanted
            and str(email).endswith("@example.com")
        ):
            return email
    for email, meta in users.items():
        if str((meta or {}).get("department", "")).lower() == wanted:
            return email
    return None


def _persona_public(persona_id: str) -> dict | None:
    for row in _PERSONAS:
        if row["id"] == persona_id:
            return {
                "id": row["id"],
                "label": row["label"],
                "department": row["department"],
                "department_label": row["department_label"],
                "blurb": row["blurb"],
            }
    return None


def _scrub(text: str) -> str:
    """Remove emails and personal display names from anything sent to the browser."""
    cleaned = re.sub(r"[\w.\-+]+@[\w.\-]+\.\w+", "[redacted-email]", text or "")
    for needle in ("Aswin", "aswin", "External / exfil watch"):
        cleaned = cleaned.replace(needle, "[redacted]")
    return cleaned


def _json_response(handler: SimpleHTTPRequestHandler, code: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: SimpleHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    raw = handler.rfile.read(length) if length else b"{}"
    data = json.loads(raw.decode("utf-8") or "{}")
    return data if isinstance(data, dict) else {}


def overview() -> dict:
    return {
        "title": "MCP Security Gateway",
        "principle": "Prompt guides. Gateway enforces.",
        "llm_note": (
            "This trial UI does not embed Cursor's LLM. "
            "Cursor remains the chat/LLM host; this page only demonstrates gateway policy decisions."
        ),
        "privacy_note": "Trial mode: real names and emails are never shown in the UI.",
        "phases": [
            {"id": 1, "name": "Tool selection", "role": "Expose permitted tools"},
            {"id": 2, "name": "Enforcement", "role": "Allow or deny before execution"},
            {"id": 3, "name": "Monitoring", "role": "Audit and detect abuse"},
        ],
        "personas": [_persona_public(p["id"]) for p in _PERSONAS],
    }


def phase1(persona_id: str) -> dict:
    public = _persona_public(persona_id)
    email = _email_for_persona(persona_id)
    if not public or not email:
        return {"ok": False, "error": "Unknown trial persona."}
    identity = resolve_identity(email)
    if isinstance(identity, str):
        return {"ok": False, "error": _scrub(identity)}
    tools = tools_for_user(email)
    if isinstance(tools, str):
        return {"ok": False, "error": _scrub(tools)}
    return {
        "ok": True,
        "persona": public,
        "tools": tools,
    }


def try_tool(persona_id: str, tool: str, arguments: dict) -> dict:
    public = _persona_public(persona_id)
    email = _email_for_persona(persona_id)
    if not public or not email:
        return {
            "status": "DENIED",
            "persona": persona_id,
            "department": None,
            "tool": tool,
            "phase1_exposed": False,
            "reason": "Unknown trial persona.",
        }

    identity = resolve_identity(email)
    if isinstance(identity, str):
        return {
            "status": "DENIED",
            "persona": public["label"],
            "department": public["department"],
            "tool": tool,
            "phase1_exposed": False,
            "reason": _scrub(identity),
        }

    tools = tools_for_user(email)
    permitted = set(tools) if isinstance(tools, list) else set()
    exposed = tool in permitted
    audit_user = public["id"]

    if tool in HIGH_RISK_TOOLS:
        reason = (
            "DENIED by Phase 2 demo: high-risk tools require a human-approved "
            "execution token in the live MCP gateway (CLI --approve). "
            "This trial UI does not mint tokens, so write/send/transfer tools stay blocked here."
        )
        monitor = record_and_monitor(
            user_id=audit_user,
            department=public["department"],
            tool_name=tool,
            status="DENIED",
            session_id="demo-ui",
            reason=reason,
            arguments=arguments,
        )
        alert = monitor.get("alert")
        if alert and isinstance(alert.get("message"), str):
            alert = {**alert, "message": _scrub(alert["message"])}
        anomaly = _public_anomaly(monitor.get("anomaly"))
        return {
            "status": "DENIED",
            "persona": public["label"],
            "department": public["department_label"],
            "tool": tool,
            "phase1_exposed": exposed,
            "reason": reason,
            "alert": alert,
            "anomaly": anomaly,
        }

    denied = authorize_tool(email, tool, arguments)
    status = "DENIED" if denied else "ALLOWED"
    reason = _scrub(denied) if denied else "authorized by trusted department policy and resource checks"
    monitor = record_and_monitor(
        user_id=audit_user,
        department=public["department"],
        tool_name=tool,
        status=status,
        session_id="demo-ui",
        reason=reason,
        arguments=arguments,
    )
    alert = monitor.get("alert")
    if alert and isinstance(alert.get("message"), str):
        alert = {**alert, "message": _scrub(alert["message"])}
    anomaly = _public_anomaly(monitor.get("anomaly"))
    return {
        "status": status,
        "persona": public["label"],
        "department": public["department_label"],
        "tool": tool,
        "phase1_exposed": exposed,
        "reason": reason,
        "alert": alert,
        "anomaly": anomaly,
    }


def _public_anomaly(anomaly: dict | None) -> dict | None:
    if not isinstance(anomaly, dict):
        return None
    out = {
        "algorithm": anomaly.get("algorithm"),
        "is_anomaly": bool(anomaly.get("is_anomaly")),
        "anomaly_score": anomaly.get("anomaly_score"),
        "risk_level": anomaly.get("risk_level"),
        "risk_score": anomaly.get("risk_score"),
        "recommended_action": anomaly.get("recommended_action"),
        "phase2_note": anomaly.get("phase2_note"),
        "message": _scrub(str(anomaly.get("message") or "")),
        "features": anomaly.get("features") or {},
        "feature_names": anomaly.get("feature_names") or [],
    }
    return out


def anomaly_overview() -> dict:
    from phase3.anomaly_detector import analyze_session, retrain
    from phase3.audit_store import recent_anomalies
    from phase3.features import FEATURE_NAMES

    # Ensure model is warmed for the trial UI.
    train = retrain()
    current = analyze_session(session_id="demo-ui", user_id="trial-user", department="trial")
    events = []
    for row in recent_anomalies(20):
        events.append(
            {
                "timestamp": row.get("timestamp"),
                "risk_level": row.get("risk_level"),
                "risk_score": row.get("risk_score"),
                "anomaly_score": row.get("anomaly_score"),
                "is_anomaly": row.get("is_anomaly"),
                "recommended_action": row.get("recommended_action"),
                "message": _scrub(str(row.get("message") or "")),
                "features": row.get("features") or {},
                "persona": "trial-user",
            }
        )
    return {
        "title": "Phase 3 — monitoring & anomaly detection",
        "principle": (
            "Phase 2 checks whether an action is permitted. "
            "Phase 3 checks whether the activity looks suspicious, even when actions are allowed."
        ),
        "algorithm": train.get("algorithm") or current.get("algorithm"),
        "model": train,
        "feature_names": FEATURE_NAMES,
        "current": _public_anomaly(current),
        "events": events,
        "risk_legend": [
            {"level": "low", "response": "Record the event"},
            {"level": "medium", "response": "Alert and increase monitoring"},
            {"level": "high", "response": "Require extra verification / human approval"},
            {"level": "critical", "response": "Recommend session suspend + notify admin"},
        ],
    }


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND), **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/overview":
            _json_response(self, 200, overview())
            return
        if path == "/api/audit":
            from phase3.audit_logger import recent_decisions

            rows = []
            for row in recent_decisions(50):
                rows.append(
                    {
                        "timestamp": row.get("timestamp"),
                        "status": row.get("status"),
                        "tool_name": row.get("tool_name"),
                        "department": row.get("department"),
                        "persona": row.get("user_id") if str(row.get("user_id", "")).startswith("persona-") else "trial-user",
                    }
                )
            _json_response(self, 200, {"decisions": rows})
            return
        if path == "/api/anomaly":
            try:
                _json_response(self, 200, anomaly_overview())
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 500, {"error": _scrub(str(exc))})
            return
        if path == "/api/evaluation":
            try:
                _json_response(self, 200, build_evaluation())
            except FileNotFoundError as exc:
                _json_response(self, 404, {"error": _scrub(str(exc))})
            except Exception as exc:  # noqa: BLE001 — surface to trial UI
                _json_response(self, 500, {"error": _scrub(str(exc))})
            return
        if path == "/api/testcases":
            try:
                _json_response(self, 200, testcase_catalog())
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 500, {"error": _scrub(str(exc))})
            return
        if path == "/":
            self.path = "/index.html"
        return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        data = _read_json(self)
        if path == "/api/phase1":
            result = phase1(str(data.get("persona_id") or data.get("email") or ""))
            _json_response(self, 200 if result.get("ok") else 400, result)
            return
        if path == "/api/try-tool":
            result = try_tool(
                str(data.get("persona_id") or data.get("email") or ""),
                str(data.get("tool", "")),
                data.get("arguments") if isinstance(data.get("arguments"), dict) else {},
            )
            _json_response(self, 200, result)
            return
        if path == "/api/run-tests":
            try:
                result = run_tests(str(data.get("mode") or "compare"))
                _json_response(self, 200, result)
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 500, {"ok": False, "error": _scrub(str(exc))})
            return
        if path == "/api/run-from-prompt":
            try:
                result = run_from_prompt(
                    test_id=str(data.get("test_id") or "") or None,
                    user_prompt=str(data.get("user_prompt") or ""),
                    system_prompt=str(data.get("system_prompt") or ""),
                    mode=str(data.get("mode") or "compare"),
                )
                _json_response(self, 200, result)
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 500, {"ok": False, "error": _scrub(str(exc))})
            return
        _json_response(self, 404, {"error": "not found"})


def main() -> int:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"MCP Gateway explainer UI -> http://{HOST}:{PORT}", flush=True)
    print("Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
