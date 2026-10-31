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
sys.path.insert(0, str(BACKEND))

from phase1.identity_manager import resolve_identity  # noqa: E402
from phase1.permission_manager import authorize_tool, load_policy  # noqa: E402
from phase1.tool_selector import HIGH_RISK_TOOLS, tools_for_user  # noqa: E402
from phase3.monitoring import record_and_monitor  # noqa: E402

HOST = "127.0.0.1"
PORT = 8760

# Stable trial personas. Real directory emails stay server-side only.
_PERSONAS = [
    {
        "id": "persona-engineering",
        "label": "Trial User A",
        "department": "engineering",
        "department_label": "Engineering",
        "blurb": "Can access engineering project tools + mail/calendar.",
    },
    {
        "id": "persona-marketing",
        "label": "Trial User B",
        "department": "marketing",
        "department_label": "Marketing",
        "blurb": "Can access marketing campaign tools + mail/calendar.",
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
    for email, meta in (policy.get("users") or {}).items():
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
            "This trial UI does not mint tokens, so send/calendar stays blocked here."
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
        return {
            "status": "DENIED",
            "persona": public["label"],
            "department": public["department_label"],
            "tool": tool,
            "phase1_exposed": exposed,
            "reason": reason,
            "alert": alert,
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
    return {
        "status": status,
        "persona": public["label"],
        "department": public["department_label"],
        "tool": tool,
        "phase1_exposed": exposed,
        "reason": reason,
        "alert": alert,
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
