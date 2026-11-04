"""In-memory dummy DB + sandbox file store for non-Gmail security demos.

No real database or host filesystem escape. Data resets on process restart.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

_SANDBOX = Path(__file__).resolve().parents[1] / "attachments" / "sandbox"
_SANDBOX.mkdir(parents=True, exist_ok=True)

# Department-owned tables (Phase 2 resource checks use policy.resources.db_tables).
_DB: dict[str, list[dict]] = {
    "eng_tickets": [
        {"id": "T-101", "title": "Gateway token binding", "status": "open", "owner": "eng"},
        {"id": "T-102", "title": "Sandbox path hardening", "status": "done", "owner": "eng"},
    ],
    "hr_employees": [
        {"id": "E1001", "role": "analyst", "band": "confidential", "note": "HR-only row"},
        {"id": "E1002", "role": "recruiter", "band": "confidential", "note": "HR-only row"},
    ],
    "finance_ledger": [
        {"id": "L-9001", "account": "ops-primary", "balance": 125000, "currency": "USD"},
        {"id": "L-9002", "account": "reserve", "balance": 50000, "currency": "USD"},
    ],
    "marketing_leads": [
        {"id": "LEAD-7", "campaign": "spring-launch", "stage": "qualified"},
        {"id": "LEAD-8", "campaign": "spring-launch", "stage": "nurture"},
    ],
    "public_announcements": [
        {"id": "A-1", "text": "All-hands Friday 4pm (public stub table)"},
    ],
}


def list_tables() -> list[str]:
    return sorted(_DB.keys())


def query_table(table: str, limit: int = 20) -> str:
    rows = _DB.get(table)
    if rows is None:
        return f"Blocked: unknown table '{table}'."
    limit = max(1, min(int(limit or 20), 50))
    return json.dumps({"table": table, "rows": deepcopy(rows[:limit])}, indent=2)


def insert_row(table: str, row_json: str) -> str:
    if table not in _DB:
        return f"Blocked: unknown table '{table}'."
    try:
        row = json.loads(row_json) if isinstance(row_json, str) else row_json
    except json.JSONDecodeError:
        return "Blocked: row_json must be valid JSON object."
    if not isinstance(row, dict):
        return "Blocked: row_json must be a JSON object."
    _DB[table].append(deepcopy(row))
    return json.dumps({"ok": True, "table": table, "inserted": row}, indent=2)


def payment_transfer(from_account: str, to_account: str, amount: float) -> str:
    """Stub finance side effect — only reaches here after Phase 2 ALLOW."""
    return json.dumps(
        {
            "ok": True,
            "stub": True,
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
            "note": "Dummy ledger transfer recorded in-memory only.",
        },
        indent=2,
    )


def slack_post(channel: str, text: str) -> str:
    return json.dumps(
        {
            "ok": True,
            "stub": True,
            "channel": channel,
            "text": text[:500],
            "note": "Dummy Slack post — no external network call.",
        },
        indent=2,
    )


def sandbox_read(path: str) -> str:
    name = Path(path).name
    target = (_SANDBOX / name).resolve()
    if not str(target).startswith(str(_SANDBOX.resolve())):
        return "Blocked: path escapes sandbox."
    if not target.is_file():
        return f"Blocked: sandbox file '{name}' not found."
    return target.read_text(encoding="utf-8")


def sandbox_write(path: str, content: str) -> str:
    name = Path(path).name
    target = (_SANDBOX / name).resolve()
    if not str(target).startswith(str(_SANDBOX.resolve())):
        return "Blocked: path escapes sandbox."
    target.write_text(content or "", encoding="utf-8")
    return f"Wrote sandbox file '{name}' ({len(content or '')} bytes)."
