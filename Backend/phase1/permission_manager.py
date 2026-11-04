"""Department-to-permission and resource authorization (trusted DB / policy.json)."""

from __future__ import annotations

import json
from pathlib import Path

_POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.json"
_cached: dict | None = None


def load_policy(*, force: bool = False) -> dict:
    global _cached
    if _cached is not None and not force:
        return _cached
    _cached = json.loads(_POLICY_PATH.read_text(encoding="utf-8"))
    return _cached


def permissions_for(user_email: str) -> list[str] | str:
    from .identity_manager import resolve_identity

    identity = resolve_identity(user_email)
    if isinstance(identity, str):
        return identity
    return list(identity.get("permissions") or [])


def permission_set_for(user_email: str) -> set[str] | str:
    """Fast membership set for Phase 2 cross-checks."""
    perms = permissions_for(user_email)
    if isinstance(perms, str):
        return perms
    return set(perms)


def tools_for_user(user_email: str) -> list[str] | str:
    perms = permissions_for(user_email)
    if isinstance(perms, str):
        return perms
    perm_set = set(perms)
    policy = load_policy()
    tool_map = policy.get("tool_permissions") or {}
    return [tool for tool, need in tool_map.items() if need in perm_set]


def authorize_tool(user_email: str, tool: str, fields: dict | None = None) -> str | None:
    from .identity_manager import resolve_identity

    identity = resolve_identity(user_email)
    if isinstance(identity, str):
        return identity
    policy = load_policy()
    tool_map = policy.get("tool_permissions") or {}
    need = tool_map.get(tool)
    if need is None:
        return f"Blocked: unknown tool ({tool})."
    permissions = set(identity.get("permissions") or [])
    if need not in permissions:
        return (
            f"Blocked: department '{identity['department']}' is not permitted to call {tool}. "
            "Prompt claims about department are ignored."
        )
    return _authorize_resource(identity, tool, fields or {})


def _authorize_resource(identity: dict, tool: str, fields: dict) -> str | None:
    policy = load_policy()
    resources = policy.get("resources") or {}
    department = identity["department"]

    if tool == "read_project_report":
        project_id = str(fields.get("project_id", "")).strip()
        catalog = resources.get("projects") or {}
        item = catalog.get(project_id)
        if not item:
            return f"Blocked: unknown project_id '{project_id}'."
        if item.get("department") != department:
            return (
                f"Blocked: project '{project_id}' belongs to {item.get('department')}, "
                f"not {department}."
            )
        return None

    if tool == "read_salary_record":
        employee_id = str(fields.get("employee_id", "")).strip()
        catalog = resources.get("salary_records") or {}
        item = catalog.get(employee_id)
        if not item:
            return f"Blocked: unknown employee_id '{employee_id}'."
        if item.get("department") != "hr" or department != "hr":
            return "Blocked: salary records are restricted to HR."
        return None

    if tool == "read_financial_report":
        report_id = str(fields.get("report_id", "")).strip()
        catalog = resources.get("financial_reports") or {}
        item = catalog.get(report_id)
        if not item:
            return f"Blocked: unknown report_id '{report_id}'."
        if item.get("department") != department:
            return (
                f"Blocked: report '{report_id}' belongs to {item.get('department')}, "
                f"not {department}."
            )
        return None

    if tool == "read_campaign_insights":
        campaign_id = str(fields.get("campaign_id", "")).strip()
        catalog = resources.get("campaigns") or {}
        item = catalog.get(campaign_id)
        if not item:
            return f"Blocked: unknown campaign_id '{campaign_id}'."
        if item.get("department") != department:
            return (
                f"Blocked: campaign '{campaign_id}' belongs to {item.get('department')}, "
                f"not {department}."
            )
        return None

    if tool in ("db_query", "db_insert"):
        table = str(fields.get("table", "")).strip()
        catalog = resources.get("db_tables") or {}
        item = catalog.get(table)
        if not item:
            return f"Blocked: unknown db table '{table}'."
        owner = str(item.get("department") or "")
        if owner != "*" and owner != department:
            return (
                f"Blocked: table '{table}' belongs to {owner}, not {department}. "
                "Dummy DB enforces department ownership."
            )
        access = str(item.get("access") or "read")
        if tool == "db_insert" and access != "read_write":
            return f"Blocked: table '{table}' is read-only for writes."
        return None

    if tool == "payment_transfer":
        # Finance-only permission already checked; require non-empty accounts.
        if not str(fields.get("from_account", "")).strip() or not str(fields.get("to_account", "")).strip():
            return "Blocked: payment_transfer requires from_account and to_account."
        try:
            amount = float(fields.get("amount", 0))
        except (TypeError, ValueError):
            return "Blocked: payment_transfer amount must be numeric."
        if amount <= 0:
            return "Blocked: payment_transfer amount must be positive."
        return None

    if tool in ("file_read_sandbox", "file_write_sandbox"):
        path = str(fields.get("path", "")).strip()
        if not path or ".." in path.replace("\\", "/").split("/"):
            return "Blocked: sandbox path must be a simple filename (no '..')."
        return None

    if tool == "slack_post_message":
        if not str(fields.get("channel", "")).strip():
            return "Blocked: slack_post_message requires channel."
        return None

    if tool in ("run_shell_command", "export_env_secrets", "admin_grant_role"):
        return (
            f"Blocked: {tool} is permanently denied by policy "
            "(no department holds the required danger/admin permission)."
        )

    return None


def describe_resource(kind: str, resource_id: str) -> str | None:
    catalog = (load_policy().get("resources") or {}).get(kind) or {}
    item = catalog.get(resource_id)
    if not item:
        return None
    return json.dumps({"id": resource_id, **item}, indent=2)
