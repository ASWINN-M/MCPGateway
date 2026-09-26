import secrets

ALLOWED_TOOLS = [
    "read_latest_emails",
    "create_email_draft",
    "send_email",
    "get_calendar_availability",
    "create_calendar_event",
    "store_attachment",
    "list_allowed_tools",
    "require_user_confirm",
]

HIGH_RISK_TOOLS = frozenset({"send_email", "create_calendar_event"})

_pending: dict[str, dict] = {}


def describe_allowed_tools() -> str:
    lines = [
        "Allowed tools in this session:",
        *[f"- {name}" for name in ALLOWED_TOOLS],
        "",
        "High-risk tools that need require_user_confirm first:",
        *[f"- {name}" for name in sorted(HIGH_RISK_TOOLS)],
        "",
        "These tools are not available: finance, payroll, passwords, contacts export, shell, other people's calendars.",
    ]
    return "\n".join(lines)


def issue_confirmation(action: str, summary: str) -> str:
    if action not in HIGH_RISK_TOOLS:
        return f"{action} does not require confirmation. Call it directly."
    token = secrets.token_hex(8)
    _pending[token] = {"action": action, "summary": summary}
    return (
        f"Confirmation created for {action}.\n"
        f"Summary: {summary}\n"
        f"confirm_token: {token}\n"
        "Ask the user to approve this exact action. If they approve, retry the tool with this confirm_token. "
        "If they refuse, do not call the high-risk tool."
    )


def consume_confirmation(action: str, token: str) -> str | None:
    """Return None if allowed, or an error string if blocked."""
    if action not in HIGH_RISK_TOOLS:
        return None
    if not token or token not in _pending:
        return (
            f"Blocked: {action} requires user confirmation. "
            "Call require_user_confirm first, show the summary to the user, "
            "then retry with the returned confirm_token."
        )
    record = _pending.pop(token)
    if record["action"] != action:
        return f"Blocked: that token was issued for {record['action']}, not {action}."
    return None
