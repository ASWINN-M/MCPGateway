"""Phase 2 — Central MCP gateway pre-execution enforcement."""

from .approval_manager import (
    HIGH_RISK_TOOLS,
    advance_execution_lock,
    check_execution_lock,
    issue_confirmation,
    load_pending,
)
from .authorization import ALLOWED_TOOLS, authorize_session_tool, describe_allowed_tools
from .enforcement import enforce_tool_request
from .session_manager import caller_auth_error, cancel_session, current_session_id
from .token_validator import consume_execution_token, issue_execution_token, verify_execution_token

# Re-export storage paths used by tests
from . import _engine

APPROVALS_DIR = _engine.APPROVALS_DIR
PLANS_DIR = _engine.PLANS_DIR
EXECUTIONS_DIR = _engine.EXECUTIONS_DIR
LOCK_PATH = _engine.LOCK_PATH

__all__ = [
    "enforce_tool_request",
    "caller_auth_error",
    "current_session_id",
    "cancel_session",
    "issue_execution_token",
    "verify_execution_token",
    "consume_execution_token",
    "issue_confirmation",
    "load_pending",
    "check_execution_lock",
    "advance_execution_lock",
    "authorize_session_tool",
    "describe_allowed_tools",
    "ALLOWED_TOOLS",
    "HIGH_RISK_TOOLS",
]
