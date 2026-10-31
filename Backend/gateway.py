"""Compatibility shim — Phase 2 engine lives under Backend/phase2/."""

from phase2 import _engine as _engine
from phase2.approval_manager import (
    HIGH_RISK_TOOLS,
    advance_execution_lock,
    check_execution_lock,
    issue_confirmation,
    load_pending,
)
from phase2.authorization import ALLOWED_TOOLS, authorize_session_tool, describe_allowed_tools
from phase2.session_manager import caller_auth_error, cancel_session, current_session_id
from phase2.token_validator import consume_execution_token, issue_execution_token, verify_execution_token

# Paths / helpers used by security_guarantees.py
APPROVALS_DIR = _engine.APPROVALS_DIR
PLANS_DIR = _engine.PLANS_DIR
EXECUTIONS_DIR = _engine.EXECUTIONS_DIR
LOCK_PATH = _engine.LOCK_PATH
_clear_lock = _engine._clear_lock
canonical_fields = _engine.canonical_fields

__all__ = [
    "ALLOWED_TOOLS",
    "HIGH_RISK_TOOLS",
    "APPROVALS_DIR",
    "PLANS_DIR",
    "EXECUTIONS_DIR",
    "LOCK_PATH",
    "caller_auth_error",
    "current_session_id",
    "cancel_session",
    "describe_allowed_tools",
    "authorize_session_tool",
    "issue_confirmation",
    "load_pending",
    "issue_execution_token",
    "verify_execution_token",
    "consume_execution_token",
    "check_execution_lock",
    "advance_execution_lock",
    "_clear_lock",
    "canonical_fields",
]
