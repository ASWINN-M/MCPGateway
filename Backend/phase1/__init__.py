"""Phase 1 — Dynamic tool selection and access management."""

from .identity_manager import format_identity, resolve_identity
from .permission_manager import (
    authorize_tool,
    describe_resource,
    load_policy,
    permissions_for,
    tools_for_user,
)
from .tool_selector import allowed_tool_set, describe_allowed_tools, select_tools_for_user

__all__ = [
    "resolve_identity",
    "format_identity",
    "load_policy",
    "permissions_for",
    "tools_for_user",
    "authorize_tool",
    "describe_resource",
    "select_tools_for_user",
    "describe_allowed_tools",
    "allowed_tool_set",
]
