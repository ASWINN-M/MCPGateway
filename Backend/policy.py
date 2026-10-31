"""Compatibility shim — Phase 1 policy lives under Backend/phase1/."""

from phase1.identity_manager import format_identity, resolve_identity
from phase1.permission_manager import (
    authorize_tool,
    describe_resource,
    load_policy,
    permissions_for,
    tools_for_user,
)

__all__ = [
    "load_policy",
    "resolve_identity",
    "format_identity",
    "permissions_for",
    "tools_for_user",
    "authorize_tool",
    "describe_resource",
]
