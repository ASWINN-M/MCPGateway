"""Phase 2 — cross-validate tool requests against trusted permissions (set membership)."""

from . import _engine

authorize_session_tool = _engine.authorize_session_tool
ALLOWED_TOOLS = _engine.ALLOWED_TOOLS
describe_allowed_tools = _engine.describe_allowed_tools
