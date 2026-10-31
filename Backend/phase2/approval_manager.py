"""Phase 2 — human approval plans and execution locks."""

from . import _engine

issue_confirmation = _engine.issue_confirmation
load_pending = _engine.load_pending
check_execution_lock = _engine.check_execution_lock
advance_execution_lock = _engine.advance_execution_lock
canonical_fields = _engine.canonical_fields
HIGH_RISK_TOOLS = _engine.HIGH_RISK_TOOLS
