"""Entry helper documenting the three-phase layout.

Prefer:
  python Backend/launch_stdio.py          # Cursor / MCP stdio
  python Backend/email_server.py --login  # OAuth
  python Backend/email_server.py --approve <plan_id>
"""

from __future__ import annotations


def describe_phases() -> str:
    return (
        "Phase 1 (Backend/phase1): identity, permissions, tool selection\n"
        "Phase 2 (Backend/phase2): session, tokens, approval, authorization, enforcement\n"
        "Phase 3 (Backend/phase3): audit log, anomaly detection, monitoring\n"
        "MCP surface: Backend/email_server.py\n"
    )


if __name__ == "__main__":
    print(describe_phases())
