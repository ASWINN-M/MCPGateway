# Overview

## What this project is

A **three-phase MCP Security Gateway** between an LLM (Cursor) and protected tools (Gmail/Calendar + department stubs):

1. **Phase 1** — Authenticate, read trusted department, expose only permitted tools  
2. **Phase 2** — Central gateway allows or denies every tool call **before** execution  
3. **Phase 3** — Log decisions and detect suspicious unauthorized attempts  

Mail/calendar capabilities remain least-privilege (draft ≠ send; high-risk needs human approval). Department stubs (HR/Finance/Engineering/Marketing) are gated by `policy.json`.

---

## Working principle (one sentence)

**Untrusted content is data; Phase 1 limits tool exposure, Phase 2 enforces authorization in code, Phase 3 audits the outcome — the prompt never replaces the gateway.**

---

## Mailbox model

| Role | Address | You use it to… |
| --- | --- | --- |
| Connected / attacking mail | `aswinm2k4@gmail.com` | OAuth login; agent operates as this user; attack **From** |
| Exfil / attacked inbox | `aswinmmsa@gmail.com` | See whether attack forwards arrived |

---

## Why it exists (capstone)

Agents that read email face **prompt injection** and **over-privilege** (same *classes* of risk as incidents involving Claude + Google Workspace or Hugging Face WebFetch — not the same CVEs).

This project shows:

1. A realistic multi-tool agent (mail + calendar + department stubs)  
2. A **three-phase gateway** (selection → enforcement → monitoring)  
3. A **16-attack harness** (+ security guarantees) reporting **ASR** against the **real** MCP gateway  

See [architecture.md](architecture.md) for the faculty-facing phase write-up.

---

## Key ideas

| Idea | Meaning |
| --- | --- |
| **Phase 1** | Trusted identity + department → permitted tool list |
| **Phase 2** | Gateway allow/deny before any privileged tool runs |
| **Phase 3** | Audit trail and suspicious-pattern checks |
| **MCP** | Cursor (or harness) talks to `Backend/email_server.py` over stdio |
| **Confirmation** | High-risk tools need human `--approve` + execution token |
| **Data ≠ instructions** | Bodies/filenames are not authorization |
| **ASR** | % of cases where the attacker goal was met — **lower is better** |

---

## What is built

| Piece | Status |
| --- | --- |
| Phase 1 policy directory + `list_allowed_tools` / `get_my_identity` | Working |
| Phase 2 gateway (caller auth, permissions, args, approval) | Working |
| Phase 3 harness guarantees + result JSON trail | Working (lightweight) |
| Gmail + Calendar MCP tools | Working |
| Literal attachment store | Working |
| Cursor MCP config (`launch_stdio.py`) | Working |
| 16-case harness vs **real** gateway | Working (default) |
| Optional mock baseline (`--with-baseline`) | Working |

---

## Documentation map

| Doc | Contents |
| --- | --- |
| [setup.md](setup.md) | Clone → OAuth → Cursor |
| [architecture.md](architecture.md) | Diagrams, principles, file map |
| [tools-and-usage.md](tools-and-usage.md) | Tools and day-to-day use |
| [testing.md](testing.md) | How to run the 16 attacks |
| [scores_real_gateway.md](scores_real_gateway.md) | Latest real-run scores |
| [security.md](security.md) | Secrets and honest reporting |
