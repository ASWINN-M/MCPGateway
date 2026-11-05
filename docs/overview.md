# Overview

## What this project is

A **three-phase MCP Security Gateway** between an LLM (Cursor) and protected tools (Gmail/Calendar + department stubs + dummy enterprise tools):

1. **Phase 1** — Authenticate, read trusted department, expose only permitted tools  
2. **Phase 2** — Central gateway allows or denies every tool call **before** execution (permissions, args/resources, execution tokens, bulk/rate ceilings)  
3. **Phase 3** — Log decisions and detect suspicious patterns (Isolation Forest + heuristics)  

Mail/calendar stay least-privilege (draft ≠ send without a bound token on the hardened path; high-risk needs human approval). Department and danger tools are gated by `Backend/policy.json`.

**Important design choice:** high-risk tools such as `run_shell`, `export_secrets`, `fetch_finance_records`, and `render_template` **exist in the catalog** so prompt-injection attacks can attempt them. SAFE means Phase 2 **denied** the call — not that the tool was missing.

---

## Working principle (one sentence)

**Untrusted content is data; Phase 1 limits tool exposure, Phase 2 enforces authorization in code, Phase 3 audits the outcome — the prompt never replaces the gateway.**

---

## Mailbox model

| Role | Address | You use it to… |
| --- | --- | --- |
| Connected / attacking mail | `aswinm2k4@gmail.com` | OAuth login; agent operates as this user; attack **From** |
| Exfil / attacked inbox | `aswinmmsa@gmail.com` | See whether attack forwards arrived |

Trial UI personas use `@example.com` so demos do not leak real names/emails.

---

## Why it exists (capstone)

Agents that read email face **prompt injection** and **over-privilege** (same *classes* of risk as public agent/mail incidents — not the same CVEs).

This project shows:

1. A realistic multi-tool agent (mail + calendar + dept + DB/file/comms stubs)  
2. A **three-phase gateway** (selection → enforcement → monitoring)  
3. A **21-attack harness** (+ security guarantees) reporting **ASR**, with layer ablation charts in the explainer UI  

See [architecture.md](architecture.md) for the faculty-facing phase write-up.

---

## Key ideas

| Idea | Meaning |
| --- | --- |
| **Phase 1** | Trusted identity + department → permitted tool list |
| **Phase 2** | Gateway allow/deny before any privileged tool runs |
| **Phase 3** | Audit trail + Isolation Forest anomaly / risk levels |
| **MCP** | Cursor (or harness) talks to `Backend/email_server.py` over stdio |
| **Confirmation** | High-risk tools need human `--approve` + execution token |
| **Catalog ≠ allow** | Danger tools are registered so attacks can try them; policy denies |
| **Data ≠ instructions** | Bodies/filenames are not authorization |
| **ASR** | % of cases where the attacker goal was met — **lower is better** |

---

## What is built

| Piece | Status |
| --- | --- |
| Phase 1 policy directory + `list_allowed_tools` / `get_my_identity` | Working |
| Phase 2 gateway (caller auth, permissions, args, approval, bulk/rate) | Working |
| Phase 3 SQLite/JSONL audit + Isolation Forest anomaly API | Working |
| Gmail + Calendar MCP tools | Working |
| Dummy DB / sandbox files / slack / payment stubs | Working |
| Danger catalog tools (shell / secrets / template / payroll fetch) | Present + denied |
| Cursor MCP config (`launch_stdio.py`) | Working |
| 21-case harness (mock + real) | Working |
| Explainer UI + evaluation / prompt-driven test run (`:8760`) | Working |

---

## Documentation map

| Doc | Contents |
| --- | --- |
| [setup.md](setup.md) | Clone → OAuth → Cursor |
| [architecture.md](architecture.md) | Diagrams, principles, file map |
| [tools-and-usage.md](tools-and-usage.md) | Tools and day-to-day use |
| [testing.md](testing.md) | How to run the 21 attacks |
| [scores_before_after_gateway.md](scores_before_after_gateway.md) | Latest before/after ASR |
| [security.md](security.md) | Secrets and honest reporting |
