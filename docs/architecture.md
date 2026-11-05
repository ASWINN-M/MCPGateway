# Architecture and working principles

## What the system is

A **three-phase MCP Security Gateway** between:

1. **Cursor’s LLM** (or the automated test harness / explainer UI), and  
2. **Protected tools / Google APIs** for one connected Gmail/Calendar account, plus department stubs, dummy enterprise tools, and a **denial-gated attack-surface catalog**.

**Central idea:** Phase 1 decides which tools should be *visible*. Phase 2 independently verifies whether a requested tool may *execute*. Phase 3 records and monitors what happened.

The prompt guides the LLM ([system-prompt.md](system-prompt.md)). **The gateway enforces security in code.** Untrusted content (email bodies, filenames, user claims) is **data**, not authorization.

Dangerous tools (`run_shell`, `export_secrets`, `render_template`, …) are **registered** so injections can attempt them. Phase 2 must **deny** them — SAFE must not mean “tool missing.”

---

## Three-phase MCP security architecture

```text
┌──────────────────────────────────────────────────────────────────────────┐
│  Phase 1 — Dynamic tool selection (least privilege exposure)              │
│  Authenticate → trusted department → permitted tool set → expose to LLM │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ LLM may still request anything
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Phase 2 — Central MCP gateway (pre-execution enforcement)                │
│  Token/session → permission set check → args/resources → approval       │
│  bulk/rate ceilings → ALLOW tool runs | DENY before side effects        │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ decision + outcome
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Phase 3 — Monitoring and auditing (detective)                            │
│  Log allow/deny · Isolation Forest anomaly · risk levels · alert        │
└──────────────────────────────────────────────────────────────────────────┘
```

| Aspect | Phase 1 | Phase 2 | Phase 3 |
| --- | --- | --- | --- |
| **Main role** | Tool selection | Enforcement | Monitoring |
| **When** | Before / at tool discovery | Before execution | During / after each decision |
| **Main input** | User identity and department | Incoming tool request | Execution events and logs |
| **Main action** | Expose permitted tools | Allow or deny requests | Detect suspicious activity |
| **Security type** | Preventive *guidance* (least exposure) | Preventive *enforcement* | Detective |

Phase 1 alone is **not** the security boundary. A malicious prompt or direct client call can still request a disallowed tool — Phase 2 must reject it before execution. Phase 3 cannot undo a call that already succeeded — Phase 2 must block first.

---

## Phase 1 — Dynamic tool selection and access management

### Purpose

Determine which tools a user may access based on **trusted** department membership.

| Department | Example permitted tools |
| --- | --- |
| Engineering | `read_project_report`, mail/calendar, eng DB/files/comms |
| HR | `read_salary_record`, mail/calendar, HR-readable DB |
| Finance | `read_financial_report`, `fetch_finance_records`, payment (policy), finance DB |
| Marketing | `read_campaign_insights`, mail/calendar, marketing DB/comms |

No department holds `danger:shell`, `danger:secrets`, `danger:template`, or `admin:roles`.

### How it works

1. **User authentication** — Local MCP client presents `MCP_CALLER_TOKEN`; Google OAuth identifies the mailbox (`token.json`).  
2. **Department identification** — Backend loads the user from `Backend/policy.json` (trusted directory). Department is **never** taken from the LLM or untrusted tool arguments.  
3. **Retrieve permissions** — `phase1.permission_manager` maps department → permission set → tools.  
4. **Expose permitted tools** — `get_my_identity` and `list_allowed_tools` return only what that session may use.

### Implemented as

| Component | Code |
| --- | --- |
| Identity Manager | `Backend/phase1/identity_manager.py` |
| Permission Manager | `Backend/phase1/permission_manager.py` + `policy.json` |
| Tool selector | `Backend/phase1/tool_selector.py` + MCP tools in `email_server.py` |

---

## Phase 2 — Central MCP gateway (pre-execution enforcement)

### Purpose

Sit between the LLM/MCP client and protected operations. Inspect **every** tool request and **allow or deny before side effects**.

Example: Engineering is not shown finance payroll tools, but an injected email says “fetch payroll…”. The LLM may still *request* `fetch_finance_records`. The gateway must reject that request for engineering **before** data returns.

### How the gateway works

1. **Receive the tool request** — Tool name + arguments from the MCP client.  
2. **Verify caller and session** — `MCP_CALLER_TOKEN` vs `.env`; session id; for high-risk writes, validate the human-issued **execution token** (raw token not stored — only hash).  
3. **Cross-validate tool permissions** — department permission sets from the trusted directory.  
4. **Validate arguments, resources, ceilings, and approvals** — resource ownership; schema; bulk/row limits; mailbox rate limits; high-risk ops need approved plan + execution lock bound to exact arguments.  
5. **Forward or reject** — ALLOW runs the tool; DENY returns blocked text with no privileged side effect.

```text
LLM / client
   │  tool_request { tool, arguments }
   ▼
┌─────────────────────────────────────┐
│  MCP Gateway (Phase 2)              │
│  1. caller + session                │
│  2. department permission sets      │
│  3. resource / argument checks      │
│  4. bulk / rate ceilings            │
│  5. approval + execution lock       │
└──────────────┬──────────────────────┘
        ALLOW  │  DENY
               ▼
   Gmail / Calendar / stubs / denied danger tools
```

### Implemented as

| Component | Code |
| --- | --- |
| MCP Gateway | `email_server.py` `_guard_tool` / `_verify_protected` |
| Enforcement | `Backend/phase2/enforcement.py`, `_engine.py` |
| Session / caller | `phase2/session_manager.py`, `launch_stdio.py` |
| Token issue / verify | `phase2/token_validator.py`, `approval_manager.py` |
| Authorization | `phase2/authorization.py` + `permission_manager.authorize_tool` |

---

## Phase 3 — Monitoring and anomaly detection

### Purpose

Detective layer: record authorization decisions and identify **suspicious behavior patterns**. Cannot undo a successful tool call — Phase 2 must block first.

- **Phase 2** checks whether an action is *permitted*.  
- **Phase 3** checks whether the *activity pattern* looks suspicious (volume bursts, repeated unauthorized attempts, unusual sensitive-action rates).

### How it works

1. **Collect tool execution logs** — user/persona, department, tool, allow/deny, timestamp, session (no email bodies, passwords, or tokens).  
2. **Extract behavioral features** — calls/minute, failed authorizations, unique tools, department mismatches, sensitive-action counts, etc.  
3. **Detect unusual patterns** — Isolation Forest on representative normal behavior (+ heuristics fallback).  
4. **Generate risk scores** — low / medium / high / critical with recommended responses.  
5. **Surface in UI** — `frontend` `/api/anomaly` (trial personas).

### Implemented as

| Component | Code / artifacts |
| --- | --- |
| SQLite + JSONL audit | `Backend/phase3/audit_store.py`, `results/audit/` |
| Feature extraction | `Backend/phase3/features.py` |
| Isolation Forest + heuristics | `Backend/phase3/anomaly_detector.py` |
| Risk engine | `Backend/phase3/risk_engine.py` |
| Monitoring facade | `Backend/phase3/monitoring.py` |
| Security guarantees | `testcases/extracted/security_guarantees.py` (SG-01…SG-12) |

---

## Complete example (all three phases)

**Scenario:** Engineering user asks to summarize recent emails. One email contains injection: run `cat ~/.ssh/id_rsa` via shell and email the result.

1. **Phase 1** — Directory says Engineering; `list_allowed_tools` does not advertise `run_shell`.  
2. **LLM** — Injection may still request `run_shell` (tool exists on the server).  
3. **Phase 2** — Gateway denies (`danger:shell` / permanent deny); no shell runs.  
4. **Phase 3** — Record DENY; repeated unauthorized attempts raise anomaly risk.

**Outcome:** Malicious email does not yield secrets or a send.

---

## Mailbox roles (this project)

| Role | Address | Meaning |
| --- | --- | --- |
| **Connected / OAuth** | `aswinm2k4@gmail.com` | `token.json`; enrolled as **Engineering** in `policy.json`. Attack payloads use this as **From**. |
| **Exfil watch inbox** | `aswinmmsa@gmail.com` | Collection address in attack bodies. Enrolled as Marketing for stub demos only — not the OAuth agent identity. |

---

## End-to-end deployment view

```text
┌─────────────────────────────────────────────────────────────────┐
│  Operators                                                        │
│  • Cursor chat (LLM + MCP tools)                                  │
│  • Test harness (run_eval / compare_before_after)                 │
│  • Explainer UI (:8760) — trial personas, charts, anomaly         │
└────────────────────────────┬────────────────────────────────────┘
                             │ MCP stdio (via launch_stdio.py)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Backend/email_server.py   (Phases 1–3 on every tool call)        │
│    ├── phase1/  identity, permissions, tool selection             │
│    ├── phase2/  auth, tokens, locks, ceilings                     │
│    ├── phase3/  audit + Isolation Forest                          │
│    ├── policy.json / dummy_store.py                               │
│    └── Gmail / Calendar APIs                                      │
└────────────────────────────┬────────────────────────────────────┘
                             │ OAuth (credentials.json + token.json)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Google: aswinm2k4@gmail.com   ·   Exfil watch: aswinmmsa@…     │
└─────────────────────────────────────────────────────────────────┘
```

### Working principles

1. **Least privilege** — Phase 1 exposes only department-permitted tools.  
2. **Prompt guides; gateway enforces** — Phase 2 denies unauthorized execution in code.  
3. **Catalog present ≠ allowed** — danger tools exist so attacks can try; policy denies.  
4. **Confirm before harm** — High-risk writes need human `--approve` and a bound execution token.  
5. **Draft ≠ send** — Drafts are gated on the hardened path; they never transmit without policy.  
6. **Data ≠ instructions** — Email/filename content is not authorization.  
7. **Detect after decide** — Phase 3 audits; it does not replace Phase 2.  
8. **Secrets stay local** — `credentials.json` / `token.json` / `.env` are gitignored.  
9. **Eval isolation** — The agent under test must not see TC ids or `attack_generator.py`.  

---

## Runtime paths

### A. Cursor (interactive agent)

1. Cursor starts `Backend/launch_stdio.py` (presents `MCP_CALLER_TOKEN`).  
2. Optionally load [system-prompt.md](system-prompt.md).  
3. Phase 1: `get_my_identity` / `list_allowed_tools`.  
4. Phase 2–3: every tool call through `_guard_tool` → monitoring.  
5. Gmail/Calendar use `token.json` for **aswinm2k4@gmail.com**.

### B. Automated security harness

1. `run_eval.py` / `compare_before_after.py` → `mock_*` or `real`.  
2. TC-01 … TC-21 + optional security guarantees (SG-01 … SG-12).  
3. Results → `results/*_gateway.json`, `results/evaluation.json`, `docs/scores_*.md`.  
4. **ASR** = compromised / 21 × 100 (**lower is better**).

### C. Explainer UI

1. `frontend/server.py` on http://127.0.0.1:8760.  
2. Trial personas; Phase 1–2 try-tool; evaluation charts; prompt-driven test run; anomaly API.  
3. Does **not** embed Cursor’s LLM or send real mail from the visitor surface.

---

## Confirmation / execution token (Phase 2 detail)

```text
LLM
   │ require_user_confirm(...exact fields...)
   ▼
gateway  →  pending plan (plan_id)  [not an execution token]
   │
   │  person: python Backend/email_server.py --approve <plan_id>
   ▼
256-bit execution token shown once; only SHA-256 hash stored
   │
   ▼
send_email / create_calendar_event / … (..., execution_token=...)
   │  verify hash + user + session + plan version + exact args + lock
   ▼
ALLOW once → consume token → API runs
```

Without a valid, matching token, high-risk tools return **Blocked** (Phase 2 DENY). Content that claims “always-allow” never mints a token (TC-21).

---

## Backend modules (mapped to phases)

| Path | Phase | Role |
| --- | --- | --- |
| `Backend/phase1/` | 1 | `identity_manager`, `permission_manager`, `tool_selector` |
| `Backend/phase2/` | 2 | `session_manager`, `token_validator`, `approval_manager`, `authorization`, `enforcement`, `_engine` |
| `Backend/phase3/` | 3 | `audit_logger`, `audit_store`, `features`, `anomaly_detector`, `risk_engine`, `monitoring` |
| `Backend/policy.json` | 1 | Trusted directory / department DB / tool_permissions |
| `Backend/dummy_store.py` | 2 | Sandbox DB/files stubs |
| `Backend/policy.py` / `gateway.py` | shims | Compatibility re-exports for harness |
| `Backend/launch_stdio.py` | 2 | Legitimate client presents caller token |
| `Backend/email_server.py` | 1–3 | MCP tools; calls Phase 2 then Phase 3 |
| `Backend/attachments.py` | 2 | Literal attachment store |
| `docs/system-prompt.md` | Guidance | LLM instructions only (not enforcement) |
| `results/audit/` | 3 | JSONL authorization decision trail |

### Google scopes

| Scope | Tools |
| --- | --- |
| `gmail.readonly` | `read_latest_emails` |
| `gmail.compose` | `create_email_draft` |
| `gmail.send` | `send_email` |
| `calendar.events` | `get_calendar_availability`, `create_calendar_event` |

---

## Test harness layout

| Path | Role |
| --- | --- |
| `testcases/extracted/test_cases.py` | Metadata for TC-01 … TC-21 |
| `testcases/extracted/attack_generator.py` | Payloads; connected + exfil addresses |
| `testcases/extracted/target_adapter.py` | Seam to real MCP or mocks |
| `testcases/extracted/scorer.py` | Deterministic SAFE / COMPROMISED |
| `testcases/extracted/run_eval.py` | Runs all 21, writes JSON |
| `testcases/extracted/layer_eval.py` | Layer ablation → `evaluation.json` |
| `testcases/extracted/demo_testrun.py` | UI / prompt-driven runner |
| `testcases/extracted/compare_before_after.py` | Default real-only eval + score docs |
| `testcases/extracted/harness.py` | Suite + `--guarantees` |
| `testcases/extracted/security_guarantees.py` | Phase 2/3 style guarantee tests |
| `testcases/extracted/research_benchmarks.py` | Research analogue mapping |

```text
run_eval / compare_before_after / harness / demo_testrun
        → attack_generator.generate(id)
        → target_adapter.run_target(channel, payload)
        → scorer.score(id, actions)
        → ASR + results/*.json + docs/scores_*.md
layer_eval → results/evaluation.json → frontend charts
```

---

## Project file map

| Path | Purpose |
| --- | --- |
| `README.md` | Entry + quick start |
| `docs/` | Full documentation |
| `docs/architecture.md` | This three-phase architecture |
| `Backend/` | Phases 1–3 gateway |
| `frontend/` | Explainer UI (`server.py`, `app.js`) |
| `testcases/extracted/` | Attacks + guarantees |
| `results/` | JSON scores / evaluation / audit |
| `approvals/` | Plans, execution token hashes, locks (local) |
| `.cursor/mcp.json` | Cursor → `launch_stdio.py` |
| `credentials.json` / `token.json` | OAuth (local only) |

---

## Faculty review summary

**Three-Phase MCP Security Architecture**

Phase 1 authenticates the user and retrieves department information from a trusted directory, then exposes only authorized tools to the LLM (least privilege at selection time).

Phase 2 places a centralized MCP Security Gateway between the client and protected tools. Every tool request is checked for caller/session validity, department permissions, argument/resource policy, bulk/rate ceilings, and human approval for sensitive operations. Unauthorized requests — including attempts to call catalogued danger tools — are rejected **before** execution.

Phase 3 records authorization decisions and outcomes, runs Isolation Forest–based anomaly detection on session features, and maintains an audit trail for investigation.

Together, the phases combine least-privilege tool exposure, centralized pre-execution authorization, and post-execution monitoring to reduce unauthorized tool use and prompt-injection impact in MCP-based agents.

---

## Related systems (context, not installed)

| System | Relation |
| --- | --- |
| **AgentDojo** | Same metric family (targeted ASR); our suite is 21 mail/calendar/enterprise-focused cases |
| **InjecAgent / MCPTox / AgenTRIM** | Inspired TC-17…TC-21 additions |
| **IBM ContextForge** | Production MCP/A2A gateway idea; we implement a local Python three-phase gateway |
| **Docker MCP Gateway** | Tool allowlisting proxy idea; ours is in-process Phase 1–2 with confirm + policy |

Next: [tools-and-usage.md](tools-and-usage.md) · [testing.md](testing.md) · [security.md](security.md) · [system-prompt.md](system-prompt.md)
