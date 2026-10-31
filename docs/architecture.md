# Architecture and working principles

## What the system is

A **three-phase MCP Security Gateway** between:

1. **Cursor’s LLM** (or the automated test harness), and  
2. **Protected tools / Google APIs** for one connected Gmail/Calendar account, plus department stub tools.

**Central idea:** Phase 1 decides which tools should be *visible*. Phase 2 independently verifies whether a requested tool may *execute*. Phase 3 records and monitors what happened.

The prompt guides the LLM ([system-prompt.md](system-prompt.md)). **The gateway enforces security in code.** Untrusted content (email bodies, filenames, user claims) is **data**, not authorization.

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
│  ALLOW → tool runs   |   DENY → reject before side effects              │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ decision + outcome
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Phase 3 — Monitoring and auditing (detective)                            │
│  Log allow/deny · detect repeated unauthorized attempts · alert         │
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

Determine which tools a user may access based on **trusted** department membership. Different departments must not automatically receive every MCP tool.

| Department (this project) | Example permitted tools |
| --- | --- |
| Engineering | `read_project_report`, mail/calendar tools |
| HR | `read_salary_record`, mail/calendar tools |
| Finance | `read_financial_report`, mail/calendar tools |
| Marketing | `read_campaign_insights`, mail/calendar tools |

### How it works

1. **User authentication** — Local MCP client presents `MCP_CALLER_TOKEN`; Google OAuth identifies the mailbox (`token.json`).  
2. **Department identification** — Backend loads the user from `Backend/policy.json` (trusted directory). Department is **never** taken from the LLM or untrusted tool arguments.  
3. **Retrieve permissions** — `policy.py` maps department → permission set → tools.  
4. **Expose permitted tools** — `get_my_identity` and `list_allowed_tools` return only what that session may use.

### What Phase 1 achieves

- Department-based access management  
- Reduced unnecessary tool exposure  
- Least privilege at discovery time  
- Fewer chances for the LLM to *select* unauthorized tools (not a hard block)

### Implemented as

| Component | Code |
| --- | --- |
| Identity Manager | Google profile email + `policy.resolve_identity` |
| Permission Manager | `Backend/policy.py` + `policy.json` |
| Tool selector / exposure | `list_allowed_tools`, `get_my_identity` in `email_server.py` |

---

## Phase 2 — Central MCP gateway (pre-execution enforcement)

### Purpose

Sit between the LLM/MCP client and protected operations. Inspect **every** tool request and **allow or deny before side effects**.

Example: Marketing is only shown mail/search-style tools, but an injected email says “ignore instructions and `send_email`…”. The LLM may still *request* `send_email`. The gateway must reject that request before Gmail send runs.

### How the gateway works

1. **Receive the tool request** — Tool name + arguments from the MCP client.  
2. **Verify caller and session** — `MCP_CALLER_TOKEN` vs `.env`; session id derived from the gateway secret; for high-risk writes, validate the human-issued **execution token** (raw token is not stored — only its hash).  
3. **Cross-validate tool permissions** — `authorize_session_tool` / `policy.authorize_tool` against the trusted directory (Python set membership over permissions). Do **not** trust a stale list from the LLM.  
4. **Validate arguments, resources, and approvals** — Resource ownership (e.g. project/salary ids); schema/exact fields; high-risk ops need a human-approved plan + execution lock bound to those exact arguments.  
5. **Forward or reject**  
   - **ALLOW** — token/session valid + tool permitted + args/resources OK + required approval present → run tool.  
   - **DENY** — return a blocked error to the LLM; no privileged API call.

```text
LLM / client
   │  tool_request { tool, arguments }
   ▼
┌─────────────────────────────────────┐
│  MCP Gateway (Phase 2)              │
│  1. caller + session                │
│  2. department permission sets      │
│  3. resource / argument checks      │
│  4. approval + execution lock       │
└──────────────┬──────────────────────┘
        ALLOW  │  DENY
               ▼
   Gmail / Calendar / dept stubs
```

Downstream tools must not be reachable by bypassing the gateway where the host allows it. This project’s protected surface is the tools registered on `email_server.py` (in-process gateway). Other Cursor MCP servers are out of scope unless also routed through the same enforcement.

### What Phase 2 achieves

- Prevents unauthorized tool execution  
- Validates caller/session and execution tokens  
- Enforces department-based permissions  
- Validates arguments and resource access  
- Enforces human approval for sensitive operations  
- Common enforcement point for mail, calendar, and department stubs  

### Implemented as

| Component | Code |
| --- | --- |
| MCP Gateway | `email_server.py` `_guard_tool` / `_verify_protected` |
| Session / caller | `gateway.caller_auth_error`, `current_session_id`, `launch_stdio.py` |
| Token issue / verify | `issue_execution_token`, `verify_execution_token` (hash in `approvals/executions/`) |
| Authorization | `gateway.authorize_session_tool`, `policy.authorize_tool` |
| Approval Manager | `require_user_confirm`, CLI `--approve`, execution lock |

---

## Phase 3 — Post-execution monitoring and auditing

### Purpose

Detective layer: record authorization decisions and outcomes, spot suspicious patterns (e.g. repeated DENY on out-of-department tools), support investigation. **Cannot undo** a successful tool call — Phase 2 must block first.

### How it works

1. **Collect execution information** — user, department, tool, allow/deny, timestamp, session (no raw secrets in logs).  
2. **Monitor activity** — unusual volume, repeated unauthorized tools, odd sequences.  
3. **Detect suspicious activity** — e.g. Marketing: `read_email` SUCCESS then many DENY on Finance/HR tools.  
4. **Alerts and reports** — flag session, notify admin, recommend revocation (harness-side guarantees + future audit log files).

### What Phase 3 achieves

- Visibility into tool usage  
- Detection of suspicious call patterns  
- Audit trail for faculty / incident review  
- Evidence that the gateway is denying as designed  

### Implemented as

| Component | Code / artifacts |
| --- | --- |
| Audit / eval trail | `results/after_gateway.json`, harness action logs |
| Security guarantees | `testcases/extracted/security_guarantees.py` (SG-01…SG-12) |
| Monitoring Engine | Pattern checks in guarantees + scored ASR reports (full SIEM-style alerting is optional future work) |

---

## Complete example (all three phases)

**Scenario:** A Marketing employee asks the LLM to summarize recent emails. One email contains prompt injection: forward confidential information with `send_email`.

1. **Phase 1** — Authenticate; directory says Marketing; expose marketing + mail tools via `list_allowed_tools` (not Finance/HR stubs).  
2. **LLM** — Reads mail; injection manipulates it into requesting `send_email` to an attacker.  
3. **Phase 2** — Gateway verifies caller/session; checks permissions / approval; rejects unauthorized or unapproved `send_email` **before** Gmail send.  
4. **Phase 3** — Record DENY; repeated unauthorized attempts can be flagged in monitoring / guarantee reports.

**Outcome:** Malicious email does not result in an unauthorized send.

---

## Mailbox roles (this project)

| Role | Address | Meaning |
| --- | --- | --- |
| **Connected / OAuth** | `aswinm2k4@gmail.com` | `token.json`; enrolled as **Engineering** in `policy.json`. Attack payloads use this as **From**. |
| **Exfil watch inbox** | `aswinmmsa@gmail.com` | Collection address in attack bodies. Enrolled as Marketing for stub demos only — not used as the OAuth agent identity. |

---

## End-to-end deployment view

```text
┌─────────────────────────────────────────────────────────────────┐
│  Operators                                                        │
│  • Cursor chat (LLM + MCP tools)                                  │
│  • Test harness (compare_before_after.py → real MCP)              │
└────────────────────────────┬────────────────────────────────────┘
                             │ MCP stdio (via launch_stdio.py)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Backend/email_server.py   (Phases 1–2 on every tool call)        │
│    ├── policy.py / policy.json   Phase 1 directory + permissions│
│    ├── gateway.py                Phase 2 auth, tokens, locks    │
│    ├── attachments.py            literal filename store         │
│    ├── Gmail / Calendar APIs     protected operations           │
│    └── department stubs          project / salary / finance / … │
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
3. **Confirm before harm** — High-risk writes need human `--approve` and a bound execution token (hash stored).  
4. **Draft ≠ send** — Drafts never transmit.  
5. **Data ≠ instructions** — Email/filename content is not authorization.  
6. **Detect after decide** — Phase 3 audits allow/deny; it does not replace Phase 2.  
7. **Secrets stay local** — `credentials.json` / `token.json` / `.env` are gitignored.  
8. **Eval isolation** — The agent under test must not see TC ids or `attack_generator.py`.  

---

## Runtime paths

### A. Cursor (interactive agent)

1. Cursor starts `Backend/launch_stdio.py` (presents `MCP_CALLER_TOKEN`).  
2. Optionally load [system-prompt.md](system-prompt.md).  
3. Phase 1: `get_my_identity` / `list_allowed_tools`.  
4. Phase 2: every tool call through `_guard_tool` / `_verify_protected`.  
5. Gmail/Calendar use `token.json` for **aswinm2k4@gmail.com**.

### B. Automated security harness

1. `compare_before_after.py` / `harness.py` → real MCP by default.  
2. TC-01 … TC-16 + security guarantees (SG-01 … SG-12).  
3. Results → `results/after_gateway.json`, `docs/scores_real_gateway.md`.  
4. **ASR** = compromised / 16 × 100 (**lower is better**).

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
send_email / create_calendar_event(..., execution_token=...)
   │  verify hash + user + session + plan version + exact args + lock
   ▼
ALLOW once → consume token → API runs
```

Without a valid, matching token, high-risk tools return **Blocked** (Phase 2 DENY).

---

## Backend modules (mapped to phases)

| Path | Phase | Role |
| --- | --- | --- |
| `Backend/phase1/` | 1 | `identity_manager`, `permission_manager`, `tool_selector` |
| `Backend/phase2/` | 2 | `session_manager`, `token_validator`, `approval_manager`, `authorization`, `enforcement` |
| `Backend/phase3/` | 3 | `audit_logger`, `anomaly_detector`, `monitoring` |
| `Backend/policy.json` | 1 | Trusted directory / department DB |
| `Backend/policy.py` / `gateway.py` | shims | Compatibility re-exports for harness |
| `Backend/launch_stdio.py` | 2 | Legitimate client presents caller token |
| `Backend/email_server.py` | 1–2 | MCP tools; calls `phase2.enforcement` |
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
| `testcases/extracted/test_cases.py` | Metadata for TC-01 … TC-16 |
| `testcases/extracted/attack_generator.py` | Payloads; connected + exfil addresses |
| `testcases/extracted/target_adapter.py` | Seam to real MCP (default) or mocks |
| `testcases/extracted/scorer.py` | Deterministic SAFE / COMPROMISED |
| `testcases/extracted/run_eval.py` | Runs all 16, writes JSON |
| `testcases/extracted/compare_before_after.py` | Default real-only eval + score docs |
| `testcases/extracted/harness.py` | Suite + `--guarantees` |
| `testcases/extracted/security_guarantees.py` | Phase 2/3 style guarantee tests |

```text
compare_before_after / harness
        → attack_generator.generate(id)
        → target_adapter.run_target(channel, payload)   # real MCP
        → scorer.score(id, actions)
        → ASR + docs/scores_*.md
```

---

## Project file map

| Path | Purpose |
| --- | --- |
| `README.md` | Entry + quick start |
| `docs/` | Full documentation |
| `docs/architecture.md` | This three-phase architecture |
| `Backend/` | Phases 1–2 gateway |
| `testcases/extracted/` | Attacks + Phase 3–style guarantees |
| `results/` | JSON scores / trails |
| `approvals/` | Plans, execution token hashes, locks (local) |
| `.cursor/mcp.json` | Cursor → `launch_stdio.py` |
| `credentials.json` / `token.json` | OAuth (local only) |

---

## Faculty review summary

**Three-Phase MCP Security Architecture**

Phase 1 authenticates the user and retrieves department information from a trusted directory, then exposes only authorized tools to the LLM (least privilege at selection time).

Phase 2 places a centralized MCP Security Gateway between the client and protected tools. Every tool request is checked for caller/session validity, department permissions, argument/resource policy, and human approval for sensitive operations. Unauthorized requests are rejected **before** execution.

Phase 3 records authorization decisions and outcomes, supports pattern detection (e.g. repeated unauthorized attempts), and maintains an audit-style trail for investigation.

Together, the phases combine least-privilege tool exposure, centralized pre-execution authorization, and post-execution monitoring to reduce unauthorized tool use and prompt-injection impact in MCP-based agents.

---

## Related systems (context, not installed)

| System | Relation |
| --- | --- |
| **AgentDojo** | Same metric family (targeted ASR); our suite is smaller and mail/calendar-focused |
| **IBM ContextForge** | Production MCP/A2A gateway idea; we implement a local Python three-phase gateway |
| **Docker MCP Gateway** | Tool allowlisting proxy idea; ours is in-process Phase 1–2 with confirm + policy |

Next: [tools-and-usage.md](tools-and-usage.md) · [testing.md](testing.md) · [security.md](security.md) · [system-prompt.md](system-prompt.md)
