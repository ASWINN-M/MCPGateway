# MCP Security Gateway

Least-privilege **three-phase** MCP bridge between **Cursor’s LLM** and **Gmail + Google Calendar**, plus department stubs, dummy DB/file/comms tools, and a catalog of high-risk tools that exist so injections can attempt them — Phase 2 denies them in code.

**Working principle:** (1) expose only department-permitted tools, (2) allow/deny before execution (permissions, args, confirmation tokens, rate/bulk ceilings), (3) audit + Isolation Forest anomaly detection. The prompt guides; the gateway enforces.

| Role | Address |
| --- | --- |
| Connected / attacking mail (OAuth) | `aswinm2k4@gmail.com` |
| Exfil / attacked inbox (watch) | `aswinmmsa@gmail.com` |

Trial personas for the explainer UI use `@example.com` (no real names/emails in the visitor surface).

---

## Documentation

| Doc | Contents |
| --- | --- |
| [docs/overview.md](docs/overview.md) | What / why / principles |
| [docs/setup.md](docs/setup.md) | Clone → OAuth → Cursor |
| [docs/architecture.md](docs/architecture.md) | Three-phase architecture |
| [docs/tools-and-usage.md](docs/tools-and-usage.md) | Full tool catalog |
| [docs/testing.md](docs/testing.md) | **21-attack** harness + evaluation UI |
| [docs/scores_before_after_gateway.md](docs/scores_before_after_gateway.md) | Before vs after ASR |
| [docs/scores_real_gateway.md](docs/scores_real_gateway.md) | Latest hardened-run detail |
| [docs/security.md](docs/security.md) | Secrets + reporting honesty |

Index: [`docs/README.md`](docs/README.md). Pointers: [`implementation.md`](implementation.md) · [`test.md`](test.md).

---

## Quick start

1. Clone and install (`uv sync` or venv + `pip install -e .`).  
2. Enable **Gmail API** + **Calendar API**.  
3. OAuth consent = **Testing**; add `aswinm2k4@gmail.com` as test user.  
4. Desktop OAuth client → `credentials.json` in project root.  
5. Login **as the connected account**:

```powershell
.\.venv\Scripts\python.exe Backend\email_server.py --login
```

6. Edit `.cursor/mcp.json` → **Settings → MCP** → enable **gmail**.  
7. Chat: `What tools are allowed?` / `Read my latest emails`.

Details: [docs/setup.md](docs/setup.md).

---

## Tools (summary)

| Group | Examples | Notes |
| --- | --- | --- |
| Identity | `get_my_identity`, `list_allowed_tools` | Trusted directory department |
| Mail / calendar | `read_latest_emails`, `create_email_draft`, `send_email`, calendar tools | High-risk writes need execution token |
| Dept stubs | `read_project_report`, `read_salary_record`, `read_financial_report`, `read_campaign_insights` | Department-gated |
| Dummy enterprise | `db_*`, `file_*_sandbox`, `slack_post_message`, `payment_transfer` | Policy + confirm where high-risk |
| Attack-surface (catalog present) | `fetch_finance_records`, `run_shell`, `export_secrets`, `render_template`, `admin_grant_role` | **Present so attacks can try them**; Phase 2 denies (`danger:*` / wrong dept) |

Full table: [docs/tools-and-usage.md](docs/tools-and-usage.md).

---

## Commands

| Command | Purpose |
| --- | --- |
| `python Backend/email_server.py --login` | Create `token.json` |
| `python Backend/email_server.py` | Print inbox |
| `python Backend/email_server.py --stdio` | MCP for Cursor / harness |
| `python Backend/email_server.py --approve <plan_id>` | Human approval → execution token |
| `python frontend/server.py` | Explainer UI + live Phase 1–3 playground |

---

## Testing (21 cases)

Mock before/after (deterministic demo ASR):

```powershell
$env:MCP_HARNESS_TARGET='mock_vulnerable'
.\.venv\Scripts\python.exe testcases\extracted\run_eval.py --label before --out results\before_gateway.json --allow-mock
$env:MCP_HARNESS_TARGET='mock_hardened'
.\.venv\Scripts\python.exe testcases\extracted\run_eval.py --label after --out results\after_gateway.json --allow-mock
.\.venv\Scripts\python.exe testcases\extracted\layer_eval.py
```

Real gateway (no mock):

```powershell
cd testcases\extracted
Remove-Item Env:MCP_HARNESS_TARGET -ErrorAction SilentlyContinue
..\..\.venv\Scripts\python.exe compare_before_after.py
```

Current mock baseline in-repo: **before ASR 100% → after ASR 0%** on TC-01…TC-21 (SAFE via Phase 2 deny of present tools, not “tool missing”).

---

## Explainer UI

Phase 1–3 playground, evaluation charts, prompt-driven test run, anomaly view. Uses trial personas; does not embed Cursor’s LLM or send real mail from the UI:

```powershell
.\.venv\Scripts\python.exe frontend\server.py
```

Open http://127.0.0.1:8760

---

## Layout

```text
Security/
  README.md
  docs/                     architecture, testing, scores
  frontend/                 visitor explainer UI (:8760)
  Backend/
    phase1/                 identity, permissions, tool selection
    phase2/                 session, tokens, approval, enforcement
    phase3/                 audit, Isolation Forest anomaly, monitoring
    email_server.py         MCP tool surface
    dummy_store.py          sandbox DB/files stubs
    policy.json
  testcases/extracted/      21-attack harness + guarantees
  results/                  before/after/evaluation JSON + audit/
  .cursor/mcp.json
```

---

## Security

- Never commit `credentials.json` or `token.json`.  
- Label mock ASR as mock; do not claim product “CVE patches.”  
- Dangerous tools are **in catalog** and **denied** — SAFE ≠ missing tool.

More: [docs/security.md](docs/security.md) · [docs/architecture.md](docs/architecture.md).
