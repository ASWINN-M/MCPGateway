# Architecture

## System diagram

```text
You (Cursor chat)
        │
        ▼
   Cursor LLM
        │  MCP stdio
        ▼
Backend/email_server.py     ← only process that talks to Google
   ├── gateway.py           ← allowlist + confirmation tokens
   ├── attachments.py       ← safe local filename store
   ├── Gmail API            ← inbox, drafts, send
   └── Calendar API         ← primary calendar only
        │
        ▼
credentials.json + token.json   (local only, not in Git)
```

Cursor starts `email_server.py --stdio` when the **gmail** MCP server is enabled. Google login is done once with `--login`; afterward `token.json` is reused.

---

## Backend modules

| File | Role |
| --- | --- |
| `Backend/email_server.py` | MCP server entry point. OAuth, Gmail/Calendar clients, all `@mcp.tool()` functions |
| `Backend/gateway.py` | Fixed `ALLOWED_TOOLS` and in-memory `confirm_token` for high-risk tools |
| `Backend/attachments.py` | Writes files under `attachments/` with literal filenames (no template eval) |

### How confirmation works

1. LLM calls `require_user_confirm(action, summary)`.  
2. Gateway stores a random token in memory.  
3. User approves the summary in chat.  
4. LLM calls `send_email` / `create_calendar_event` with `confirm_token`.  
5. Gateway consumes the token (one-time) and allows the call.

Tokens are **not** written to disk. Restarting the MCP process clears pending tokens.

---

## Google scopes

| Scope | Tools |
| --- | --- |
| `gmail.readonly` | `read_latest_emails` |
| `gmail.compose` | `create_email_draft` |
| `gmail.send` | `send_email` |
| `calendar.events` | `get_calendar_availability`, `create_calendar_event` |

---

## Project file map

### Root

| Path | Purpose |
| --- | --- |
| `README.md` | Short entry + links to docs |
| `docs/` | Full documentation (this folder) |
| `implementation.md` | Pointer to architecture / overview |
| `test.md` | Pointer to testing docs |
| `pyproject.toml` / `uv.lock` / `requirements.txt` | Dependencies |
| `main.py` | Unused starter; real entry is `Backend/email_server.py` |
| `.gitignore` | Ignores `.venv`, secrets, attachments |
| `.env.example` | Placeholder only (server uses `credentials.json`) |
| `credentials.json` | OAuth client — **you** add; never commit |
| `token.json` | Session after `--login` — never commit |
| `attachments/` | Local store for `store_attachment` |

### Cursor

| Path | Purpose |
| --- | --- |
| `.cursor/mcp.json` | Command/args to start the MCP server |

### Test suite

| Path | Purpose |
| --- | --- |
| `testcases/files.zip` | Original harness archive |
| `testcases/extracted/test_cases.py` | Case metadata (ids, goals) |
| `testcases/extracted/attack_generator.py` | Builds payloads |
| `testcases/extracted/target_adapter.py` | **Only** seam to the agent under test |
| `testcases/extracted/scorer.py` | SAFE / COMPROMISED from tool-call logs |
| `testcases/extracted/harness.py` | Runs all 8 cases, prints ASR |

**Isolation rule:** the agent must never import `test_cases.py` or `attack_generator.py`. It only sees raw payloads.

---

## Design choices

1. **Small allowlist** — unknown tools do not exist.  
2. **Human confirm for send / calendar create**.  
3. **Own calendar only** — no guests, no external share.  
4. **Draft ≠ send**.  
5. **Filenames are data** — `{{...}}` / `${...}` are not evaluated.  
6. **Secrets stay local** — OAuth files gitignored.

Next: [tools-and-usage.md](tools-and-usage.md) · [testing.md](testing.md) · [security.md](security.md)
