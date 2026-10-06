# MCP Security Gateway

Least-privilege MCP bridge between **Cursor’s LLM** and your **Gmail + Google Calendar**.

The model can read mail, save drafts, send mail (with confirmation), check your calendar, create events on **your** calendar only (with confirmation), and store attachments as **literal** filenames. Finance, payroll, passwords, and shell access are not exposed.

---

## Documentation

Full docs live in [`docs/`](docs/README.md):

| Doc | Contents |
| --- | --- |
| [docs/overview.md](docs/overview.md) | What / why |
| [docs/setup.md](docs/setup.md) | Clone → OAuth → Cursor |
| [docs/architecture.md](docs/architecture.md) | Design + every file |
| [docs/tools-and-usage.md](docs/tools-and-usage.md) | Tools, CLI, chat examples |
| [docs/testing.md](docs/testing.md) | 8 security test cases |
| [docs/security.md](docs/security.md) | Secrets + what you can claim |

Also: [`implementation.md`](implementation.md) and [`test.md`](test.md) point into `docs/`.

---

## Quick start

1. Clone the repo and install deps (`uv sync` or `python -m venv .venv` + `pip install -e .`).  
2. Enable **Gmail API** and **Calendar API** on a Google Cloud project.  
3. OAuth consent screen = **Testing**; add yourself as a **test user**.  
4. Create a **Desktop** OAuth client → save as `credentials.json` in the project root.  
5. Login once:

```powershell
.\.venv\Scripts\python.exe Backend\email_server.py --login
```

6. Edit `.cursor/mcp.json` paths for your machine → **Settings → MCP** → enable **gmail**.  
7. In chat: `What tools are allowed?` / `Read my latest emails`.

**Details:** [docs/setup.md](docs/setup.md).

---

## Tools (summary)

| Tool | Confirm? |
| --- | --- |
| `list_allowed_tools` | No |
| `require_user_confirm` | No |
| `read_latest_emails` | No |
| `create_email_draft` | No |
| `send_email` | **Yes** |
| `get_calendar_availability` | No |
| `create_calendar_event` | **Yes** |
| `store_attachment` | No |

---

## Commands

| Command | Purpose |
| --- | --- |
| `python Backend/email_server.py --login` | Create `token.json` |
| `python Backend/email_server.py` | Print inbox in terminal |
| `python Backend/email_server.py --stdio` | MCP for Cursor |
| `python Backend/email_server.py --serve` | Optional HTTP MCP |

---

## Testing (one command)

```powershell
cd testcases\extracted
..\..\.venv\Scripts\python.exe harness.py
```

Default = **vulnerable mock** (~100% ASR). That is not the live Cursor agent. See [docs/testing.md](docs/testing.md).

---

## Layout

```text
Security/
  README.md
  docs/                     ← full documentation
  Backend/
    email_server.py         ← MCP entry
    gateway.py              ← allowlist + confirm
    attachments.py          ← literal file store
  testcases/extracted/      ← security harness
  .cursor/mcp.json
  credentials.json          ← you add (gitignored)
  token.json                ← from --login (gitignored)
```

---

## Security

- Never commit `credentials.json` or `token.json`.  
- Each clone needs its own Google OAuth client and login.  
- Do not report mock 0% ASR as a live-agent result.  

More: [docs/security.md](docs/security.md).
