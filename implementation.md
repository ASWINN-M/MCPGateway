# Implementation

This document explains **what this project is**, **what was added**, and **what every file does**. Read this after `README.md` (setup) if you want to understand the system.

For how to run the security test suite, see [`test.md`](test.md).

---

## What this project is

This is a **least-privilege MCP gateway**. An LLM in Cursor can use a small, fixed set of tools to:

- read Gmail
- save a Gmail draft
- send Gmail (only after you confirm)
- read your primary Google Calendar
- create an event on **your** calendar only (only after you confirm)
- store a local attachment under a **literal** filename

The LLM does not get finance, payroll, passwords, a shell, or other people’s calendars. Those tools were never added.

**MCP** (Model Context Protocol) is how Cursor starts `Backend/email_server.py` and calls the tools listed below. You do not open a website to use the tools. You talk to the LLM; the LLM calls the tools.

---

## What was added (in order)

| Stage | What was added | Why |
| --- | --- | --- |
| Gmail MCP server | `read_latest_emails`, `send_email`, Google OAuth (`credentials.json` + `token.json`) | Let an LLM read and send mail through your own Google account |
| Setup docs | `README.md`, `.gitignore` | So a clone from GitHub can set up OAuth safely without committed secrets |
| Extra tools | Drafts, calendar, attachments, gateway allowlist + confirmation | Match a realistic multi-tool agent and the security test cases |
| Test harness | `testcases/` (zip + extracted Python suite) | Measure whether an agent treats untrusted content as data, not as commands |
| This documentation | `implementation.md`, `test.md` | Explain the design and how to run tests |

---

## How the pieces connect

```text
You (chat in Cursor)
        │
        ▼
   Cursor LLM
        │  MCP (--stdio)
        ▼
Backend/email_server.py          ← only process that talks to Google
   ├── gateway.py                ← allowlist + confirm tokens
   ├── attachments.py            ← safe local file store
   ├── Gmail API                 ← inbox, drafts, send
   └── Calendar API              ← your primary calendar only
        │
        ▼
credentials.json  +  token.json  (local, not in Git)
```

Google login happens **once** with `--login`. After that, `token.json` is reused. Cursor starts the server with `--stdio` when the **gmail** MCP server is enabled.

---

## Tools (what the LLM can call)

| Tool | What it does | Needs confirm? |
| --- | --- | --- |
| `list_allowed_tools` | Prints the allowlist and what is **not** available | No |
| `require_user_confirm` | Creates a one-time `confirm_token` for a high-risk action | No |
| `read_latest_emails` | Latest inbox From / Subject | No |
| `create_email_draft` | Saves a draft. Does **not** send | No |
| `send_email` | Sends mail | **Yes** |
| `get_calendar_availability` | Events on **your** primary calendar in a time range | No |
| `create_calendar_event` | Event on **your** primary calendar only. No guests, no external share | **Yes** |
| `store_attachment` | Writes text under a filename in `attachments/` | No |

### Confirmation rule

`send_email` and `create_calendar_event` refuse to run unless:

1. The LLM calls `require_user_confirm` with a short summary.
2. You approve that summary.
3. The LLM calls the tool again with the returned `confirm_token`.

The token lives only in memory for that server process. It is not written to disk.

### Attachment rule

`store_attachment` treats the filename as **text**. It does not evaluate `{{...}}` or `${...}`. Paths like `../` are stripped so files stay inside `attachments/`. Windows-illegal characters are replaced so the file can still be saved.

---

## Google permissions (scopes)

The app asks Google only for:

| Scope | Used for |
| --- | --- |
| `gmail.readonly` | `read_latest_emails` |
| `gmail.compose` | `create_email_draft` |
| `gmail.send` | `send_email` |
| `calendar.events` | `get_calendar_availability`, `create_calendar_event` |

If you add scopes later, delete `token.json` and run `--login` again.

You must enable **Gmail API** and **Google Calendar API** on the same Google Cloud project. The OAuth app stays in **Testing**; add your Gmail as a **test user**.

---

## What every project file does

### Root

| File / folder | Purpose |
| --- | --- |
| `README.md` | Step-by-step setup after a Git clone (venv, Google Cloud, login, Cursor) |
| `implementation.md` | This file: design, tools, and what each file is for |
| `test.md` | How to run and read the 8 security test cases |
| `pyproject.toml` | Python project name, Python 3.11+, package dependencies |
| `uv.lock` | Locked versions when you use `uv sync` |
| `requirements.txt` | Extra pip list (Google client libraries) |
| `main.py` | Unused starter (`Hello from security!`). Real entry point is `Backend/email_server.py` |
| `.python-version` | Suggested Python version for the environment |
| `.gitignore` | Keeps `.venv`, `credentials.json`, `token.json`, `.env`, and saved attachments out of Git |
| `.env.example` | Placeholder env names only. **No real secrets.** Copy to `.env` if you want; the server currently uses `credentials.json`, not `.env` |
| `.env` | Local env file (empty / yours). Not committed |
| `credentials.json` | **You** download this from Google Cloud (Desktop OAuth client). Identifies the app. Never commit |
| `token.json` | Created by `--login`. Saved Google session. Never commit. Treat like a password |
| `attachments/` | Local folder for `store_attachment`. `.gitkeep` keeps the folder; files inside are ignored |

### Backend (the running gateway)

| File | Purpose |
| --- | --- |
| `Backend/email_server.py` | MCP server. Google login, Gmail + Calendar clients, and all `@mcp.tool()` functions. Run this file |
| `Backend/gateway.py` | Fixed `ALLOWED_TOOLS` list and in-memory confirmation tokens |
| `Backend/attachments.py` | Safe filename + write helper used by `store_attachment` |

**Commands for `email_server.py`** (from the project root):

| Command | What happens |
| --- | --- |
| `python Backend/email_server.py --login` | Browser Google sign-in; writes `token.json` |
| `python Backend/email_server.py` | Prints latest inbox mail, then exits |
| `python Backend/email_server.py --stdio` | MCP mode for Cursor (almost no terminal output) |
| `python Backend/email_server.py --serve` | Optional HTTP MCP server at `http://127.0.0.1:8765/mcp` |

### Cursor

| File | Purpose |
| --- | --- |
| `.cursor/mcp.json` | Tells Cursor how to start the gateway: venv Python + `email_server.py --stdio` |

Edit the two paths in this file to match **your** machine. Enable the **gmail** server in **Settings → MCP**.

### Test suite

| File / folder | Purpose |
| --- | --- |
| `testcases/files.zip` | Original zip of the harness |
| `testcases/extracted/` | Unzipped runnable suite (see `test.md`) |
| `testcases/extracted/test_cases.py` | IDs, categories, attacker goals (metadata only) |
| `testcases/extracted/attack_generator.py` | Builds ordinary-looking payloads from a test id |
| `testcases/extracted/target_adapter.py` | Only place a target agent should connect |
| `testcases/extracted/scorer.py` | Grades tool-call lists as SAFE or COMPROMISED |
| `testcases/extracted/harness.py` | Runs all 8 cases and prints Attack Success Rate |
| `testcases/extracted/README.md` | Original harness notes |

**Hard rule:** the LLM / mail agent must never import `test_cases.py` or `attack_generator.py`. It should only ever see a raw payload (an email, a filename, and so on).

---

## Security choices (so the design is obvious)

1. **Small allowlist.** If a tool is not in `gateway.py`, it does not exist.
2. **High-risk actions need a human.** Send and calendar-create cannot run from email text alone.
3. **Calendar is yours only.** No attendees, no “share externally,” no other calendars.
4. **Draft ≠ send.** The model can prepare a reply without sending it.
5. **Filenames are data.** Template-looking names are stored as text, not executed.
6. **Secrets stay local.** `credentials.json` and `token.json` are gitignored.

These choices line up with the test suite (fake admin in email, expression in a filename, out-of-scope asks, email-body injection, tool chaining). Details and how to run the suite are in [`test.md`](test.md).

---

## What a teammate should do

1. Follow `README.md` (clone, venv, Google Cloud, `--login`, edit `.cursor/mcp.json`).
2. Enable **gmail** in Cursor MCP. Ask: `What tools are allowed?` and `Read my latest emails.`
3. Read this file to understand why confirmation and the allowlist exist.
4. Follow `test.md` to run the 8 cases against the **mock** agents first.

The mock harness does **not** automatically drive Cursor. Out of the box it tests included demo agents. Wiring the real LLM is a later step; `test.md` explains that.
