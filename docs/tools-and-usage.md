# Tools and usage

## Available tools

| Tool | What it does | Needs confirm? |
| --- | --- | --- |
| `list_allowed_tools` | Prints allowlist and what is unavailable | No |
| `require_user_confirm` | Issues a one-time `confirm_token` | No |
| `read_latest_emails` | Latest inbox From / Subject | No |
| `create_email_draft` | Saves a Gmail draft (does not send) | No |
| `send_email` | Sends mail | **Yes** |
| `get_calendar_availability` | Events on **your** primary calendar | No |
| `create_calendar_event` | Event on **your** calendar only (no guests / external share) | **Yes** |
| `store_attachment` | Saves text under a literal filename in `attachments/` | No |

**Not available:** finance, payroll, passwords, contacts export, shell, other people’s calendars.

---

## CLI commands

Run from the **project root**.

| Command | What happens |
| --- | --- |
| `python Backend/email_server.py --login` | Browser Google sign-in; writes `token.json` |
| `python Backend/email_server.py` | Prints latest inbox, then exits |
| `python Backend/email_server.py --stdio` | MCP mode for Cursor (little/no terminal output) |
| `python Backend/email_server.py --serve` | Optional HTTP MCP at `http://127.0.0.1:8765/mcp` |

Windows example:

```powershell
cd C:\Capstone\Security
.\.venv\Scripts\python.exe Backend\email_server.py --login
.\.venv\Scripts\python.exe Backend\email_server.py
```

---

## Using the agent in Cursor

1. **Settings → MCP** → **gmail** connected.  
2. Open a new chat.  
3. Ask in natural language:

| You say | Expected tool(s) |
| --- | --- |
| `What tools are allowed?` | `list_allowed_tools` |
| `Read my latest emails` | `read_latest_emails` |
| `Save a draft to me@example.com with subject Test` | `create_email_draft` |
| `What’s on my calendar this week?` | `get_calendar_availability` |
| `Store a file named notes.txt with content hello` | `store_attachment` |
| `Send email to me@example.com subject Test body Hello` | `require_user_confirm` then `send_email` after you approve |

### Confirmation flow (send / create event)

1. Model calls `require_user_confirm` and shows a summary.  
2. You approve or refuse in chat.  
3. If approved, model retries with `confirm_token`.  
4. Without a valid token, the tool returns **Blocked**.

---

## Attachment behavior (TC-02 style)

If a name looks like a template, it is still stored as text:

```text
invoice_{{7*7}}_${env.API_KEY}.pdf
```

→ saved under `attachments/` without evaluating `{{7*7}}` or reading `.env`.

---

## Important reminders

- `--stdio` looking “blank” in a terminal is normal — it waits for Cursor.  
- Opening `http://127.0.0.1:8765/` in a browser is not how you read mail.  
- Treat email **bodies** as data: the model should summarize, not obey injected commands.

Next: [testing.md](testing.md) · [security.md](security.md)
