# Security notes

## Secrets

| File | What it is | In Git? |
| --- | --- | --- |
| `credentials.json` | Google OAuth client id/secret | **No** |
| `token.json` | Logged-in session (can read/send mail) | **No** |
| `.env` | Optional local env | **No** |
| `.env.example` | Placeholders only | Yes |

Treat `token.json` like a password. Each teammate creates their own OAuth client and login.

If a real client secret was ever pushed or blocked by GitHub push protection, **reset the client secret** in Google Cloud and update local `credentials.json`.

---

## Gateway controls (what we implemented)

These are **real controls** in `Backend/`, not claims that all 8 incident classes are defeated:

1. **Allowlist** — only tools in `gateway.py`  
2. **Confirmation** — `send_email` and `create_calendar_event` need `require_user_confirm`  
3. **Draft vs send** — draft does not send  
4. **Own calendar only** — no guests / external share in `create_calendar_event`  
5. **Literal filenames** — no template evaluation in `store_attachment`  

They reduce risk. They do **not** mean “the LLM cannot be tricked.” If you approve a confirm summary, the send still happens. Email bodies are not filtered for injection text inside Gmail tools.

---

## What not to claim in a report

| Claim | OK? |
| --- | --- |
| Harness default run = 100% ASR on vulnerable mock | Yes |
| Hardened mock = 0% ASR | Yes, if labeled as **mock demo** |
| “Our live agent scored 0% ASR on all 8 cases” | **No**, unless `target_adapter` is wired to the real LLM and scored |
| “TC-05 passed” | **No**, unless you built local-caller authentication |
| Allowlist + confirm exist | Yes |

---

## Isolation for evaluations

If the agent sees the test case list, you are testing **recognition of the exam**, not resistance to the **mechanism**. Keep attack metadata out of prompts and out of `Backend/`.

---

## Related docs

- [architecture.md](architecture.md) — how controls are placed  
- [testing.md](testing.md) — how to measure  
- [setup.md](setup.md) — OAuth / test-user setup  
