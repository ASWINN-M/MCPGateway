# Security notes

## Secrets

| File | What it is | In Git? |
| --- | --- | --- |
| `credentials.json` | Google OAuth client id/secret | **No** |
| `token.json` | Session for **connected** account (`aswinm2k4@gmail.com`) | **No** |
| `.env` | Optional local env / gateway secrets | **No** |
| `.env.example` | Placeholders only | Yes |
| `approvals/` | Plans, execution-token hashes, locks | Local (do not commit secrets) |

Treat `token.json` like a password for the connected mailbox.

---

## Working principles (controls)

Implemented under `Backend/phase1`–`phase3` and `email_server.py`:

1. **Phase 1 least exposure** — `list_allowed_tools` filtered by trusted department  
2. **Phase 2 enforcement** — every tool through `_guard_tool` / authorization  
3. **Caller / session auth** — `MCP_CALLER_TOKEN` via `launch_stdio.py`  
4. **Confirmation** — high-risk writes need human `--approve` + bound execution token  
5. **Draft ≠ send** — drafts also gated on the hardened path  
6. **Own calendar only** — no guests / external share  
7. **Literal filenames** — `store_attachment`; `render_template` denied  
8. **Bulk / rate ceilings** — `db_query` row limits; mailbox read throttling  
9. **Danger catalog present + denied** — shell / secrets / admin / template (`danger:*`)  
10. **Phase 3 audit + anomaly** — JSONL/SQLite + Isolation Forest risk levels  
11. **Narrow OAuth scopes** — Gmail read/compose/send + calendar events  

---

## Mailbox risk model

| Mailbox | Risk if misused |
| --- | --- |
| `aswinm2k4@gmail.com` | Full agent power (read/send as this user) via `token.json` |
| `aswinmmsa@gmail.com` | Receives exfil if send is allowed without proper confirm |

A **SAFE** harness result for send-based attacks means the gateway blocked delivery to the exfil inbox (confirm required; harness does not auto-approve).

---

## What not to claim

| Claim | OK? |
| --- | --- |
| Real gateway ASR from a `real` harness run | Yes (label `target_mode=real`) |
| Mock 100% → 0% ASR as a **demo** of Phase 1–2 | Yes if labeled **mock** |
| Mock ASR as the sole “product” production result | **No** without labeling |
| “Tools unavailable, so we are safe” | **No** — tools exist; policy denies |
| “We patched Claude/Google/Hugging Face CVEs” | **No** — same *risk classes*, different product |
| Allowlist + confirm + Phase 3 monitoring exist | Yes |

---

## Isolation for evaluations

If the agent sees TC ids or `attack_generator.py`, you are testing exam recognition, not mechanism resistance. Keep attack metadata out of prompts and out of `Backend/`.

Trial UI scrubbing: avoid leaking real Gmail addresses / personal names into evaluation payloads shown to visitors.

---

## Related docs

- [architecture.md](architecture.md) — principles and diagrams  
- [testing.md](testing.md) — how to measure  
- [scores_before_after_gateway.md](scores_before_after_gateway.md) — latest numbers  
