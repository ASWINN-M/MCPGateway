# Project documentation

Full docs for the **MCP Security Gateway** — three-phase least-privilege bridge between Cursor’s LLM and Gmail / Google Calendar, plus department stubs, dummy enterprise tools, and a denial-gated attack-surface catalog.

**Connected (attacking) mail:** `aswinm2k4@gmail.com`  
**Exfil (attacked) inbox:** `aswinmmsa@gmail.com`  
**Suite size:** TC-01 … TC-21

| Document | Read it when you want to… |
| --- | --- |
| [overview.md](overview.md) | What / why / working principle |
| [setup.md](setup.md) | Clone, OAuth, Cursor, UI deps |
| [architecture.md](architecture.md) | Diagrams, phases, file map |
| [tools-and-usage.md](tools-and-usage.md) | Full tool catalog and day-to-day use |
| [testing.md](testing.md) | 21-attack harness, mock vs real, evaluation UI |
| [scores_before_after_gateway.md](scores_before_after_gateway.md) | Before vs after ASR (21) |
| [scores_before_gateway.md](scores_before_gateway.md) | Undefended mock baseline detail |
| [scores_real_gateway.md](scores_real_gateway.md) | Hardened-run detail |
| [security.md](security.md) | Secrets and honest claims |
| [system-prompt.md](system-prompt.md) | LLM guidance only (not enforcement) |

**Suggested order:** setup → tools-and-usage → architecture → testing → scores_before_after_gateway → security  

Root [`README.md`](../README.md) is the short entry point.
