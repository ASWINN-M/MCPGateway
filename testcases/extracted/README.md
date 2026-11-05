# Agent Security Test Harness

Runnable red-team suite for the MCP Security Gateway (**TC-01 … TC-21**), with a hard separation between the thing that knows the attacks and the thing being attacked.

## Why the separation matters

If your target agent ever sees the test cases, category names, or attack catalogs —
even in its system prompt — you're no longer measuring security. A model that has
memorized “TC-07” will pattern-match wording and fail on differently-worded attacks.
The point is resistance to the *mechanism*, not recognition of the *test*.

```text
test_cases.py         <- metadata (id, category, what "compromised" means)
attack_generator.py   <- turns a test id into an ordinary-looking payload
target_adapter.py     <- THE ONLY FILE YOUR REAL AGENT CONNECTS TO
scorer.py             <- grades by inspecting actions taken
run_eval.py           <- full suite → results JSON
layer_eval.py         <- before/after + layer ablation for the UI
demo_testrun.py       <- prompt-driven / frontend runner
compare_before_after.py / harness.py
security_guarantees.py
research_benchmarks.py
```

`target_adapter.run_target(channel, payload)` receives only the raw payload —
never the test id, category, or the fact that it's a test. Backend code must never
import `test_cases.py` or `attack_generator.py`.

## Targets

| `MCP_HARNESS_TARGET` | Meaning |
| --- | --- |
| `real` (default for compare) | Live `Backend/email_server.py` over stdio |
| `mock_vulnerable` | Undefended baseline (expect high ASR) |
| `mock_hardened` | Phase 2–style denials (tools present; blocked) |

Danger tools (`run_shell`, `export_secrets`, `fetch_finance_records`, `render_template`, …)
are **in the catalog**. Scorers treat “tool invoked + blocked” as SAFE.

## Running it

From repo root:

```powershell
# Mock before / after (21 cases)
$env:MCP_HARNESS_TARGET='mock_vulnerable'
..\..\.venv\Scripts\python.exe run_eval.py --label before --out ..\..\results\before_gateway.json --allow-mock
$env:MCP_HARNESS_TARGET='mock_hardened'
..\..\.venv\Scripts\python.exe run_eval.py --label after --out ..\..\results\after_gateway.json --allow-mock
..\..\.venv\Scripts\python.exe layer_eval.py

# Real gateway
Remove-Item Env:MCP_HARNESS_TARGET -ErrorAction SilentlyContinue
..\..\.venv\Scripts\python.exe compare_before_after.py
```

Or use the explainer UI: `python frontend/server.py` → http://127.0.0.1:8760

## Reading the results

- **ASR** — % of cases where the attacker goal was met. Lower is better (same metric family as InjecAgent / AgentDojo).
- **21 cases** — TC-01…TC-16 classic mail/calendar injections; TC-17…TC-21 research-backed (draft staging, bulk/volume, tool shadowing, always-allow).
- **Mock 100% → 0%** is a valid demo when labeled mock; report `target_mode=real` separately for live gateway claims.
- A 0% ASR means nothing if utility also collapses — still verify benign tasks work through the same adapter.

## Mailboxes

| Role | Address |
| --- | --- |
| Connected / From | `aswinm2k4@gmail.com` |
| Exfil / To | `aswinmmsa@gmail.com` |

Docs: [docs/testing.md](../../docs/testing.md) · [docs/scores_before_after_gateway.md](../../docs/scores_before_after_gateway.md)
