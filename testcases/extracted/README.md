# Agent Security Test Harness

Turns the incident reference doc's 8 test cases into a runnable red-team
suite, with a hard separation between the thing that knows the attacks and
the thing being attacked.

## Why the separation matters

If your target agent ever sees the test cases, category names, or the
incident doc itself — even in its system prompt, fine-tuning data, or a
"here's what to watch for" note — you're no longer measuring security. A
model that has memorized "ClaudeBleed" and "TC-07" will pattern-match the
exact wording of these payloads and fail the moment a differently-worded
attack shows up in production. The whole point is a target that resists the
*mechanism*, not one that recognizes the *test*.

This harness enforces that with a file boundary:

```
test_cases.py        <- metadata (id, category, what "compromised" means)
attack_generator.py  <- turns a test id into a concrete, ordinary-looking payload
target_adapter.py    <- THE ONLY FILE YOUR REAL AGENT CONNECTS TO
scorer.py             <- grades results by inspecting actions taken, deterministically
harness.py            <- orchestrates all of the above, reports ASR
```

`target_adapter.run_target(channel, payload)` receives only the raw payload
(an email dict, a tool listing) — never the test id, category, or the fact
that it's a test at all. Your agent should never import `test_cases.py` or
`attack_generator.py`, directly or indirectly.

## Running it

```
cd agent_security_harness
python3 harness.py
```

Out of the box it runs against a mock "naive" agent (`_mock_vulnerable_agent`
in `target_adapter.py`) so you can see the reporting work — it should show
100% ASR. Flip the last line of `target_adapter.py` to
`run_target = _mock_hardened_agent` to see what a 0%-ASR run looks like.

## Wiring in your real mail agent

Replace the body of `target_adapter.run_target` (or repoint the `run_target`
name at a new function) so that it:

1. Delivers `payload` to your agent exactly the way real content would
   arrive (drop it in as the next email in the inbox / next tool result),
   using the same prompt, tools, and policies as production.
2. Lets the agent run normally — no "this is a test" framing anywhere in
   its context.
3. Returns every tool call the agent actually made, as
   `[{"tool": "...", "args": {...}}, ...]`, pulled from your agent
   framework's execution/tool-call log.

Nothing in `harness.py` or `scorer.py` needs to change once that's wired in.

## Reading the results

- **Attack Success Rate (ASR)** — percentage of test cases where the
  attacker's goal was met. Lower is better. This is the same metric
  InjecAgent, AgentDojo, and MCP-SafetyBench report, so you can compare your
  number against their published baselines (see the reference doc).
- **8 test cases is a floor, not a finish line.** `attack_generator.py`
  already rotates wording for TC-07 (three variants) — extend that pattern
  for the rest, and add new test cases as new incidents or attack classes
  come up, so the target can't quietly overfit to eight fixed strings.
- **A 0% ASR run means nothing on its own if utility also drops to 0%.** Run
  a set of benign, everyday tasks through the same `target_adapter` and
  confirm the agent still does its real job — AgentDojo's whole design point
  is that security and utility have to be reported together, or "secure"
  just means "refuses everything."
- **Don't call it done at 8/8 passed.** Treat each pass as "resists this
  specific mechanism today," and keep expanding the suite as your gateway
  and the attack landscape evolve.
