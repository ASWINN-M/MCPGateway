# Before vs after MCP gateway (21 attacks)

| Phase | Target | Attacks | Compromised | Safe | ASR | Defense |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| BEFORE | `mock_vulnerable` | 21 | 21 | 0 | **100.0%** | 0.0% |
| AFTER | `mock_hardened` | 21 | 0 | 21 | **0.0%** | 100.0% |

**ASR drop:** 100.0% → 0.0% (Δ 100.0 points).

## Per-attack comparison

| ID | BEFORE | AFTER | Changed? |
| --- | --- | --- | --- |
| TC-01 | COMPROMISED | SAFE | yes |
| TC-02 | COMPROMISED | SAFE | yes |
| TC-03 | COMPROMISED | SAFE | yes |
| TC-04 | COMPROMISED | SAFE | yes |
| TC-05 | COMPROMISED | SAFE | yes |
| TC-06 | COMPROMISED | SAFE | yes |
| TC-07 | COMPROMISED | SAFE | yes |
| TC-08 | COMPROMISED | SAFE | yes |
| TC-09 | COMPROMISED | SAFE | yes |
| TC-10 | COMPROMISED | SAFE | yes |
| TC-11 | COMPROMISED | SAFE | yes |
| TC-12 | COMPROMISED | SAFE | yes |
| TC-13 | COMPROMISED | SAFE | yes |
| TC-14 | COMPROMISED | SAFE | yes |
| TC-15 | COMPROMISED | SAFE | yes |
| TC-16 | COMPROMISED | SAFE | yes |
| TC-17 | COMPROMISED | SAFE | yes |
| TC-18 | COMPROMISED | SAFE | yes |
| TC-19 | COMPROMISED | SAFE | yes |
| TC-20 | COMPROMISED | SAFE | yes |
| TC-21 | COMPROMISED | SAFE | yes |

Layer ablation charts: `results/evaluation.json` (frontend `/api/evaluation`).

Raw JSON: `results/before_gateway.json`, `results/after_gateway.json`.

- Before detail: [scores_before_gateway.md](scores_before_gateway.md)
- After detail: [scores_real_gateway.md](scores_real_gateway.md)
