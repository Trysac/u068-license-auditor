# Project record

## Objective

Audit dependency licenses against an allowlist policy: normalise declared licenses to SPDX identifiers, evaluate AND, OR and WITH expressions, and report violations so that CI can fail before a legal review does.

## Scope

- In scope: parsing SPDX 2.3 Annex D license expressions; reading installed distributions and JSON inventories; mapping PEP 639 `License-Expression`, free-text `License` fields and License classifiers; evaluating a JSON allowlist policy; text and JSON reports; a `license-auditor` command with exit codes 0, 1 and 2.
- Out of scope: package registries, license files inside distributions, lockfiles, and legal advice. Runtime dependencies or I/O beyond the listed readers need an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 446835 / 108266 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.8057 |

## Factory run u068 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2709 | 96508 | 0 | 4246 | 0.4857 |
| fix-1 | claude-sonnet-5-5 | no | 6 | 469 | 6115 | 40114 | 0.0240 |
| fix-2 | claude-sonnet-5-5 | no | 10 | 896 | 7102 | 71687 | 0.0339 |
| audit | claude-sonnet-5-5 | no | 12 | 3956 | 31672 | 131099 | 0.1319 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 1596 | 8082 | 41247 | 0.0403 |
| docs | claude-haiku-5-5 | no | 155699 | 4841 | 0 | 0 | 0.0900 |

Total: $0.8057. Prices: Anthropic list prices.
