# Security validation

Security validation is category-specific; it is not an accuracy claim.

| Bypass category | Blocking control | Evidence |
| --- | --- | --- |
| Traversal, UNC, device paths, symlink escape | canonical path and scope checks | `tests/unit/detectors.test.ts`, `tests/unit/adversarial-properties.test.ts` |
| Loopback, metadata, private, IPv6, userinfo, credential query | URL/IP normalization | same tests and `scripts/evaluate.mjs` |
| Shell chaining, substitution, encoded PowerShell, destructive commands | deterministic shell detector | same tests and seeded corpus |
| Innocent tool name / no URL argument | capability contract and baseline-v2 capability hash | `tests/integration/enforcement.test.ts` |
| Missing, changed, command, or allowlisted capability | capability authorization | `tests/unit/capabilities.test.ts`, `tests/unit/policy.test.ts` |
| Prompt injection and credential-like result | output quarantine/redaction | `tests/unit/output-firewall.test.ts` |
| Raw judge data leak | structural projection only | `tests/unit/judge.test.ts` |

`npm.cmd run evaluate` writes a machine-readable per-category report with attack/benign counts, expected/actual decisions, failures, and unsupported cases. It is deterministic fixture coverage, not a claim about live GPT accuracy or real-world prevalence.

`tests/unit/detector-mutation.test.ts` creates isolated path, network, and shell detector mutants from the built module and proves that each disabled control loses its corresponding regression case. Capability, schema-validation, audit, and output-firewall branches are covered by direct behavior tests but do not yet have a general mutation runner.
