# Submission checklist

| Requirement | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Working MCP security proxy | Complete for v1 scope | `packages/core/src/index.ts`, `tests/integration/stdio-forwarding.test.ts`, `tests/integration/enforcement.test.ts` | Harden during Day 5 |
| Deterministic policy engine | Complete | `packages/policy`, `packages/detectors`, `tests/unit/detectors.test.ts` | Expand corpus during hardening |
| GPT-5.6 integration | Blocked on account activation | `packages/judge`, `scripts/judge-smoke.mjs` | Live request reaches OpenAI but project billing is inactive; rerun after activation |
| Codex integration | Complete except feedback ID | `packages/remediation`, `schemas/remediation.schema.json`, `scripts/remediation-smoke.mjs` | Add `/feedback` ID |
| CLI | In progress | `apps/cli/src/index.ts` | Audit/report/remediation review work; add init/demo/replay |
| API and React dashboard | Complete for Day 4 scope | `apps/api`, `apps/dashboard`, `tests/integration/api.test.ts` | Day 5 browser hardening |
| Vulnerable demo and fixtures | In progress | `examples/vulnerable-server`, `fixtures/attacks/day2-corpus.json` | Add output attacks and evaluation runner |
| Automated tests | In progress | `tests/unit`, `tests/integration` | 50+ tests cover judge, output, audit, remediation, API, and stdio; add Day 5 E2E/browser coverage |
| Offline keyless demo | In progress | `fixtures/recorded-judge-results`, `fixtures/dashboard-snapshot` | Add one-command full attack replay |
| Documentation and threat model | In progress | project records | Complete judge documentation |
| Permissive license | Not started | — | Add Apache-2.0 license |
| Prebuilt judge artifact | Not started | — | Publish container/release |
| Public video under 3 minutes | Not started | URL: pending | Record after final demo |
| `/feedback` Codex Session ID | Blocked on human action | ID: pending | Run `/feedback` in primary task and record ID |
