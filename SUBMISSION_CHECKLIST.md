# Submission checklist

| Requirement | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Working MCP security proxy | In progress | `packages/core/src/index.ts`, `tests/integration/stdio-forwarding.test.ts` | Add enforcement and output inspection stages |
| Deterministic policy engine | Complete | `packages/policy`, `packages/detectors`, `tests/unit/detectors.test.ts` | Expand corpus during hardening |
| GPT-5.6 integration | Not started | — | Day 3 live and offline modes |
| Codex integration | In progress | `docs/codex-collaboration.md` | Add remediation loop and feedback ID |
| CLI | In progress | `apps/cli/src/index.ts` | `run`, `doctor`, and `version` work; implement remaining commands |
| API and React dashboard | Not started | — | Day 3 |
| Vulnerable demo and fixtures | In progress | `examples/vulnerable-server`, `fixtures/attacks/day2-corpus.json` | Add output attacks and evaluation runner |
| Automated tests | In progress | `tests/unit`, `tests/integration` | 31 passing tests; add judge, output, API, dashboard, and E2E coverage |
| Offline keyless demo | Not started | — | Day 3–5 |
| Documentation and threat model | In progress | project records | Complete judge documentation |
| Permissive license | Not started | — | Add Apache-2.0 license |
| Prebuilt judge artifact | Not started | — | Publish container/release |
| Public video under 3 minutes | Not started | URL: pending | Record after final demo |
| `/feedback` Codex Session ID | Blocked on human action | ID: pending | Run `/feedback` in primary task and record ID |
