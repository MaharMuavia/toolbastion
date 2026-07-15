# Submission checklist

| Requirement | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Working MCP security proxy | Complete for v1 scope | `packages/core/src/index.ts`, `tests/integration/stdio-forwarding.test.ts`, `tests/integration/enforcement.test.ts` | Final documentation |
| Deterministic policy engine | Complete | `packages/policy`, `packages/detectors`, `fixtures/evaluation/day5-corpus.json` | Final documentation |
| GPT-5.6 integration | Blocked on account activation | `packages/judge`, `scripts/judge-smoke.mjs` | Rerun live acceptance after billing activation |
| Codex integration | Complete except feedback ID | `packages/remediation`, `schemas/remediation.schema.json`, `scripts/remediation-smoke.mjs` | Add `/feedback` ID |
| CLI | In progress | `apps/cli/src/index.ts` | Add init/demo/replay polish on Day 6 |
| API and React dashboard | Complete | `apps/api`, `apps/dashboard`, `tests/e2e/dashboard.spec.ts` | Final visual polish only |
| Vulnerable demo and fixtures | Complete | `examples/vulnerable-server`, `fixtures/attacks`, `fixtures/evaluation` | None for RC |
| Automated tests | Complete for RC | `tests/unit`, `tests/integration`, `tests/e2e` | Maintain gates |
| Offline keyless demo | Complete | `npm run demo:offline`, `fixtures/dashboard-snapshot`, `scripts/evaluate.mjs` | None for RC |
| Documentation and threat model | In progress | project records, `docs/judge-guide.md`, `docs/supported-platforms.md` | Day 6 polish |
| Permissive license | Not started | — | Add Apache-2.0 license on Day 6 |
| Prebuilt judge artifact | Ready to publish | `Dockerfile`, `docker-compose.judge.yml`, `.github/workflows/release.yml` | Push tag to publish GHCR image/release |
| Public video under 3 minutes | Not started | URL: pending | Record after final demo |
| `/feedback` Codex Session ID | Blocked on human action | ID: pending | Run `/feedback` in primary task and record ID |
