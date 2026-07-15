# Submission checklist

| Requirement | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Working MCP security proxy | Complete | `packages/core`, forwarding/enforcement integration tests | None |
| Deterministic policy engine | Complete | `packages/policy`, `packages/detectors`, 35-case corpus | None |
| GPT-5.6 integration | Implemented; live acceptance deferred | `packages/judge`, `scripts/judge-smoke.mjs` | Activate project billing and rerun live smoke |
| Codex integration | Complete except feedback ID | `packages/remediation`, schema, real `codex exec` smoke | Run `/feedback` in primary task |
| CLI | Complete for v1 | `apps/cli`, README command reference | None |
| API and React dashboard | Complete | API integration tests, Playwright tests, screenshots | None |
| Vulnerable demo and fixtures | Complete | `examples/vulnerable-server`, attack/benign/evaluation fixtures | None |
| Automated tests | Complete for local release | unit, integration, E2E, process cleanup, error handling | Rerun in hosted CI after push |
| Offline keyless demo | Complete | `npm run demo:offline`, read-only snapshot/container | None |
| Audit integrity | Complete | `npm run verify:snapshot`, CLI `audit verify` | None |
| Documentation and threat model | Complete | README, architecture, evaluation, security assumptions | None |
| Codex/human decision record | Complete | `docs/codex-collaboration.md`, `docs/human-decisions.md`, `DECISIONS.md` | Add feedback ID |
| Screenshots | Complete | `docs/screenshots` from real Playwright session | Final privacy inspection before upload |
| Permissive license | Complete | `LICENSE`, Apache-2.0 package metadata | None |
| Prebuilt judge artifact | Locally verified; publication pending | Dockerfile, judge compose, release workflow | Push final tag and verify GHCR pull |
| Hosted read-only dashboard | Workflow ready; not deployed | `.github/workflows/pages.yml` | Configure remote/Pages and verify public URL |
| Submission description | Complete with honest pending links | `docs/submission-description.md` | Insert verified public URLs |
| Public video under 3 minutes | Script/preparation complete | `docs/demo-script.md` | Owner records, uploads, and verifies URL |
| Repository visibility | Not externally configured | `docs/deployment.md`; no Git remote currently | Owner creates/publicizes repository after history scan |
| GitHub Release | Workflow ready; not published | `.github/workflows/release.yml` | Push final tag after remote CI passes |
| `/feedback` Codex Session ID | Not recorded | `docs/feedback-session.md` | Human must run `/feedback` and copy returned ID |

## Final secret/publication gate

- [ ] Inspect full Git history, screenshots, Actions settings, and release assets for secrets.
- [ ] Confirm repository visibility is public and clone works without authentication.
- [ ] Confirm Pages URL in a private browser window.
- [ ] Pull the GHCR image on a clean machine and run the keyless judge compose path.
- [ ] Verify SHA256SUMS for the GitHub Release archive.
- [ ] Confirm YouTube runtime is below three minutes and no private notifications appear.
- [ ] Record the exact `/feedback` Session ID in README, description, checklist, and feedback record.
