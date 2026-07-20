# Submission checklist

| Requirement | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Working MCP security proxy | Complete | `packages/core`, forwarding/enforcement integration tests | None |
| Deterministic policy engine | Complete | `packages/policy`, `packages/detectors`, 40-case corpus | None |
| GPT-5.6 integration | Live verified | `packages/judge`, `scripts/judge-smoke.mjs --record`, `reports/live-judge-proof.json` | Regenerate the sanitized proof immediately before recording the final demo |
| Codex integration | Complete except feedback ID | `packages/remediation`, schema, real `codex exec` smoke | Run `/feedback` in primary task |
| CLI | Complete for v1 | `apps/cli`, README command reference | None |
| API and React dashboard | Complete | API integration tests, Playwright tests, screenshots | None |
| Vulnerable demo and fixtures | Complete | `examples/vulnerable-server`, attack/benign/evaluation fixtures | None |
| Automated tests | Complete for local release | unit, integration, E2E, process cleanup, error handling | Rerun in hosted CI after push |
| Offline keyless demo | Complete | `npm run demo:offline`: direct synthetic-canary/loopback control, protected non-execution counters, sealed proof | None |
| Target-side network containment | Locally verified; hosted verification pending | Docker no-network target profile, local host-collector proof, unit construction checks, GitHub Actions gate | Verify the configured CI gate after push |
| Audit tamper evidence | Complete for v2 start/event/seal logs | `npm run verify:snapshot`, CLI `audit verify` | Use an external signing or attestation service if non-repudiation is required; whole-chain replacement remains out of scope |
| Documentation and threat model | Complete | README, architecture, evaluation, security assumptions | None |
| Codex/human decision record | Complete | `docs/codex-collaboration.md`, `docs/human-decisions.md`, `DECISIONS.md` | Add feedback ID |
| Screenshots | Complete | `docs/screenshots` from real Playwright session | Final privacy inspection before upload |
| Permissive license | Complete | `LICENSE`, Apache-2.0 package metadata | None |
| Prebuilt judge artifact | Locally verified; publication pending | Dockerfile, judge compose, release workflow | Verify final GHCR pull after tag workflow |
| Hosted read-only dashboard | Publication target configured | `.github/workflows/pages.yml` | Verify public URL after push |
| Submission description | Complete with publication targets | `docs/submission-description.md` | Verify generated URLs |
| Public video under 3 minutes | Script/preparation complete | `docs/demo-script.md` | Owner records, uploads, and verifies URL |
| Repository visibility | Publication authorized | `https://github.com/MaharMuavia/toolbastion` | Verify unauthenticated clone after push |
| GitHub Release | Workflow ready | `.github/workflows/release.yml` | Verify assets and checksums after tag workflow |
| `/feedback` Codex Session ID | Not recorded | `docs/feedback-session.md` | Human must run `/feedback` and copy returned ID |

## Final secret/publication gate

- [ ] Inspect full Git history, screenshots, Actions settings, and release assets for secrets.
- [ ] Confirm repository visibility is public and clone works without authentication.
- [ ] Confirm Pages URL in a private browser window.
- [ ] Pull the GHCR image on a clean machine and run the keyless judge compose path.
- [ ] Verify SHA256SUMS for the GitHub Release archive.
- [ ] Confirm YouTube runtime is below three minutes and no private notifications appear.
- [ ] Record the exact `/feedback` Session ID in README, description, checklist, and feedback record.
