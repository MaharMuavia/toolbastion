# Submission checklist

Status reflects direct command evidence recorded on 2026-07-21. `Verified` means the cited command completed successfully in this verification pass; `Not reverified` is deliberately not a passing claim.

| Requirement | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Working MCP security proxy | Verified | `npm.cmd run demo:offline` printed all nine controls as `PASS` and `VERDICT Enforcement proof passed`. | None. |
| Deterministic policy engine | Verified | `npm.cmd run artifact:prepare` reported `160` total fixtures, `160` passed, `0` failed. | None. |
| GPT-5.6 integration | Live verified | `node --env-file=.env.local .\scripts\judge-smoke.mjs --record` returned `ALLOW`, model `gpt-5.6`, and all three subchecks `safe`; proof validation returned `valid:true` at `2026-07-21T08:22:37.687Z`. | None. |
| Codex integration | Human feedback pending | No feedback session ID was supplied in this pass. | Run `/feedback` in the primary task and record the returned ID. |
| CLI | Verified | `node ./apps/cli/dist/index.js --version` returned `0.1.3`. | None. |
| API and React dashboard | Verified | `npm.cmd run test:e2e` returned `4 passed`; released container returned health `200`, protected version `401` without a token, and `200` with a token. | None. |
| Vulnerable demo and fixtures | Verified | `npm.cmd run demo:offline` exercised the synthetic canary, traversal, undeclared argument, loopback exfiltration, hostile output, and credential-like output controls. | None. |
| Automated tests | Verified | Local `npm.cmd test`: `146 passed`, `1 skipped`; release workflow `29814169400` completed successfully for commit `e9b5fa8`. | None. |
| Offline keyless demo | Verified | `npm.cmd run demo:offline` completed with `VERDICT Enforcement proof passed`. | None. |
| Target-side network containment | Verified | `npm.cmd run test:docker-isolation` returned `1 passed (1)`; the same gate passed in release workflow `29814169400`. | None. |
| Audit tamper evidence | Verified | `npm.cmd run demo:offline` reported `Sealed tamper-evident audit 66 linked events verified`. | None. |
| Documentation and threat model | Not reverified | This pass did not independently review the prose for completeness. | No new publication failure found by the release gates. |
| Codex/human decision record | Human feedback pending | No feedback session ID was supplied in this pass. | Run `/feedback` and add its returned ID. |
| Screenshots | Credential-pattern scan clean; visual review pending | Full-history/docs/screenshots scan returned `documentation_and_screenshots_secret_pattern_matches=0`. | Manually review the final recorded video for accidental exposure. |
| Permissive license | Not reverified | License contents were not independently reviewed in this pass. | None. |
| Prebuilt judge artifact | Verified | Release API returned `HTTP/2.0 200 OK`, `asset_count:6`; fresh `docker pull ghcr.io/maharmuavia/toolbastion:v0.1.3` resolved `sha256:7aa32c...`; downloaded Compose started and passed HTTP checks. | None. |
| Hosted read-only dashboard | Verified | Pages workflow `29814132241` completed for `e9b5fa8`; direct public fetch returned `HTTP/1.1 200 OK` and `<title>ToolBastion | Secure MCP tooling</title>`. | None. |
| Submission description | Not reverified | This pass did not independently review the submission prose. | None. |
| Public video under 3 minutes | Human action pending | Demo script exists at `docs/demo-script.md`; no recorded video was supplied. | Record/upload the video and confirm its duration. |
| Repository visibility | Verified | `gh repo view` returned `"visibility":"PUBLIC"`, `"isPrivate":false`; non-interactive clone with credential helpers disabled succeeded at `e9b5fa8`. | None. |
| GitHub Release | Verified | `gh api repos/MaharMuavia/toolbastion/releases/tags/v0.1.3` returned `HTTP/2.0 200 OK`, `asset_count:6`; tag dereferences to `e9b5fa89b023dc5aabb1c677dd5a01521cb782fc`; all five SHA256SUMS entries passed. | None. |
| `/feedback` Codex Session ID | Not recorded | No session ID was supplied in this pass. | Human must run `/feedback` and copy the returned ID into `docs/feedback-session.md`. |

## Final secret/publication gate

- [x] Full Git-history scan returned `full_history_secret_pattern_matches=0`; docs/screenshots scan returned `0`; downloaded release assets and extracted release source each returned `0`; GitHub Actions reported `total_count:0` repository secrets.
- [x] Repository is public and a fresh non-interactive HTTPS clone with credential helpers disabled succeeded.
- [x] Pages deployment for the release commit succeeded; direct unauthenticated fetch of `https://maharmuavia.github.io/toolbastion/` returned `200` with the ToolBastion title.
- [x] Fresh GHCR pull of `v0.1.3` and the downloaded keyless judge Compose path completed successfully; health was `200`, unauthenticated API access was `401`, and authenticated version was `0.1.3`.
- [x] `gh release download v0.1.3` followed by `sha256sum -c SHA256SUMS` returned `OK` for every checksummed release asset.
- [ ] Confirm the public video is under three minutes and contains no accidental secret exposure.
- [ ] Record the exact `/feedback` session ID in `docs/feedback-session.md`.
