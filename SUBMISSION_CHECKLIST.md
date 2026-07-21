# Submission checklist

This checklist describes the `0.1.4` release candidate in the current commit. Local gates below are evidence for this commit; the GitHub tag and external publication claims remain pending.

| Requirement | Status | Evidence | Remaining action |
| --- | --- | --- | --- |
| Filesystem capability contracts | Verified | Unit and integration coverage blocks hidden reads, read-to-write escalation, deletes/renames, symlink escapes, and out-of-scope writes. | None for the implemented scope. |
| Target artifact trust binding | Verified | Baseline v3 stores Docker digest/image ID or executable/build hashes; artifact mutation and v2 fail-closed migration tests pass. | Migrate deployed v2 baselines with explicit operator review. |
| Durable receipts | Verified | Failure-injection tests prove partial-file cleanup, retry success, and duplicate rejection; full suite passes. | None. |
| Unsupported product claims | Verified | README, package metadata, dashboard, and submission copy use the approved gateway/evidence-layer description. | None. |
| Clean install | Verified | `npm.cmd ci --no-fund --no-audit` exited `0`. | Repeat on the final release commit. |
| Build | Verified | `npm.cmd run build` exited `0`. | Repeat on the final release commit. |
| Lint and typecheck | Verified | `npm.cmd run lint` and `npm.cmd run typecheck` exited `0`. | Repeat on the final release commit. |
| Unit and integration tests | Verified | `npm.cmd test -- --reporter=dot`: `27` files passed, `1` skipped; `188` tests passed, `1` skipped; exit `0`. | Repeat on the final release commit. |
| Property/fuzz tests | Verified | `tests/unit/adversarial-fast-check.test.ts`: 6 property tests passed with `fast-check`; included in the full suite. | Repeat on the final release commit. |
| Docker isolation | Verified | `npm.cmd run test:docker-isolation`: `1` file and `1` test passed; exit `0` with Docker daemon access. | Repeat on the final release commit and record image digest. |
| Playwright E2E | Verified | `npm.cmd run test:e2e -- --reporter=line`: `4 passed`; exit `0`. | Repeat on the final release commit. |
| Evaluation | Verified | `npm.cmd run evaluate`: `160` fixtures, `160` passed, `0` failed; exit `0`. | Repeat on the final release commit. |
| Snapshot verification | Verified | `npm.cmd run verify:snapshot`: valid, `9` audit events, no errors; exit `0`. | Repeat on the final release commit. |
| Dependency audit | Verified | `npm.cmd audit --audit-level=high`: `found 0 vulnerabilities`; exit `0`. | Repeat on the final release commit. |
| Secret scan | Verified | Tracked-file credential-pattern scan found no matches; exit `0`. | Run again from the final release commit/history. |
| `git diff --check` | Verified | Exit `0`; only Git line-ending normalization warnings were emitted. | Run after staging the final commit. |
| Evaluation/snapshot hashes | Verified | Evaluation SHA-256 `8d13b9eb3aa73e2ab103281186455fb6feab8d0b715156587078c23daf6894db`; snapshot audit SHA-256 `2a644b52753ea0825bcc3d18cacb836123c4a42e1f6e62ae66fc5a7319c59443`. | Recompute after the final commit if artifacts change. |
| GitHub Release `v0.1.4` | Pending | The release commit exists; the tag and GitHub release do not. | Create the tag, push it, then verify the release assets and image digest. |
| YouTube video under 3 minutes | Owner-supplied | [Demo URL](https://youtu.be/EcI2DhUJo2s) | Confirm the video is public, under 3:00, and the voiceover explains the build, Codex use, and GPT-5.6 use. |
| Codex `/feedback` session ID | Owner-supplied | `019f8430-7d0d-7951-9eec-f8a3a1ba4190` in `docs/feedback-session.md` | Confirm this is the exact ID returned by a successful `/feedback` submission; do not submit a task/thread ID. |

The project is not marked production-ready. External publication and release signing/provenance still require human authority.
