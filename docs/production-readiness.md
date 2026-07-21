# Production readiness

Current readiness: security-hardened development candidate; not production ready.

Implemented and covered locally:

- Per-tool schema-validated capability contracts and immutable target artifact identity are hashed into trust-baseline v4. Enforce mode blocks missing, changed, unsupported, and uncontained contracts.
- Docker `--network=none` is containment only. `network: allowlist` fails closed because no authenticated egress proxy exists.
- Receipts use acceptance-time `startedAt`, terminal-only `completedAt`, exclusive file creation, and optional operator-held Ed25519 signatures.
- The proxy has bounded input/output traversal, target/judge deadlines, process cleanup, output quarantine, redacted audit records, and bounded dashboard event retention.

Release blockers remain:

- The production Docker base image is tag-based rather than digest-pinned, and the runtime stage still copies build-time material.
- The release workflow publishes only `linux/amd64`; no arm64 build, provenance attestation, Cosign signing, Trivy gate, CodeQL workflow, or dependency-review workflow is present.
- A packed/npx install smoke test and published-image verification remain outstanding; the local Docker isolation test now passes with daemon access.
- No authenticated allowlisted egress proxy exists. Do not mark any target with `network: allowlist` as runnable in enforce mode.

The dashboard, recorded fixtures, and offline corpus are evidence aids; they are outside the enforcement path.
