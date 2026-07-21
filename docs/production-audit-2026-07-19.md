# Production Audit — 2026-07-19

## Executive assessment

| Area | Score | Evidence-based assessment |
| --- | ---: | --- |
| Overall | 80/100 | Strong local security runtime with verified controls; not a general production gateway yet. |
| Production readiness | 79/100 | Reproducible build, CI, hardened container execution, local tests, and one sanitized live GPT-5.6 verification are recorded. |
| Security | 82/100 | Deterministic pre-execution controls, output quarantine, trust baselines, audit sealing, and remote API authentication are implemented. |
| Data quality | 85/100 | There is no database or user dataset. Policy, fixture, audit, and snapshot inputs are schema-validated and regeneration-verified. |
| Architecture | 84/100 | Clear package boundaries keep enforcement independent from the dashboard. One local stdio target is an intentional scope limit. |
| Testing | 84/100 | 119 unit/integration tests, 2 browser tests, and the Docker isolation test passed locally. |
| UX | 75/100 | Local and recorded-session dashboard flows are browser-tested; authenticated remote dashboard flow has integration but not browser coverage. |
| AI reliability | 78/100 | Inputs/outputs are bounded and structured; a real GPT-5.6 run verified the integration, although one run does not establish model-quality accuracy. |
| Deployment | 82/100 | Docker build, Compose startup, health checks, and remote API authentication were verified locally. |

**Verdict:** strong but requires specific fixes before a broader production release. It is suitable for a bounded local MCP-security demonstration and controlled developer use, not for claims of general remote-gateway or enterprise readiness.

## Architecture and data flow

```text
MCP client
  -> CLI / core proxy
  -> approved tool schema + trust baseline + deterministic policy
  -> optional GPT-5.6 structured subchecks
  -> one stdio MCP target (optional Docker no-network isolation)
  -> output firewall
  -> redacted sealed JSONL audit
  -> local API / React dashboard / deterministic reports
```

| Component | Status | Evidence |
| --- | --- | --- |
| `apps/cli` | Verified | Owns stdio proxy, policy, trust, audit, remediation, and dashboard commands. |
| `packages/core` | Verified | Validates tool schemas, bounds inputs, evaluates policy, calls the target with a timeout, and inspects results. |
| `packages/policy` + `packages/detectors` | Verified | Uses Zod-validated config, tool baseline hashes, and deterministic detection. |
| `packages/judge` | Verified for integration | OpenAI Responses integration uses structured parsing, timeouts, limits, and `store: false`; a sanitized live GPT-5.6 proof is recorded. |
| `packages/audit` + `packages/reports` | Verified | Writes fsynced start/event/seal hash chains and verifies before reports. The chain is not externally anchored. |
| `packages/remediation` | Verified | Uses an empty read-only Codex workspace, local invariant checks, re-verification, and HMAC-sealed proposals. |
| `apps/api` + `apps/dashboard` | Verified locally | Serves live local observations or clearly labelled recorded fixtures. Remote API now requires a bearer token. |
| Docker isolation | Verified | Probe image owns Linux dependencies; no-network exfiltration test passed locally. |

## Data inventory and lineage

| Data source | Purpose | Volume examined | Validation / integrity | Status |
| --- | --- | ---: | --- | --- |
| YAML policy | Runtime configuration | 1 example policy | Zod strict schema | Verified |
| Tool baseline JSON | Approved metadata identity | Local generated artifact | Canonical hash and schema verification | Verified by code/tests |
| Attack/benign/evaluation fixtures | Deterministic regression corpus | 40 evaluated fixtures at the time of this audit; superseded by the current 160-case corpus | JSON parsing, policy/detector assertions | Verified offline |
| Recorded judge fixture | Offline semantic replay | 3 subchecks per tool fixture | Zod fixed-length subchecks | Verified offline |
| JSONL audit | Redacted decision evidence | 9 snapshot events; 39 events in live test proof | Sealed SHA-256 chain, sequence/session checks | Verified |
| Dashboard snapshot | Read-only public evidence | 12 scenarios, 9 audit events | Artifact regeneration and snapshot verification | Verified |
| Environment variables | OpenAI and remote-dashboard secrets | Names only; values were not read | Ignored `.env.local`; allowlists and redaction | Partially verified |

There are no migrations, ORM models, database connections, object storage integrations, authentication profiles, or user records in the repository. Database completeness, uniqueness, foreign-key, and tenant-isolation checks are therefore not applicable.

Critical lineage is: MCP arguments -> schema/bounds validation -> deterministic result -> optional structural judge result -> target output -> output firewall -> redacted audit event -> verified report/dashboard projection. Raw request arguments are hashed rather than persisted in audit output.

## Feature verification matrix

| Feature | Actual implementation | Data source | Tested | Status | Main gap |
| --- | --- | --- | --- | --- | --- |
| Pre-execution blocking | Core proxy blocks before target forwarding | MCP request | Integration proof | Verified | Does not sandbox a non-Docker target process. |
| Tool identity baseline | Schema/description hashes and diffing | Target `tools/list` | Unit/integration | Verified | Approved implementation can still act maliciously behind unchanged metadata. |
| Output firewall | Redaction/quarantine traversal | Target result | Unit/integration | Verified | Injection classifier remains bounded pattern detection. |
| GPT semantic judgment | Three structured Responses subchecks | Structural request profile | Unit failure paths and live proof | Verified for integration | One live run proves connectivity and schema handling, not general model quality. |
| Offline replay | Recorded subchecks, clearly labeled | Fixture JSON | Unit/E2E | Verified | It is not live-model evidence. |
| Audit/reporting | Sealed JSONL and deterministic reports | Audit JSONL | Unit/integration/artifact | Verified | No external signature/anchor. |
| Dashboard | Local live session or static fallback | Runtime events/snapshot | API/E2E | Verified locally | No remote authenticated browser E2E test. |
| Remote dashboard API | Explicit `--expose` plus bearer token | `TOOLBASTION_API_TOKEN` | API integration | Verified | TLS must be provided by the deployment boundary. |
| Codex remediation | Constrained output, local verification, explicit apply | Blocked event + replay args | Unit | Verified | Requires operator-held HMAC secret; not an automatic fix path. |
| Docker target isolation | No-network, RO, non-root, resource-limited run | Docker runtime | CI configuration/test plus local integration proof | Verified | The isolated target started and failed to reach the controlled host collector. |

## Findings and fixes

| ID | Severity | Area | Evidence | Fix status |
| --- | --- | --- | --- | --- |
| SEC-01 | High | Remote dashboard exposure | `--expose` previously allowed unauthenticated API reads of policy, events, audits, and reports. | Fixed: non-loopback binds require a 32-256 character `TOOLBASTION_API_TOKEN`; API uses timing-safe bearer comparison. |
| DATA-01 | Medium | Dashboard trust projection | `/api/trust` read `rootDir` instead of configured `project_root`. | Fixed and regression-tested with a distinct project root. |
| AI-01 | Resolved | Live model proof | `reports/live-judge-proof.json` records a non-replay GPT-5.6 run with three structured outcomes, non-zero token usage, and `store: false`. | Fixed: regenerate immediately before the final recording if the demo environment changes. |
| DEP-01 | Medium | Windows bind-mounted dependencies | The Node-only probe image stalled while loading MCP dependencies from host `node_modules`. | Fixed: the image owns Linux runtime dependencies and the host dependency directory is hidden from the target mount. |
| AUD-01 | Medium | Audit non-repudiation | Hash chain detects edits but is not externally signed or anchored. | Open: add an external signer/attestation only if the product needs non-repudiation. |
| NET-01 | Medium | Target egress | Argument inspection cannot enforce a target's permitted outbound traffic; Docker profile denies all egress. | Open: build an authenticated egress proxy if allowlisted target networking is required. |

## Implemented during this audit

- `apps/api/src/index.ts`: reads trust state beneath configured `project_root`; adds remote-only bearer enforcement and CORS authorization-header support.
- `apps/dashboard/src/main.tsx`: accepts `#token=<secret>`, removes the fragment immediately, sends it only as an in-memory bearer header, and fetches protected downloads as blobs.
- `tests/integration/api.test.ts`: covers remote bind refusal, bearer enforcement, and configured trust root.
- `examples/vulnerable-server/Dockerfile.isolated` and `packages/core/src/index.ts`: the isolated runtime owns its dependencies rather than resolving host-mounted `node_modules`.
- `.env.example`, Compose files, and deployment/judge documentation: require and document the remote API token without storing a value.

## Verification evidence

| Command | Result | Evidence |
| --- | --- | --- |
| `npm.cmd run lint` | Passed | ESLint completed without findings. |
| `npm.cmd run typecheck` | Passed | `tsc --noEmit` completed. |
| `npm.cmd test` | Passed | 119 passed, 1 skipped; keyless attack-and-prevention proof sealed 39 audit events. |
| `npm.cmd run test:e2e` | Passed | 2 Chromium dashboard flows passed. |
| `npm.cmd run artifact:prepare` | Passed | 40/40 offline fixtures passed at the time; the current release gate regenerates and verifies the 160-case summary. |
| `npm.cmd audit --audit-level=high` | Passed | 0 vulnerabilities reported. |
| `npm.cmd run test:docker-isolation` | Passed | The no-network target started and could not reach the controlled host collector. |
| `docker compose -f docker-compose.yml up -d` | Passed | Current image built; health returned `200`, unauthenticated API returned `401`, authenticated API returned `200`; resources were removed afterward. |

## Production launch checklist

- [x] Verify the intended OpenAI project and save only a sanitized proof of live structured checks.
- [ ] Store `OPENAI_API_KEY`, `TOOLBASTION_API_TOKEN`, and remediation HMAC material in a secret manager, never in source or images.
- [ ] Terminate TLS before any non-loopback dashboard API; distribute the bearer token through an approved operator channel.
- [x] Run Docker isolation and compose tests on a daemon-enabled local environment; repeat them in CI and on release hosts.
- [ ] Verify CI is green for the release commit and perform a clean `npm ci` build/test/audit.
- [ ] Keep target egress disabled unless a real authenticated egress proxy is deployed.
- [ ] Define audit retention, backup, and external-attestation requirements before compliance claims.
- [ ] Keep the public dashboard labelled as a recorded read-only fixture where no live runtime exists.

## Roadmap

### Immediate: before release

1. Regenerate the live GPT-5.6 structured-decision proof immediately before recording the final demo.
2. Repeat Docker build, judge Compose, and no-network target-isolation tests from a clean release host.
3. Use TLS and a secret-managed API token for every remote dashboard deployment.

### Short term: 1–2 weeks

1. Add authenticated remote-dashboard browser E2E coverage.
2. Add property-based/mutation tests for encoding, Unicode, deep nesting, and output injection variants.
3. Define an operator approval integration and document its trust model.

### Medium term: 1–2 months

1. Add a controlled egress proxy if targets need permitted network access.
2. Add externally verifiable audit receipts/attestation if non-repudiation is a product requirement.
3. Expand from one local stdio target only after adding remote transport, identity, and multi-target isolation designs.
