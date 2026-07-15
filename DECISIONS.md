# Engineering decisions

## 2026-07-15 — Publication states remain explicit

- Decision: Prepare Pages, GHCR, Release, video, repository, and feedback handoffs but keep their links marked pending until each external destination is actually verified.
- Alternatives: insert guessed URLs; treat workflow configuration as a successful deployment.
- Why: submission evidence must be accurate and account-level publication requires owner authorization and valid GitHub access.
- Trade-off: the local release can be complete while the submission checklist still shows external actions.
- Source: Codex implementation following the human requirement against fake success states.

## 2026-07-15 — Relative static snapshot paths

- Decision: Build the dashboard with a relative Vite base and resolve committed snapshot assets against `document.baseURI`.
- Alternatives: assume domain-root hosting; add a runtime server to the hosted judge view.
- Why: the same credential-free artifact must work at localhost root and a GitHub Pages project subpath.
- Trade-off: the hosted build is intentionally read-only; live `/api` routes exist only in the local API/container path.
- Source: proposed by Codex for the Day 6 hosted-snapshot gate.

## 2026-07-15 — Honest offline evaluation and reproducible judge artifact

- Decision: Evaluate 35 deterministic fixtures without network calls, publish explicit limitations, ship a read-only snapshot, and package the same build as a non-root read-only container.
- Alternatives: report synthetic model quality as live results; require an API key for judging; make the dashboard the enforcement path.
- Why: judges need a reproducible security demonstration that cannot leak credentials and remains honest about deferred live-model acceptance.
- Trade-off: GPT escalation and cache metrics are structural/offline measurements until billing is activated.
- Source: human requirement, implemented and verified by Codex.

## 2026-07-15 — Browser server lifecycle stays inside the Playwright worker

- Decision: Start and close the Fastify API from the Playwright worker, using installed Chrome locally and pinned Chromium in CI.
- Alternatives: shell-managed web server; browser-only mocked data.
- Why: direct lifecycle ownership eliminates orphaned Windows child processes while exercising real API/download behavior.
- Trade-off: browser tests run serially through one controlled API instance.
- Source: proposed by Codex after reproducing shell child cleanup issues.

## 2026-07-15 — Read-only Codex proposals with local verification

- Decision: Invoke actual `codex exec` with ephemeral state, ignored user config/rules, read-only sandbox, disabled approvals, schema output, and stdin-delivered redacted evidence; strip `OPENAI_API_KEY` and never auto-apply.
- Alternatives: let Codex edit policy directly; accept free-form output; reuse ToolBastion MCP configuration.
- Why: remediation must be useful without becoming a recursive or policy-weakening execution path.
- Trade-off: patches require temporary application, schema validation, event reevaluation, regression checks, and explicit human apply.
- Source: human requirement, aligned with the official Codex manual and verified against local Codex v0.136.0 help.

## 2026-07-15 — Hash-chained, redacted audit source

- Decision: Store canonical JSONL events with sequence, previous hash, event hash, session identity, and recursively redacted payloads.
- Alternatives: ordinary logs; retaining raw output; calling the chain a signature.
- Why: reports must regenerate from an integrity-checked source without persisting discovered secrets.
- Trade-off: this is a tamper-evident chain, not a cryptographic signature or externally anchored attestation.
- Source: human product requirement, implemented by Codex.

## 2026-07-15 — Responses API structured outputs with independent subchecks

- Decision: Run scope, exfiltration, and tool-integrity checks independently with `Promise.all`, using the official OpenAI SDK Zod structured-output helper, then aggregate in TypeScript.
- Alternatives: one combined model request; free-form JSON parsing; beta multi-agent orchestration.
- Why: independent evidence and deterministic aggregation are easier to audit and cannot silently rewrite policy.
- Trade-off: an ambiguous request uses three API calls and must be bounded by session caps and timeouts.
- Source: human product requirement, aligned by Codex with current official OpenAI documentation.

## 2026-07-15 — Dashboard serves recorded data without entering enforcement

- Decision: Serve a labeled offline fixture session through a localhost-only Fastify API and keep the React dashboard outside proxy enforcement.
- Alternatives: dashboard-mediated decisions; simulated live events without a label.
- Why: the proxy must remain reliable when the dashboard is closed, and recorded results must never be presented as live GPT output.
- Trade-off: interactive approval transport remains a later controlled feature.
- Source: human product requirement, implemented by Codex.

## 2026-07-15 — High-severity deterministic findings are hard denies

- Decision: Treat high and critical path, network, shell, secret-path, and explicit policy findings as `HARD_DENY` before semantic judgment.
- Alternatives: send high-risk findings to GPT-5.6; let per-tool rules weaken them.
- Why: clear security boundary violations must be deterministic, testable, and impossible for model output to override.
- Trade-off: conservative classification can require users to narrow commands or policy rather than approve a risky exact call.
- Source: human product requirement, implemented by Codex.

## 2026-07-15 — Persistent baseline hash is verified before diffing

- Decision: Reject edited `.toolbastion/toolbastion.lock.json` files whose canonical content does not match `baselineHash`.
- Alternatives: trust the lockfile; keep baselines only in memory.
- Why: persistent trust must distinguish target metadata changes from baseline tampering.
- Trade-off: intentional manual edits are rejected and must use `toolbastion trust approve`.
- Source: human product requirement, implemented by Codex.

## 2026-07-15 — MCP SDK v1.29.0 exact pin

- Decision: Pin `@modelcontextprotocol/sdk` to 1.29.0 in the lockfile.
- Alternatives: a floating range; the beta v2 split packages.
- Why: registry verification showed 1.29.0 is the current stable/latest v1 release, matching the required supported line.
- Trade-off: upgrades are intentional and require interoperability regression tests.
- Source: proposed by Codex under the human-provided v1 constraint.

## 2026-07-15 — TypeScript npm workspace

- Decision: Use strict ESM TypeScript packages in one npm workspace.
- Alternatives: separate repositories; a single undivided package.
- Why: package boundaries reflect security trust boundaries while keeping the hackathon build simple.
- Trade-off: workspace build ordering and package exports require care.
- Source: proposed by Codex from the human-provided build brief.

## 2026-07-15 — One stdio target and dashboard-independent enforcement

- Decision: Support exactly one local stdio MCP target per ToolBastion process; keep API/dashboard out of the request path.
- Alternatives: multiple targets; dashboard-mediated approvals.
- Why: narrow scope and fail-safe enforcement are product requirements.
- Trade-off: users run one ToolBastion instance per target.
- Source: human-provided product decision.

## 2026-07-15 — Windows command shims

- Decision: Document and use `npm.cmd` and `codex.cmd` in this Windows development environment.
- Alternatives: changing the machine-wide PowerShell execution policy.
- Why: the `.cmd` shims work without weakening host policy.
- Trade-off: Windows examples differ slightly from POSIX commands.
- Source: proposed by Codex after environment verification.

## 2026-07-15 — TypeScript 5.8 compatibility pin

- Decision: Pin TypeScript 5.8.3 instead of registry-latest TypeScript 7.
- Alternatives: bypass peer checks; omit typed linting.
- Why: the current typed ESLint peer range is `<5.9.0`; npm rejected the incompatible tree.
- Trade-off: the project does not use TypeScript 7 features.
- Source: proposed by Codex based on actual dependency resolution.

## 2026-07-15 — Explicit workspace build orchestrator

- Decision: Compile server workspaces in dependency order with the TypeScript compiler from a shell-free Node orchestrator; build the dashboard with Vite.
- Alternatives: npm's unordered `--workspaces` execution; direct tsup orchestration; a larger task runner.
- Why: direct tsup/esbuild entry resolution intermittently scanned above this Windows/OneDrive repository, while ordered `tsc` builds are repeatable and preserve ESM package boundaries.
- Trade-off: server packages are emitted as modules instead of bundled files, and new buildable workspaces must be added to one explicit list.
- Source: proposed by Codex after reproducing the failure.
