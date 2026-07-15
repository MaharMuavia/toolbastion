# Engineering decisions

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

- Decision: Reject edited `.warden/warden.lock.json` files whose canonical content does not match `baselineHash`.
- Alternatives: trust the lockfile; keep baselines only in memory.
- Why: persistent trust must distinguish target metadata changes from baseline tampering.
- Trade-off: intentional manual edits are rejected and must use `warden trust approve`.
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

- Decision: Support exactly one local stdio MCP target per Warden process; keep API/dashboard out of the request path.
- Alternatives: multiple targets; dashboard-mediated approvals.
- Why: narrow scope and fail-safe enforcement are product requirements.
- Trade-off: users run one Warden instance per target.
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

- Decision: Build workspaces in dependency order with a small Node orchestrator that uses `shell: false` and package-local working directories.
- Alternatives: npm's unordered `--workspaces` execution; a larger task runner.
- Why: nested npm workspace builds on this Windows/OneDrive path caused tsup glob discovery to scan outside the repository.
- Trade-off: new buildable workspaces must be added to one explicit list.
- Source: proposed by Codex after reproducing the failure.
