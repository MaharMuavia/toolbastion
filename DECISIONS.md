# Engineering decisions

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
