# Build state

- Current phase: Day 2 — deterministic security foundation
- Completed: Day 1 environment de-risking; npm workspace scaffold; exact MCP SDK v1 pin; benign stdio target; two-hop MCP proxy; real tool discovery and call forwarding; structured lifecycle events on stderr; `warden doctor`; unit/integration test harness; basic CI; clean lockfile install
- Partial: configuration schema currently covers the Day 1 target/runtime subset; full policy schema begins in Day 2
- Blocked: GPT-5.6 access cannot be confirmed without inspecting configured credentials or making a live call; deferred until the live judge phase
- Most recent commands: `npm.cmd ci --no-fund --no-audit`; `npm.cmd run build`; `npm.cmd run lint`; `npm.cmd run typecheck`; `npm.cmd test`; `node apps/cli/dist/index.js doctor --config warden.config.example.yaml`
- Known failures: PowerShell execution policy blocks npm/codex `.ps1` shims; `.cmd` shims work. Initial install rejected TypeScript 7 because typed ESLint supports TypeScript <5.9; compiler pinned to 5.8.3. First build exposed unordered workspace declaration builds and an unsupported tsup banner flag; both were corrected. A repeated build let tsup scan above the OneDrive workspace; package-local tsconfigs now constrain discovery.
- Next tasks: implement the full policy YAML schema and precise validation errors; add cross-platform path/network/shell detectors; gate forwarding with deterministic decisions and tests
- Submission readiness: 12%
