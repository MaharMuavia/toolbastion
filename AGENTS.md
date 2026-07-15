# MCP Warden contributor guide

## Architecture

- `apps/cli`: the `warden` command and stdio entrypoint.
- `packages/core`: MCP proxy lifecycle, target transport, events, and errors.
- `packages/shared`: validated boundary types and canonical hashing.
- `examples/benign-server`: minimal target used for interoperability tests.
- `examples/vulnerable-server`: controlled attack target; effects stay in fixtures.
- `packages/policy`, `packages/detectors`, `packages/judge`, `packages/audit`, and `packages/remediation`: isolated security stages added in phase order.

The proxy supports one local stdio target per process. Enforcement must not depend on the API or dashboard.

## Conventions

- TypeScript strict mode, ES modules, two-space indentation, and named exports.
- Validate all external or cross-package input with Zod.
- Write human diagnostics to stderr; stdout is reserved for MCP JSON-RPC.
- Spawn subprocesses with argument arrays and `shell: false`.
- Keep behavior changes covered by tests. Update docs when CLI flags, commands, or configuration change.

## Security rules

- Treat MCP metadata, arguments, results, YAML, model output, and subprocess output as untrusted.
- Deterministic hard denies cannot be overridden by a model.
- Never log raw secrets; redact before persistence.
- Fail closed in enforce mode when policy, audit, trust, or required judgment is unavailable.
- Never auto-apply remediation output.
- Never place credentials in source, fixtures, reports, screenshots, `.env`, audit JSONL, or configuration examples.

## Required validation

Before completing a behavior change, run the relevant focused test plus:

```powershell
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
```

