# Contributing to ToolBastion

ToolBastion is a security boundary, so small, reviewable changes with explicit threat assumptions are preferred.

## Development workflow

1. Open an issue for behavior or policy changes so the security trade-off is visible.
2. Create a focused branch and add tests that fail before the implementation.
3. Keep external inputs behind Zod validation and keep MCP stdout free of diagnostics.
4. Run the complete release gate before opening a pull request:

```powershell
npm.cmd ci
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
npm.cmd run test:e2e
npm.cmd run build
npm.cmd run evaluate
```

Pull requests must explain the threat being handled, the fail-open/fail-closed behavior, and any change to documented limitations. Never add real credentials, private audit logs, or production attack data to tests.

## Security-sensitive changes

Deterministic hard denies may not be overridden by a model. Remediation must remain proposal-only until explicit human approval. New subprocess execution must use argument arrays with `shell: false`, and new persisted data must be recursively redacted.

For vulnerabilities, do not open a public issue. Follow [SECURITY.md](SECURITY.md).
