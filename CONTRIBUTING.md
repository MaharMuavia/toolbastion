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
npm.cmd run artifact:prepare
```

When changing Docker target isolation and a Docker daemon is available, also build the supplied probe image and run `npm.cmd run test:docker-isolation` with `TOOLBASTION_DOCKER_TEST_IMAGE` set to that immutable image ID. GitHub Actions performs this host-collector proof on every pull request and release.

Pull requests must explain the threat being handled, the fail-open/fail-closed behavior, and any change to documented limitations. Never add real credentials, private audit logs, or production attack data to tests.

## Security-sensitive changes

Deterministic hard denies may not be overridden by a model. An MCP client cannot be trusted as an approval authority; ambiguous calls must not be forwarded without an independently authenticated operator channel. Remediation remains proposal-only until explicit human approval. New subprocess execution must use argument arrays with `shell: false`, and new persisted data must be recursively redacted.

For vulnerabilities, do not open a public issue. Follow [SECURITY.md](SECURITY.md).
