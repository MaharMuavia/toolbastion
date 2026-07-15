# Security policy

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/MaharMuavia/toolbastion/security/advisories/new). Include the affected version, a minimal reproduction, expected impact, and whether the issue can cause a tool call to execute despite a block decision.

Do not include live secrets, private audit logs, or third-party data. If a safe reproducer needs credential-like content, use an obvious synthetic placeholder.

## Scope

Security reports are especially valuable for policy bypasses, tool-baseline confusion, secret leakage, output-firewall bypasses, audit-chain integrity errors, subprocess escape, SSRF, unsafe remediation, and fail-open behavior in enforce mode.

ToolBastion v1 mediates one local stdio MCP target per process. It is not an operating-system sandbox and cannot prevent a malicious target from acting during startup or outside a mediated tool call. See [SECURITY_ASSUMPTIONS.md](SECURITY_ASSUMPTIONS.md) for the full threat model.

## Response

The maintainers will acknowledge a well-formed report as soon as practical, validate it against supported versions, coordinate a fix and disclosure timeline, and credit the reporter unless anonymity is requested.
