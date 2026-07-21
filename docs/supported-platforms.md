# Supported platforms

| Platform | Status | Notes |
| --- | --- | --- |
| Windows 11 x64 | CI-supported | Node.js 22, npm 10+, PowerShell; the Windows CI job runs install, build, lint, typecheck, unit tests, and non-Docker integration tests. Use `npm.cmd` if local execution policy blocks `.ps1` shims. |
| Ubuntu latest x64 | CI-supported | Node.js 22; GitHub Actions runs install, lint, typecheck, unit, integration, browser, build, evaluation, snapshot verification, audit, secret-scan, and SBOM gates. |
| Docker on Windows/Linux | Supported judge and target-isolation path | Multi-stage Linux image, localhost-only judge port, read-only runtime; target isolation requires a running daemon and a Linux image with the configured non-root UID. |
| macOS 14+ | Best effort | Expected to work with Node.js 22, but not yet included in the release gate. |
| Windows ARM64 / Linux ARM64 | Not yet certified | The source is portable; release images are initially `linux/amd64` until ARM validation is added. |

Requirements: Node.js 22.12.0 or newer, npm with lockfile support, and Git. Docker is optional unless using the judge image. A local stdio MCP target must run on the same host as ToolBastion.

Known constraints: v1 protects one stdio target per process, does not secure remote MCP transports, and uses a tamper-evident hash chain rather than a cryptographic signature. `target_egress: isolated` is an all-egress-denied Docker profile; allowed target-side egress through an authenticated proxy is not implemented.
