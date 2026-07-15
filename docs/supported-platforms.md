# Supported platforms

| Platform | Status | Notes |
| --- | --- | --- |
| Windows 11 x64 | Tested | Node.js 22, npm 10+, PowerShell; use `npm.cmd` if local execution policy blocks `.ps1` shims. |
| Ubuntu latest x64 | CI-supported | Node.js 22; GitHub Actions runs install, lint, typecheck, unit, integration, browser, build, evaluation, and audit gates. |
| Docker on Windows/Linux | Supported judge path | Multi-stage Linux image, localhost-only port, read-only runtime, no API key for offline replay. |
| macOS 14+ | Best effort | Expected to work with Node.js 22, but not yet included in the release gate. |
| Windows ARM64 / Linux ARM64 | Not yet certified | The source is portable; release images are initially `linux/amd64` until ARM validation is added. |

Requirements: Node.js 20 or newer (22 is the release-tested line), npm with lockfile support, and Git. Docker is optional unless using the judge image. A local stdio MCP target must run on the same host as Warden.

Known constraints: v1 protects one stdio target per process, does not secure remote MCP transports, and uses a tamper-evident hash chain rather than a cryptographic signature.
