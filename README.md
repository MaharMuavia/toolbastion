# MCP Warden

MCP Warden is a local-first security gateway that inspects MCP tools, calls, and outputs before coding agents can execute unsafe actions.

This repository is under active hackathon development in the Developer Tools category. It currently supports one local stdio target, deterministic enforcement, persistent tool trust, exact-call caching, GPT-5.6 semantic judgment with keyless recorded replay, a localhost API, and a React security dashboard. Output inspection, remediation, and reports are tracked in [BUILD_STATE.md](./BUILD_STATE.md).

## Development quickstart

Requirements: Node.js 20 or newer and npm.

```powershell
npm.cmd ci
npm.cmd run build
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
node .\apps\cli\dist\index.js doctor --config .\warden.config.example.yaml
```

On macOS or Linux, use `npm` instead of `npm.cmd` and `/` path separators.

## Current proxy command

```powershell
node .\apps\cli\dist\index.js run --config .\warden.config.example.yaml
```

The process speaks MCP over stdout. Diagnostics and structured lifecycle events go only to stderr.

## Dashboard

```powershell
node .\apps\cli\dist\index.js dashboard --config .\warden.config.example.yaml
```

Open `http://127.0.0.1:4782`. The included session is permanently labeled `OFFLINE FIXTURE REPLAY`; it does not claim a live model call.

## GPT-5.6 judgment

Only ambiguous calls reach three independent semantic checks: scope safety, exfiltration risk, and tool integrity. Structured results are aggregated deterministically and cannot override a hard deny. This follows OpenAI's current [Structured Outputs guidance](https://developers.openai.com/api/docs/guides/structured-outputs).

The live smoke command is:

```powershell
node --env-file=.env.local .\scripts\judge-smoke.mjs
```

## Security scope

Warden mediates agent-initiated calls; it is not an operating-system sandbox and cannot prevent a malicious target from acting during startup or outside a tool call. v1 intentionally supports one local stdio target per process.
