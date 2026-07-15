# MCP Warden

MCP Warden is a local-first security gateway that inspects MCP tools, calls, and outputs before coding agents can execute unsafe actions.

This repository is under active hackathon development in the Developer Tools category. The current foundation supports one local stdio target, real MCP tool discovery, and tool-call forwarding. Deterministic enforcement, trust baselines, output inspection, GPT-5.6 judgment, remediation, API, and dashboard are tracked in [BUILD_STATE.md](./BUILD_STATE.md).

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

## Security scope

Warden mediates agent-initiated calls; it is not an operating-system sandbox and cannot prevent a malicious target from acting during startup or outside a tool call. v1 intentionally supports one local stdio target per process.

