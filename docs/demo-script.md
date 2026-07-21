# Demo script — 2 minutes 50 seconds maximum

Record the successful screen flow first, then narrate. Use 1440p or 1080p, enlarge terminal text, disable notifications, show no secrets or third-party logos, and use no copyrighted music.

## 0:00–0:15 — Problem

Say: “Coding agents can access files, run commands and call external services through MCP. But developers often have no neutral control layer checking those actions before they happen.”

Show: title card and the architecture diagram from `docs/architecture.md`.

## 0:15–0:30 — Product

Say: “ToolBastion sits between Codex and an MCP server. It verifies trusted tools, evaluates each call, inspects returned content and produces allow, ask or block decisions.”

Show: Agent → ToolBastion → target, with audit/dashboard outside the enforcement path.

## 0:30–0:55 — Safe operation

Show a prepared terminal running `npm run demo:offline`. This is the product's real keyless MCP proof, not Vitest output. Highlight the direct controlled canary/loopback-collector baseline, then the protected safe read, unchanged delivery count, unchanged collector count, and evidence directory.

Say: “Safe in-scope work is forwarded quickly. Deterministic policy resolves it without spending GPT tokens.”

## 0:55–1:25 — Real attack

Show the terminal's `Protected path traversal`, `Protected undeclared argument`, and `Protected loopback exfiltration` results. Each must show its unchanged target execution/delivery counter; the loopback row must also show the collector attempt count unchanged. Then show the corresponding recorded Path Traversal card and critical timeline event in Attack Lab.

Say: "This traversal is blocked before target execution. The loopback delivery is also blocked before the target body runs: the target delivery counter and local collector both remain unchanged."

## 1:25–1:45 — MCP-specific attack

Show the poisoned-metadata or schema-change card and trust event.

Say: “ToolBastion persists approved schemas, descriptions, and per-tool capability contracts. A changed or instruction-poisoned tool is quarantined until an explicit trust decision.”

## 1:45–2:05 — Malicious output

Show Hidden Tool Instruction and Fake Credential scenarios.

Say: “Trust does not end after execution. Returned prompt injection is quarantined, and credential-like content is redacted before forwarding or persistence.”

## 2:05–2:25 — GPT-5.6

Show the sanitized live proof first, then show the recorded judge event with `OFFLINE FIXTURE REPLAY` prominently.

Explain that the live proof carries only a privacy-safe structural envelope and that the recorded replay is separate, offline evidence rather than a substitute for a current session.

Say: “Only ambiguous calls use GPT-5.6. Scope, exfiltration and tool-integrity checks return validated structured results, then TypeScript aggregates them. The Attack Lab is a recorded offline replay; the live console is labeled separately and uses only redacted lifecycle evidence.”

## 2:25–2:40 — Codex

Show a schema-validated `NO_CHANGE` or proposal record and the explicit apply command requiring `--yes`.

Say: “Codex receives only a safe metadata summary in an empty read-only workspace. ToolBastion never auto-applies policy; allowlisted target egress remains blocked until a real authenticated proxy exists.”

## 2:40–2:50 — Close

Say: “Codex accelerated the proxy, tests, fixtures and release workflow. GPT-5.6 powers ambiguous security judgment. ToolBastion makes agentic development safer, auditable and easier to govern.”

Show: repository name, Apache-2.0, keyless Docker command, and final public links after they are verified.

## Recording checklist

- Rehearsed runtime is no longer than 2:50.
- Offline labels remain visible whenever recorded semantic results appear.
- Browser and terminal contain no email, API key, notification, private path, or account avatar.
- All clicks are prepared; no time is spent typing.
- Audio is understandable without music.
- Upload is public/unlisted as submission rules require, and its verified URL replaces the pending status in all three submission records.
