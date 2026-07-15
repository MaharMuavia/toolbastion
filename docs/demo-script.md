# Demo script — 2 minutes 50 seconds maximum

Record the successful screen flow first, then narrate. Use 1440p or 1080p, enlarge terminal text, disable notifications, show no secrets or third-party logos, and use no copyrighted music.

## 0:00–0:15 — Problem

Say: “Coding agents can access files, run commands and call external services through MCP. But developers often have no neutral control layer checking those actions before they happen.”

Show: title card and the architecture diagram from `docs/architecture.md`.

## 0:15–0:30 — Product

Say: “ToolBastion sits between Codex and an MCP server. It verifies trusted tools, evaluates each call, inspects returned content and produces allow, ask or block decisions.”

Show: Agent → ToolBastion → target, with audit/dashboard outside the enforcement path.

## 0:30–0:55 — Safe operation

Show a prepared terminal running `npm run demo:offline`. This is the product's real keyless MCP proof, not Vitest output. Highlight the safe target execution and the evidence directory.

Say: “Safe in-scope work is forwarded quickly. Deterministic policy resolves it without spending GPT tokens.”

## 0:55–1:25 — Real attack

Show the terminal's `Renamed-field traversal` result and unchanged target execution counter, then show the corresponding recorded Path Traversal card and critical timeline event in Attack Lab.

Say: “This traversal is blocked before target execution. The integration scenario checks the vulnerable server’s execution counter, proving the tool body was never entered.”

## 1:25–1:45 — MCP-specific attack

Show the poisoned-metadata or schema-change card and trust event.

Say: “ToolBastion persists approved tool schemas and descriptions. A changed or instruction-poisoned tool is quarantined until an explicit trust decision.”

## 1:45–2:05 — Malicious output

Show Hidden Tool Instruction and Fake Credential scenarios.

Say: “Trust does not end after execution. Returned prompt injection is quarantined, and credential-like content is redacted before forwarding or persistence.”

## 2:05–2:25 — GPT-5.6

Show the recorded judge event and label `OFFLINE FIXTURE REPLAY` prominently.

Say: “Only ambiguous calls use GPT-5.6. Scope, exfiltration and tool-integrity checks return validated structured results, then TypeScript aggregates them. This screen is a recorded offline replay; live acceptance is deferred until project billing is active.”

## 2:25–2:40 — Codex

Show a schema-validated `NO_CHANGE` or proposal record and the explicit apply command requiring `--yes`.

Say: “Codex receives redacted evidence in a read-only process. ToolBastion dry-runs every proposal and never auto-applies policy.”

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
