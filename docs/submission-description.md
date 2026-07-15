# Submission description

## Category

Developer Tools

## One-line description

MCP Warden is a local-first security gateway that inspects MCP tools, calls and outputs before coding agents can execute unsafe actions.

## Full description

Coding agents can gain powerful file, shell, and network capabilities through MCP, but a developer often has no independent control layer between an agent's request and the target tool. MCP Warden fills that gap. It presents a real MCP server to the agent and connects as an MCP client to one local stdio server, so tool metadata, arguments, execution decisions, and returned content pass through a dedicated security boundary.

Warden first verifies a persistent cryptographic hash of the approved tool baseline and detects added, removed, schema-changed, description-changed, or poisoned tools. Deterministic detectors normalize paths and URLs and identify traversal, secret-file access, shell injection, destructive commands, SSRF, metadata endpoints, unapproved destinations, and policy tampering. Clear violations are hard denies that no model can override. In enforce mode, a blocked call never reaches the target tool body; in shadow mode, the same decision pipeline can be evaluated without claiming enforcement.

Only genuinely ambiguous calls reach GPT-5.6. Warden launches three independent Responses API structured-output checks for scope safety, exfiltration risk, and tool integrity. Zod validates every result and TypeScript aggregates them using fixed rules. Model failure is safe and session call limits bound cost. A clearly labeled offline replay demonstrates the workflow without an API key; it never presents recorded results as live.

Returned tool content is also untrusted. The output firewall passes ordinary results, redacts credential-like material, and quarantines returned prompt injection or suspicious URLs before the agent receives them. Redacted events are stored in a canonical SHA-256 hash chain and can regenerate verified JSON and Markdown reports.

Codex was the primary engineering collaborator for the proxy, fixtures, tests, dashboard, and release automation. Warden also uses real `codex exec` for remediation: redacted evidence enters a read-only, schema-constrained process; proposed policy patches are dry-run verified; weakening changes are rejected; and nothing is auto-applied. A human must explicitly approve a verified proposal.

The target users are developers and platform/security teams experimenting with local MCP coding tools who need a narrow, explainable enforcement layer and auditable evidence. v1 intentionally supports one local stdio target per process. It is not an OS sandbox, cannot stop a malicious server from acting at startup, does not yet protect remote MCP transports, and does not claim that its curated offline corpus measures live GPT-5.6 accuracy.

## Required links

| Artifact | Link/status |
| --- | --- |
| Repository | **Pending publication — no remote is configured** |
| Public YouTube demo | **Pending owner recording/upload** |
| Hosted read-only dashboard | **Pending GitHub Pages publication; workflow ready** |
| Container image | `ghcr.io/mouav/mcp-warden:0.1.0` — **pending tag push/workflow** |
| GitHub Release | **Pending repository publication and final tag push** |
| `/feedback` Codex Session ID | **Not yet recorded — see `docs/feedback-session.md`** |

These are deliberately status markers, not fabricated URLs. Replace each only after verifying the public destination.
