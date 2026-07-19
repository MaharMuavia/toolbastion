# Submission description

## Category

Developer Tools

## One-line description

ToolBastion is a local-first security gateway that inspects MCP tools, calls and outputs before coding agents can execute unsafe actions.

## Full description

Coding agents can gain powerful file, shell, and network capabilities through MCP, but a developer often has no independent control layer between an agent's request and the target tool. ToolBastion fills that gap. It presents a real MCP server to the agent and connects as an MCP client to one local stdio server, so tool metadata, arguments, execution decisions, and returned content pass through a dedicated security boundary.

ToolBastion first verifies a persistent cryptographic hash of the approved tool baseline and detects added, removed, schema-changed, description-changed, or poisoned tools. Deterministic detectors normalize paths, URLs, and bare hosts and identify traversal, secret-file access, shell injection, destructive commands, SSRF, metadata endpoints, unapproved destinations, and policy tampering. Clear violations are hard denies that no model can override. In enforce mode, a blocked call never reaches the target tool body; recognized target network/shell/command execution is also blocked by default. The only execution opt-in uses an immutable Docker target image with `--network=none`, not an operator assertion. In shadow mode, the same decision pipeline can be evaluated without claiming enforcement.

Only genuinely ambiguous calls reach GPT-5.6. ToolBastion launches three independent Responses API structured-output checks for scope safety, exfiltration risk, and tool integrity. Zod validates every result and TypeScript aggregates them using fixed rules. Model failure is safe and session call limits bound cost. A clearly labeled offline replay demonstrates the workflow without an API key; it never presents recorded results as live.

Returned tool content is also untrusted. The output firewall passes ordinary results, redacts credential-like material, and quarantines returned prompt injection or suspicious URLs before the agent receives them. Redacted events are stored in a strict canonical SHA-256 start/event/seal chain and can regenerate reports from one verified read. The chain detects ordinary edits, truncation, and session mixing; it is intentionally not presented as a signed external attestation.

Codex was the primary engineering collaborator for the proxy, fixtures, tests, dashboard, and release automation. ToolBastion also uses real `codex exec` for remediation: it runs in an empty temporary read-only workspace and receives only fixed-shape safe metadata, never raw request arguments or policy YAML. Codex can select only a structured action; local code derives and verifies a single exact public HTTP(S) host exception, reruns attack fixtures, and never auto-applies it. A human must provide the matching replay input and explicitly approve a verified proposal.

The target users are developers and platform/security teams experimenting with local MCP coding tools who need a narrow, explainable enforcement layer and auditable evidence. v1 intentionally supports one local stdio target per process. It is not a general OS sandbox, cannot stop a malicious server from acting at startup unless the optional Docker profile is selected, does not yet protect remote MCP transports, and does not implement allowlisted target-side egress through a proxy. It does not claim that its curated offline corpus measures live GPT-5.6 accuracy.

## Required links

| Artifact | Link/status |
| --- | --- |
| Repository | `https://github.com/MaharMuavia/toolbastion` |
| Public YouTube demo | **Pending owner recording/upload** |
| Hosted read-only dashboard | `https://maharmuavia.github.io/toolbastion/` — verify after the Pages workflow completes |
| Container image | `ghcr.io/maharmuavia/toolbastion:v0.1.0` — verify after the release workflow completes |
| GitHub Release | `https://github.com/MaharMuavia/toolbastion/releases/tag/v0.1.0` — verify after the release workflow completes |
| `/feedback` Codex Session ID | **Not yet recorded — see `docs/feedback-session.md`** |

The repository destinations are deterministic publication targets. The owner-supplied YouTube URL and `/feedback` Session ID remain explicit pending fields and are never fabricated.
