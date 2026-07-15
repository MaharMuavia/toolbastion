# Codex collaboration record

| Date | Module | How Codex accelerated work | Human decision or correction | Validation performed |
| --- | --- | --- | --- | --- |
| 2026-07-15 | Foundation | Inspected the build brief and environment, confirmed Codex structured-output CLI support, and created durable project/security records. | Human constrained v1 to one target and required deterministic checks before model judgment. | Verified Node, npm, Git, and Codex versions and inspected `codex exec --help`. |
| 2026-07-15 | MCP bridge | Scaffolded strict TypeScript workspaces, implemented a real SDK client/server stdio bridge and benign target, and stabilized Windows builds. | Human required stdout to remain protocol-only and child processes to use `shell: false`. | Clean `npm ci`; build, lint, and type-check passed; integration client listed and called `echo` through Warden; 3 tests passed. |
| 2026-07-15 | Deterministic security | Implemented policy validation, canonical path and symlink checks, SSRF and shell detectors, exact-call cache, persistent trust diffing, poisoned metadata detection, enforcement, and attack fixtures. | Human required deterministic checks before GPT and prohibited model overrides of hard denies. | 31 tests passed, including target-side proof that traversal was blocked before execution; CLI trust create/diff was clean; invalid YAML reported exact paths. |
