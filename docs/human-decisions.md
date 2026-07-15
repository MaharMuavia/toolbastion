# Human decision record

This record distinguishes product-owner choices from implementation choices made by Codex.

| Date | Human decision | Consequence |
| --- | --- | --- |
| 2026-07-15 | Build a narrow local-first MCP governance gateway, not a general chatbot, SAST tool, SIEM, or OS sandbox. | Scope remains one local stdio target per process with explicit limitations. |
| 2026-07-15 | Deterministic policy must run before GPT and hard denies must never be overridden. | Model output is advisory within fixed aggregation rules. |
| 2026-07-15 | Use GPT-5.6 for genuinely ambiguous scope, exfiltration, and tool-integrity judgment. | Clear safe/unsafe calls avoid model cost; live mode requires an active project credential. |
| 2026-07-15 | Recorded model results must be labeled and must not be shown as live. | Dashboard and judge image say `OFFLINE FIXTURE REPLAY` or `READ-ONLY SNAPSHOT`. |
| 2026-07-15 | Codex remediation must never auto-apply policy. | Proposals are read-only, schema-validated, dry-run verified, and require explicit human application. |
| 2026-07-15 | Keep the selected OpenAI key on hold until later. | Day 4–6 tests, evaluation, screenshots, and image builds remain credential-free; live acceptance is deferred. |
| 2026-07-15 | Proceed through Days 2–6 in order and create secure release candidates. | Work is committed by phase with durable build/checklist records. |

Engineering trade-offs proposed and adopted during implementation are documented separately in [DECISIONS.md](../DECISIONS.md).
