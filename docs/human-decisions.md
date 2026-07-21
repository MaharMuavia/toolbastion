# Human decision record

This record distinguishes product-owner choices from implementation choices made by Codex.

| Date | Human decision | Consequence |
| --- | --- | --- |
| 2026-07-15 | Build a narrow local-first MCP governance gateway, not a general chatbot, SAST tool, SIEM, or OS sandbox. | Scope remains one local stdio target per process with explicit limitations. |
| 2026-07-15 | Deterministic policy must run before GPT and hard denies must never be overridden. | Model output is advisory within fixed aggregation rules. |
| 2026-07-15 | Use GPT-5.6 for genuinely ambiguous scope, exfiltration, and tool-integrity judgment. | Clear safe/unsafe calls avoid model cost; live mode requires an active project credential. |
| 2026-07-15 | Recorded model results must be labeled and must not be shown as live. | Dashboard and judge image say `OFFLINE FIXTURE REPLAY` or `READ-ONLY SNAPSHOT`. |
| 2026-07-15 | Codex remediation must never auto-apply policy. | Proposals are read-only, schema-validated, dry-run verified, and require explicit human application. |
| 2026-07-15 | Keep the selected OpenAI key on hold until later. | At that point Day 4–6 tests, evaluation, screenshots, and image builds remained credential-free; this was superseded by the 2026-07-20 local live-proof decision. |
| 2026-07-15 | Proceed through Days 2–6 in order and create secure release candidates. | Work is committed by phase with durable build/checklist records. |
| 2026-07-20 | Permit one locally held active OpenAI key to generate a sanitized live GPT-5.6 proof. | The proof confirms provider connectivity and structured parsing; the key remains ignored, is not committed, and is not required for CI, the snapshot, or the judge image. |

Engineering trade-offs proposed and adopted during implementation are documented separately in [DECISIONS.md](../DECISIONS.md).
