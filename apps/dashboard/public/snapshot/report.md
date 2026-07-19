# ToolBastion session report

- Session: `offline-day3-demo`
- Source integrity: verified tamper-evident hash chain (not externally anchored)
- Events: 9
- Decisions: 2 allowed, 2 blocked, 0 ask-user
- Output actions: 1 redacted, 1 quarantined
- Highest risk: critical
- Source hash: `0893a92d501c51788ab0f78a5d790845cc4658f175ef8c310edd60ba68966339`

| # | Timestamp | Event | Decision | Risk |
| ---: | --- | --- | --- | --- |
| 1 | 2026-07-15T08:00:00.000Z | audit_session_started | — | — |
| 2 | 2026-07-15T08:00:00.000Z | trust_verified | — | none |
| 3 | 2026-07-15T08:00:01.000Z | policy_evaluated | ALLOW | low |
| 4 | 2026-07-15T08:00:02.000Z | call_blocked | BLOCK | critical |
| 5 | 2026-07-15T08:00:03.000Z | policy_evaluated | ALLOW | low |
| 6 | 2026-07-15T08:00:04.000Z | call_blocked | BLOCK | critical |
| 7 | 2026-07-15T08:00:05.000Z | output_inspected | REDACT | critical |
| 8 | 2026-07-15T08:00:06.000Z | output_inspected | QUARANTINE | critical |
| 9 | 2026-07-15T08:00:06.000Z | audit_session_sealed | — | — |
