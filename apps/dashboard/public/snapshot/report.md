# MCP Warden session report

- Session: `offline-day3-demo`
- Source integrity: verified tamper-evident hash chain
- Events: 7
- Decisions: 2 allowed, 2 blocked, 0 ask-user
- Output actions: 1 redacted, 1 quarantined
- Highest risk: critical
- Source hash: `34882adc160ecc6c53470bea36a8fc65ef1ec9c1c4ae7594e7be366a748a96da`

| # | Timestamp | Event | Decision | Risk |
| ---: | --- | --- | --- | --- |
| 1 | 2026-07-15T08:00:00.000Z | trust_verified | — | none |
| 2 | 2026-07-15T08:00:01.000Z | policy_evaluated | ALLOW | low |
| 3 | 2026-07-15T08:00:02.000Z | call_blocked | BLOCK | critical |
| 4 | 2026-07-15T08:00:03.000Z | policy_evaluated | ALLOW | low |
| 5 | 2026-07-15T08:00:04.000Z | call_blocked | BLOCK | critical |
| 6 | 2026-07-15T08:00:05.000Z | output_inspected | REDACT | critical |
| 7 | 2026-07-15T08:00:06.000Z | output_inspected | QUARANTINE | critical |
