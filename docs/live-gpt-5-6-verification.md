# Live GPT-5.6 verification

This is a sanitized runtime-integration record for the OpenAI Build Week submission. It demonstrates that ToolBastion made real GPT-5.6 Responses API calls; it is not a model-quality benchmark.

## Recorded run

- Captured at: `2026-07-21T08:22:37.687Z`
- Provider: OpenAI Responses API
- Model: `gpt-5.6`
- Response storage: `false`
- Test case: `run_project_command` structural ambiguity in interactive mode
- Structured subchecks: `scope_safety`, `exfiltration_risk`, and `tool_integrity`
- Aggregate decision: `ALLOW`
- Aggregate risk: `low`
- Latency: `10217 ms`
- Token usage: `1686` input and `726` output

The executable record is [live-judge-proof.json](../reports/live-judge-proof.json). It stores only the timestamp, provider/model, storage setting, test-case identity, decision, risk, token counts, latency, and structured outcome enums. It does not store API keys, raw prompts, raw argument values, policy text, or model rationale.

The recorded proof is a current acceptance artifact: every required structured subcheck is grounded and non-`unavailable`. Live requests provide policy projection, structural argument profile, schema field names/types, required-field presence, path/destination/command classifications, metadata integrity, deterministic uncertainty codes, egress mode, base risk, runtime mode, and context availability. They still never include raw commands, paths, URLs with query values, arguments, policy text, context text, credentials, recent events, or model-authored patches. The recorder refuses to replace the proof unless all three subchecks are grounded and non-`unavailable`.

## Reproduce

Use an active `OPENAI_API_KEY` only in ignored `.env.local`:

```powershell
npm.cmd run build
node --env-file=.env.local .\scripts\judge-smoke.mjs --record
```

The command refuses to overwrite the proof with an offline replay or unavailable provider result.
