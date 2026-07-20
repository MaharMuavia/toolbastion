# Live GPT-5.6 verification

This is a sanitized runtime-integration record for the OpenAI Build Week submission. It demonstrates that ToolBastion made real GPT-5.6 Responses API calls; it is not a model-quality benchmark.

## Recorded run

- Captured at: `2026-07-20T13:41:40.415Z`
- Provider: OpenAI Responses API
- Model: `gpt-5.6`
- Response storage: `false`
- Test case: `run_project_command` structural ambiguity in interactive mode
- Structured subchecks: `scope_safety`, `exfiltration_risk`, and `tool_integrity`
- Aggregate decision: `ASK_USER`
- Aggregate risk: `high`
- Latency: `5593 ms`
- Token usage: `1122` input and `457` output

The executable record is [live-judge-proof.json](../reports/live-judge-proof.json). It stores only the timestamp, provider/model, storage setting, test-case identity, decision, risk, token counts, latency, and structured outcome enums. It does not store API keys, raw prompts, raw argument values, policy text, or model rationale.

Two subchecks returned the structured `unavailable` verdict because ToolBastion intentionally withholds raw command content and detailed egress policy from the external judge. That is an epistemic result from a successful model response, not an API outage: the record identifies `gpt-5.6` and has non-zero token usage. In interactive mode, the deterministic aggregator converts that uncertainty to `ASK_USER`.

## Reproduce

Use an active `OPENAI_API_KEY` only in ignored `.env.local`:

```powershell
npm.cmd run build
node --env-file=.env.local .\scripts\judge-smoke.mjs --record
```

The command refuses to overwrite the proof with an offline replay or unavailable provider result.
