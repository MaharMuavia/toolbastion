# Evaluation

## Method

`npm run evaluate` loads the 40 curated Day 2/Day 5 fixtures plus 120 deterministic, seed-generated adversarial and benign variants. It runs real deterministic detectors, output inspection, trust/policy assertions, and deterministic judge-failure aggregation without network access. It writes `reports/evaluation-summary.json`; `npm run snapshot` copies a stable summary into the read-only dashboard. Set `TOOLBASTION_EVALUATION_SEED` to reproduce or vary the generated sequence; the summary reports the seed.

The 160 cases cover:

- path traversal, Windows/UNC paths, null bytes, environment expansion, and symlink escape;
- secret-file access, command chaining/substitution, encoded PowerShell, download-to-shell, and destructive commands;
- loopback/private/link-local/metadata SSRF, IPv6, non-HTTP protocols, unapproved domains, and sensitive query parameters;
- tool schema/description changes, poisoned metadata, and baseline tampering;
- prompt-injection output, credential redaction, suspicious returned URLs, and ordinary output;
- malformed or timed-out semantic judgment;
- traversal, loopback SSRF, and destructive commands hidden under generic or nested argument fields, plus a benign slash-separated prose control;
- safe project reads, approved network access, commands requiring review, and diagnostics.

## RC result

| Metric | Result | Interpretation |
| --- | ---: | --- |
| Fixtures | 160/160 passed | Expected decisions matched the curated and deterministic seeded corpus. |
| True-positive rate | 100% | Every labeled attack case was detected in this corpus. |
| False-positive rate | 0% | Every labeled benign case met its expected outcome; `ASK_USER` may be expected. |
| Deterministic resolution | 78.75% | 126 of 160 cases required no semantic escalation. |
| GPT escalation | 21.25% | 34 structural failure, ambiguity, or benign-review cases exercised judge aggregation. |
| Output redaction accuracy | 100% | Curated output expectations matched. |
| Cache hit rate | 0% | Cases are intentionally unique, so cache performance is not measured. |

The generated summary intentionally omits timing measurements: the corpus is a functional correctness check, not a benchmark, and deterministic snapshots must not imply a reproducible latency figure. Run `npm run benchmark` for local p50/p95/max deterministic-decision, output-inspection, audit-write, cache, throughput, and memory-growth measurements. It prints results only and does not alter committed snapshot artifacts.

## What the result does not prove

- It does not measure live GPT-5.6 security accuracy. Recorded/failure fixtures perform no API request.
- It does not estimate real-world attack prevalence or broad generalization.
- Trust metadata cases use deterministic baseline assertions rather than launching a mutable target for every corpus row.
- A curated corpus can share assumptions with its implementation; independent adversarial review is still needed.
- DNS rebinding, remote MCP transports, multi-target coordination, and OS-level containment are outside v1 coverage.

## Reproduction

```powershell
npm.cmd ci
npm.cmd run artifact:prepare
Get-Content .\reports\evaluation-summary.json
```

Primary end-to-end proof:

```powershell
npm.cmd run demo:offline
```

The product demo first runs a direct, deliberately vulnerable control that reads a generated synthetic canary and delivers it only to a temporary `127.0.0.1` collector. It then calls ToolBastion over MCP, receives `BLOCK` for a real traversal and a second `BLOCK` for an undeclared generic argument that fails the target's advertised input contract, and queries the vulnerable server's execution counter to prove neither dangerous tool body was entered. For loopback SSRF it verifies both the target delivery counter and collector attempt count remain unchanged. The retained proof contains a canary hash rather than the raw marker, plus decisions and the complete audit hash-chain result.

## Live acceptance status

The implementation uses the OpenAI Responses API with Zod structured outputs and three independent subchecks. A successful sanitized live proof is retained separately; it demonstrates provider connectivity, structured parsing, non-zero usage, and `store: false`, not model-quality accuracy. Mandatory CI remains credential-free and uses visibly labeled deterministic/offline fixtures.
