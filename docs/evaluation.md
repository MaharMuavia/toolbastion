# Evaluation

## Method

`npm run evaluate` loads the Day 2 attack and benign corpora plus the Day 5 hardening corpus. It runs real deterministic detectors, output inspection, trust/policy assertions, and deterministic judge-failure aggregation without network access. It writes `reports/evaluation-summary.json`; `npm run snapshot` copies a stable summary into the read-only dashboard.

The 35 unique cases cover:

- path traversal, Windows/UNC paths, null bytes, environment expansion, and symlink escape;
- secret-file access, command chaining/substitution, encoded PowerShell, download-to-shell, and destructive commands;
- loopback/private/link-local/metadata SSRF, IPv6, non-HTTP protocols, unapproved domains, and sensitive query parameters;
- tool schema/description changes, poisoned metadata, and baseline tampering;
- prompt-injection output, credential redaction, suspicious returned URLs, and ordinary output;
- malformed or timed-out semantic judgment;
- safe project reads, approved network access, commands requiring review, and diagnostics.

## RC result

| Metric | Result | Interpretation |
| --- | ---: | --- |
| Fixtures | 35/35 passed | Expected decisions matched this curated corpus. |
| True-positive rate | 100% | Every labeled attack case was detected in this corpus. |
| False-positive rate | 0% | Every labeled benign case met its expected outcome; `ASK_USER` may be expected. |
| Deterministic resolution | 91.43% | 32 of 35 cases required no semantic escalation. |
| GPT escalation | 8.57% | Three structural failure/ambiguity cases exercised judge aggregation. |
| Output redaction accuracy | 100% | Curated output expectations matched. |
| Cache hit rate | 0% | Cases are intentionally unique, so cache performance is not measured. |

Latency is machine-dependent and is reported as an observation, not a benchmark or service-level guarantee.

## What the result does not prove

- It does not measure live GPT-5.6 security accuracy. Recorded/failure fixtures perform no API request.
- It does not estimate real-world attack prevalence or broad generalization.
- Trust metadata cases use deterministic baseline assertions rather than launching a mutable target for every corpus row.
- A curated corpus can share assumptions with its implementation; independent adversarial review is still needed.
- DNS rebinding, remote MCP transports, multi-target coordination, and OS-level containment are outside v1 coverage.

## Reproduction

```powershell
npm.cmd ci
npm.cmd run build
npm.cmd run evaluate
Get-Content .\reports\evaluation-summary.json
```

Primary end-to-end proof:

```powershell
npm.cmd run demo:offline
```

The path-traversal integration test calls Warden, receives `BLOCK`, then queries the deliberately vulnerable server's execution counter to prove the dangerous tool body was not entered. Output tests likewise verify that raw returned credentials/instructions are not forwarded.

## Live acceptance status

The implementation uses the OpenAI Responses API with Zod structured outputs and three independent subchecks. A real smoke attempt reached OpenAI but returned account-inactive HTTP 429. The key remains outside the repository and live acceptance must be rerun after project billing is activated. This limitation is intentionally visible rather than represented by recorded output.
