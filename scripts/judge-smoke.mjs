import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { OpenAIJudge, createLiveJudgeProof } from "../packages/judge/dist/index.js";
import { toolbastionConfigSchema } from "../packages/shared/dist/index.js";

const config = toolbastionConfigSchema.parse({
  version: 1,
  mode: "interactive",
  target: { name: "smoke", command: "node", args: [], env_allowlist: [] },
  judge: { enabled: true, mode: "live", model: "gpt-5.6", reasoning_effort: "low", timeout_ms: 30_000, max_calls_per_session: 3 }
});

const judge = new OpenAIJudge(config.judge);
const verdict = await judge.evaluateRequest({
  toolName: "run_project_command",
  untrustedDescription: "Runs a project command in the current repository.",
  schemaSummary: { type: "object", properties: { command: { type: "string" } }, required: ["command"] },
  args: { command: "npm test" },
  policySummary: { commandScope: "project-local", network: "deny" },
  deterministicEvidence: [],
  recentEvents: ["trust_verified"],
  contextSummary: "Developer requested the project test suite.",
  baseRisk: "high",
  runtimeMode: "interactive"
});

const recordProof = process.argv.includes("--record");
let proofFile;
if (recordProof) {
  const proof = createLiveJudgeProof({
    capturedAt: new Date().toISOString(),
    testCase: {
      id: "project-command-ambiguity",
      toolName: "run_project_command",
      runtimeMode: "interactive",
      baseRisk: "high"
    },
    verdict
  });
  proofFile = path.resolve("reports/live-judge-proof.json");
  await mkdir(path.dirname(proofFile), { recursive: true });
  await writeFile(proofFile, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
}

process.stdout.write(`${JSON.stringify({
  decision: verdict.decision,
  riskLevel: verdict.riskLevel,
  model: verdict.model,
  latencyMs: verdict.latencyMs,
  inputTokens: verdict.inputTokens ?? 0,
  outputTokens: verdict.outputTokens ?? 0,
  checks: verdict.subchecks.map((check) => ({ name: check.checkName, verdict: check.verdict })),
  unavailableReasons: verdict.subchecks.filter((check) => check.verdict === "unavailable").map((check) => check.reason.replace(/sk-[A-Za-z0-9_-]+/g, "[REDACTED]").slice(0, 240)),
  offlineReplay: verdict.offlineReplay,
  proofFile: proofFile ? path.relative(process.cwd(), proofFile) : undefined
}, null, 2)}\n`);
