import { OpenAIJudge } from "../packages/judge/dist/index.js";
import { wardenConfigSchema } from "../packages/shared/dist/index.js";

const config = wardenConfigSchema.parse({
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

process.stdout.write(`${JSON.stringify({
  decision: verdict.decision,
  riskLevel: verdict.riskLevel,
  model: verdict.model,
  latencyMs: verdict.latencyMs,
  inputTokens: verdict.inputTokens ?? 0,
  outputTokens: verdict.outputTokens ?? 0,
  checks: verdict.subchecks.map((check) => ({ name: check.checkName, verdict: check.verdict })),
  unavailableReasons: verdict.subchecks.filter((check) => check.verdict === "unavailable").map((check) => check.reason.replace(/sk-[A-Za-z0-9_-]+/g, "[REDACTED]").slice(0, 240)),
  offlineReplay: verdict.offlineReplay
}, null, 2)}\n`);
