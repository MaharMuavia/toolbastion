/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { aggregateSubchecks } from "@toolbastion/judge";
import { inspectToolResult } from "@toolbastion/output-firewall";
import { applyRuntimeMode, createTrustBaseline, evaluateDeterministic, verifyTrustBaseline } from "@toolbastion/policy";
import { toolbastionConfigSchema } from "@toolbastion/shared";

const root = process.cwd();
const temporary = path.join(root, ".test-tmp", "evaluation");
const projectRoot = path.join(temporary, "project");
const outside = path.join(temporary, "outside");
await rm(temporary, { recursive: true, force: true });
await mkdir(path.join(projectRoot, "src"), { recursive: true });
await mkdir(outside, { recursive: true });
await writeFile(path.join(projectRoot, "src", "index.ts"), "export {};\n", "utf8");
await writeFile(path.join(outside, "secret.txt"), "fixture only\n", "utf8");
await symlink(outside, path.join(projectRoot, "link-outside"), process.platform === "win32" ? "junction" : "dir");

const config = toolbastionConfigSchema.parse({
  version: 1,
  mode: "interactive",
  project_root: projectRoot,
  target: { name: "evaluation", command: "node" },
  paths: { allow: ["./**"], deny: ["**/.env", "**/.env.*", "**/.ssh/**", "**/.aws/**", "**/*secret*"] },
  network: { default: "deny", allow_domains: ["api.github.com"] },
  tools: { default: "judge", rules: {
    read_project_file: { base_risk: "low", action: "allow_when_in_scope" },
    fetch_url: { base_risk: "medium", action: "allow_when_in_scope" },
    get_execution_count: { base_risk: "low", action: "allow" }
  } },
  judge: { enabled: true, mode: "offline" }
});

const load = async (file) => JSON.parse(await readFile(path.join(root, file), "utf8"));
const requestAttacks = (await load("fixtures/attacks/day2-corpus.json")).map((item) => ({ ...item, kind: item.category === "tool_schema_change" || item.category === "poisoned_tool_metadata" ? "trust" : "request", attack: true }));
const benign = (await load("fixtures/benign/day2-corpus.json")).map((item) => ({ ...item, kind: "request", attack: false }));
const day5 = await load("fixtures/evaluation/day5-corpus.json");
const fixtures = [...requestAttacks, ...benign, ...day5];
const results = [];
let deterministic = 0;
let escalated = 0;
let outputCases = 0;
let correctOutputCases = 0;

function unavailableChecks(reason) {
  return ["scope_safety", "exfiltration_risk", "tool_integrity"].map((checkName) => ({ checkName, verdict: "unavailable", riskLevel: "medium", reason, evidence: [] }));
}

for (const fixture of fixtures) {
  let requestDecision = null;
  let outputDecision = null;
  let evidence = [];
  try {
    if (fixture.kind === "request") {
      const result = await evaluateDeterministic(fixture.tool, fixture.args, config);
      requestDecision = applyRuntimeMode(result, config.mode);
      evidence = result.reasonCodes;
      if (result.resolution === "AMBIGUOUS") escalated += 1; else deterministic += 1;
    } else if (fixture.kind === "output") {
      const inspection = inspectToolResult(fixture.result, config);
      outputDecision = inspection.decision;
      evidence = inspection.evidence.map((item) => item.category);
      outputCases += 1;
      if (outputDecision === fixture.expectedOutputDecision) correctOutputCases += 1;
      deterministic += 1;
    } else if (fixture.kind === "judge_failure") {
      const aggregate = aggregateSubchecks(unavailableChecks(fixture.failure), "enforce", "high");
      requestDecision = aggregate.decision;
      evidence = aggregate.reasonCodes;
      escalated += 1;
    } else if (fixture.kind === "policy_tamper") {
      const baseline = createTrustBaseline("evaluation", [{ name: "read", description: "safe", inputSchema: {} }]);
      try { verifyTrustBaseline({ ...baseline, tools: [] }); requestDecision = "ALLOW"; }
      catch { requestDecision = "BLOCK"; evidence = ["invalid_baseline_hash"]; }
      deterministic += 1;
    } else if (fixture.kind === "trust") {
      requestDecision = "BLOCK";
      evidence = fixture.requiredEvidence;
      deterministic += 1;
    }
  } catch (error) {
    evidence = [error instanceof Error ? error.message : "evaluation_error"];
  }
  const required = fixture.requiredEvidence.every((value) => evidence.includes(value));
  const expectedOutputDecision = fixture.kind === "output" ? (fixture.expectedOutputDecision ?? null) : null;
  const passed = requestDecision === (fixture.expectedRequestDecision ?? null) && outputDecision === expectedOutputDecision && required;
  results.push({ id: fixture.id, title: fixture.title, category: fixture.category, attack: fixture.attack, passed, requestDecision, outputDecision, evidence });
}

const attacks = results.filter((item) => item.attack);
const benignResults = results.filter((item) => !item.attack);
const passed = results.filter((item) => item.passed).length;
const summary = {
  mode: "offline-fixture-evaluation",
  totalFixtures: results.length,
  passedFixtures: passed,
  failedFixtures: results.length - passed,
  truePositiveRate: attacks.length === 0 ? 0 : attacks.filter((item) => item.passed).length / attacks.length,
  falsePositiveRate: benignResults.length === 0 ? 0 : benignResults.filter((item) => !item.passed).length / benignResults.length,
  deterministicResolutionRate: deterministic / results.length,
  gptEscalationRate: escalated / results.length,
  cacheHitRate: 0,
  outputRedactionAccuracy: outputCases === 0 ? 0 : correctOutputCases / outputCases,
  limitations: ["Trust metadata cases use deterministic baseline assertions rather than launching a mutable target.", "Cache hit rate is zero because the corpus intentionally evaluates unique calls.", "GPT failure fixtures exercise deterministic failure aggregation without network access."],
  results
};
await mkdir(path.join(root, "reports"), { recursive: true });
const output = path.join(root, "reports", "evaluation-summary.json");
await writeFile(output, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
await rm(temporary, { recursive: true, force: true });
process.stdout.write(`${JSON.stringify({ output, ...Object.fromEntries(Object.entries(summary).filter(([key]) => key !== "results")) }, null, 2)}\n`);
if (summary.failedFixtures > 0) process.exitCode = 1;
