import path from "node:path";
import { describe, expect, it } from "vitest";
import { OfflineFixtureJudge, aggregateSubchecks } from "../../packages/judge/src/index.js";

const safeChecks = [
  { checkName: "scope_safety" as const, verdict: "safe" as const, riskLevel: "low" as const, reason: "safe", evidence: [] },
  { checkName: "exfiltration_risk" as const, verdict: "safe" as const, riskLevel: "none" as const, reason: "safe", evidence: [] },
  { checkName: "tool_integrity" as const, verdict: "safe" as const, riskLevel: "low" as const, reason: "safe", evidence: [] }
];

describe("judge aggregation", () => {
  it("blocks any malicious verdict", () => {
    expect(aggregateSubchecks([{ ...safeChecks[0]!, verdict: "malicious", riskLevel: "critical" }, safeChecks[1]!, safeChecks[2]!], "interactive", "low").decision).toBe("BLOCK");
  });
  it("asks for two suspicious verdicts", () => {
    expect(aggregateSubchecks([{ ...safeChecks[0]!, verdict: "suspicious" }, { ...safeChecks[1]!, verdict: "suspicious" }, safeChecks[2]!], "interactive", "low").decision).toBe("ASK_USER");
  });
  it("fails closed when a required check is unavailable in enforce mode", () => {
    expect(aggregateSubchecks([{ ...safeChecks[0]!, verdict: "unavailable" }, safeChecks[1]!, safeChecks[2]!], "enforce", "low").decision).toBe("BLOCK");
  });
  it("allows when every check is safe", () => {
    expect(aggregateSubchecks(safeChecks, "enforce", "medium").decision).toBe("ALLOW");
  });
});

describe("offline fixture replay", () => {
  it("returns the live verdict shape while declaring recorded replay", async () => {
    const judge = new OfflineFixtureJudge(path.resolve("fixtures/recorded-judge-results/request-verdicts.json"));
    const verdict = await judge.evaluateRequest({ toolName: "run_project_command", untrustedDescription: "Run", schemaSummary: {}, args: { command: "npm test" }, policySummary: {}, deterministicEvidence: [], recentEvents: [], baseRisk: "high", runtimeMode: "enforce" });
    expect(verdict.decision).toBe("ALLOW");
    expect(verdict.offlineReplay).toBe(true);
    expect(verdict.model).toBe("recorded-fixture");
    expect(verdict.inputTokens).toBe(0);
  });
});

