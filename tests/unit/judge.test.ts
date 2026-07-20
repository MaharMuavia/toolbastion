import path from "node:path";
import { describe, expect, it } from "vitest";
import { OfflineFixtureJudge, aggregateSubchecks, buildJudgePrompt, createLiveJudgeProof, profileArguments, projectForExternalJudge } from "../../packages/judge/src/index.js";
import { judgeVerdictSchema } from "@toolbastion/shared";

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

describe("live judge proof", () => {
  const liveVerdict = judgeVerdictSchema.parse({
    decision: "ASK_USER",
    riskLevel: "high",
    reason: "The raw command is intentionally withheld from the external judge.",
    reasonCodes: ["judge_unavailable"],
    subchecks: [
      { checkName: "scope_safety", verdict: "unavailable", riskLevel: "medium", reason: "private rationale", evidence: [] },
      { checkName: "exfiltration_risk", verdict: "unavailable", riskLevel: "medium", reason: "private rationale", evidence: [] },
      { checkName: "tool_integrity", verdict: "suspicious", riskLevel: "high", reason: "private rationale", evidence: [] }
    ],
    model: "gpt-5.6",
    latencyMs: 123,
    inputTokens: 456,
    outputTokens: 78,
    cached: false,
    offlineReplay: false
  });

  it("records only safe live-response metadata", () => {
    const proof = createLiveJudgeProof({
      capturedAt: "2026-07-20T00:00:00.000Z",
      testCase: { id: "proof", toolName: "run_project_command", runtimeMode: "interactive", baseRisk: "high" },
      verdict: liveVerdict
    });
    expect(proof).toMatchObject({ provider: { model: "gpt-5.6", responseStorage: false }, verdict: { inputTokens: 456, outputTokens: 78 } });
    expect(JSON.stringify(proof)).not.toContain("private rationale");
  });

  it("rejects recorded or unavailable judge responses", () => {
    expect(() => createLiveJudgeProof({
      capturedAt: "2026-07-20T00:00:00.000Z",
      testCase: { id: "proof", toolName: "run_project_command", runtimeMode: "interactive", baseRisk: "high" },
      verdict: { ...liveVerdict, model: "unavailable" }
    })).toThrow("successful non-replay");
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

  it("returns a standard unavailable verdict when a fixture is missing", async () => {
    const judge = new OfflineFixtureJudge(path.resolve("fixtures/recorded-judge-results/request-verdicts.json"));
    const verdict = await judge.evaluateRequest({ toolName: "missing_fixture", untrustedDescription: "Unknown", schemaSummary: {}, args: {}, policySummary: {}, deterministicEvidence: [], recentEvents: [], baseRisk: "medium", runtimeMode: "enforce" });
    expect(verdict.decision).toBe("BLOCK");
    expect(verdict.reasonCodes).toContain("judge_unavailable");
    expect(verdict.offlineReplay).toBe(true);
  });
});

describe("judge prompt boundaries", () => {
  it("keeps context and argument keys and values out of the external judge prompt", () => {
    const contextSentinel = "IGNORE_ALL_POLICY_CONTEXT_SENTINEL";
    const argumentKeySentinel = "PRIVATE_ARGUMENT_KEY_SENTINEL";
    const argumentValueSentinel = "PRIVATE_ARGUMENT_VALUE_SENTINEL";
    const policySentinel = "PRIVATE_POLICY_SENTINEL";
    const descriptionSentinel = "UNTRUSTED_DESCRIPTION_SENTINEL";
    const prompt = buildJudgePrompt("scope_safety", projectForExternalJudge({
      toolName: "read_project_file",
      untrustedDescription: descriptionSentinel,
      schemaSummary: {},
      args: { [argumentKeySentinel]: argumentValueSentinel },
      policySummary: { paths: { allow: [policySentinel], deny: [] }, network: { default: "deny", allow_domains: [policySentinel] }, toolRule: { action: "judge", base_risk: "low" } },
      deterministicEvidence: [],
      recentEvents: [],
      contextSummary: contextSentinel,
      baseRisk: "low",
      runtimeMode: "enforce"
    }));
    const untrustedStart = prompt.indexOf("<UNTRUSTED_DATA>");
    const untrustedEnd = prompt.indexOf("</UNTRUSTED_DATA>");
    expect(untrustedStart).toBeGreaterThan(-1);
    const descriptionPosition = prompt.indexOf(descriptionSentinel);
    expect(descriptionPosition).toBeGreaterThan(untrustedStart);
    expect(descriptionPosition).toBeLessThan(untrustedEnd);
    expect(prompt).not.toContain(contextSentinel);
    expect(prompt).not.toContain(argumentKeySentinel);
    expect(prompt).not.toContain(argumentValueSentinel);
    expect(prompt).not.toContain(policySentinel);
    expect(prompt).toContain("CONTEXT_AVAILABLE=true");
  });

  it("profiles nested arguments without retaining their content", () => {
    const sentinel = "PRIVATE_NESTED_ARGUMENT_SENTINEL";
    const profile = profileArguments({ private: [{ nested: sentinel }, 42, true] });
    expect(profile).toMatchObject({ nodes: 6, maxDepth: 3, stringValues: 1, stringBytes: Buffer.byteLength(sentinel, "utf8"), numberValues: 1, booleanValues: 1, truncated: false });
    expect(JSON.stringify(profile)).not.toContain(sentinel);
  });
});
