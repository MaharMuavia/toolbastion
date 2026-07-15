import { writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { verifyAuditFile } from "@mcp-warden/audit";
import { OpenAIJudge } from "@mcp-warden/judge";
import { wardenConfigSchema } from "@mcp-warden/shared";

describe("safe error handling", () => {
  it("reports malformed audit lines without throwing plaintext content", async () => {
    const file = path.join(os.tmpdir(), `warden-malformed-${crypto.randomUUID()}.jsonl`);
    await writeFile(file, "{not-json}\n", "utf8");
    const verification = await verifyAuditFile(file);
    expect(verification.valid).toBe(false);
    expect(verification.errors[0]).toContain("line 1");
  });

  it("fails closed when live judge credentials are unavailable", async () => {
    const config = wardenConfigSchema.parse({ version: 1, mode: "enforce", target: { name: "fixture", command: "node" }, judge: { mode: "live" } });
    const prior = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    try {
      const verdict = await new OpenAIJudge(config.judge).evaluateRequest({ toolName: "ambiguous", untrustedDescription: "fixture", schemaSummary: {}, args: {}, policySummary: {}, deterministicEvidence: [], recentEvents: [], baseRisk: "medium", runtimeMode: "enforce" });
      expect(verdict.decision).toBe("BLOCK");
      expect(verdict.reasonCodes).toContain("judge_unavailable");
    } finally { if (prior) process.env.OPENAI_API_KEY = prior; }
  });
});
