import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { AuditLog } from "@mcp-warden/audit";
import { generateSessionReport, renderMarkdownReport } from "@mcp-warden/reports";

describe("audit reports", () => {
  it("regenerates deterministic JSON and Markdown from verified audit data", async () => {
    const log = new AuditLog(path.join(os.tmpdir(), `warden-report-${crypto.randomUUID()}`), "report-session");
    await log.append("policy_decision", { decision: "BLOCK", riskLevel: "critical" });
    await log.append("call_blocked", { reason: "test" });
    const first = await generateSessionReport(log.filePath, "2026-07-18T00:00:00.000Z");
    const second = await generateSessionReport(log.filePath, "2026-07-18T00:00:00.000Z");
    expect(first).toEqual(second);
    expect(first.summary.highestRisk).toBe("critical");
    expect(renderMarkdownReport(first)).toContain("Source integrity: verified tamper-evident hash chain");
  });
});
