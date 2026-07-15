import { readAuditEvents } from "@mcp-warden/audit";
import { sha256 } from "@mcp-warden/shared";
import { z } from "zod";

export const sessionReportSchema = z.object({
  version: z.literal(1),
  sessionId: z.string(),
  sourceIntegrity: z.literal("verified"),
  generatedAt: z.string(),
  sourceHash: z.string(),
  summary: z.object({ events: z.number(), allowed: z.number(), blocked: z.number(), askUser: z.number(), redacted: z.number(), quarantined: z.number(), highestRisk: z.string() }),
  timeline: z.array(z.object({ sequence: z.number(), timestamp: z.string(), eventType: z.string(), decision: z.string().nullable(), riskLevel: z.string().nullable(), eventHash: z.string() }))
});
export type SessionReport = z.infer<typeof sessionReportSchema>;

const risks = ["none", "low", "medium", "high", "critical"];
export async function generateSessionReport(filePath: string, generatedAt = new Date().toISOString()): Promise<SessionReport> {
  const events = await readAuditEvents(filePath);
  if (events.length === 0) throw new Error("Cannot generate a report from an empty audit log");
  const decisions = events.map((event) => typeof event.payload.decision === "string" ? event.payload.decision : "");
  const riskLevels = events.map((event) => {
    if (typeof event.payload.riskLevel === "string") return event.payload.riskLevel;
    if (event.payload.deterministic !== null && typeof event.payload.deterministic === "object") {
      const nestedRisk = (event.payload.deterministic as Record<string, unknown>).riskLevel;
      return typeof nestedRisk === "string" ? nestedRisk : "none";
    }
    return "none";
  });
  const highestRisk = riskLevels.map(String).sort((left, right) => risks.indexOf(right) - risks.indexOf(left))[0] ?? "none";
  return sessionReportSchema.parse({
    version: 1,
    sessionId: events[0]?.sessionId,
    sourceIntegrity: "verified",
    generatedAt,
    sourceHash: sha256(events),
    summary: {
      events: events.length,
      allowed: decisions.filter((value) => value === "ALLOW").length,
      blocked: Math.max(decisions.filter((value) => value === "BLOCK").length, events.filter((event) => event.eventType === "call_blocked").length),
      askUser: decisions.filter((value) => value === "ASK_USER").length,
      redacted: decisions.filter((value) => value === "REDACT").length,
      quarantined: decisions.filter((value) => value === "QUARANTINE").length,
      highestRisk: String(highestRisk)
    },
    timeline: events.map((event) => ({ sequence: event.sequence, timestamp: event.timestamp, eventType: event.eventType, decision: typeof event.payload.decision === "string" ? event.payload.decision : null, riskLevel: typeof event.payload.riskLevel === "string" ? event.payload.riskLevel : null, eventHash: event.eventHash }))
  });
}

export function renderMarkdownReport(report: SessionReport): string {
  const rows = report.timeline.map((event) => `| ${event.sequence} | ${event.timestamp} | ${event.eventType} | ${event.decision ?? "—"} | ${event.riskLevel ?? "—"} |`).join("\n");
  return `# MCP Warden session report\n\n- Session: \`${report.sessionId}\`\n- Source integrity: ${report.sourceIntegrity} tamper-evident hash chain\n- Events: ${report.summary.events}\n- Decisions: ${report.summary.allowed} allowed, ${report.summary.blocked} blocked, ${report.summary.askUser} ask-user\n- Output actions: ${report.summary.redacted} redacted, ${report.summary.quarantined} quarantined\n- Highest risk: ${report.summary.highestRisk}\n- Source hash: \`${report.sourceHash}\`\n\n| # | Timestamp | Event | Decision | Risk |\n| ---: | --- | --- | --- | --- |\n${rows}\n`;
}
