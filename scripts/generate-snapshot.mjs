/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { canonicalJson, sha256 } from "@toolbastion/shared";
import { generateSessionReport, renderMarkdownReport } from "@toolbastion/reports";

const root = process.cwd();
const session = JSON.parse(await readFile(path.join(root, "fixtures", "dashboard-snapshot", "session.json"), "utf8"));
const scenarios = await readFile(path.join(root, "fixtures", "dashboard-snapshot", "scenarios.json"), "utf8");
const destination = path.join(root, "apps", "dashboard", "public", "snapshot");
await mkdir(destination, { recursive: true });
let previousHash = "GENESIS";
const auditEvents = [];
const appendAuditEvent = (eventId, timestamp, eventType, payload) => {
  const unsigned = { sequence: auditEvents.length + 1, eventId, sessionId: session.sessionId, timestamp, eventType, payload, previousHash };
  const completed = { ...unsigned, eventHash: sha256(unsigned) };
  previousHash = completed.eventHash;
  auditEvents.push(completed);
};
appendAuditEvent("audit-start", session.startedAt, "audit_session_started", { auditFormat: 2 });
for (const event of session.events) {
  appendAuditEvent(event.eventId, event.timestamp, event.eventType, { toolName: event.toolName, decision: event.decision, riskLevel: event.riskLevel, summary: event.summary });
}
appendAuditEvent("audit-seal", session.events.at(-1)?.timestamp ?? session.startedAt, "audit_session_sealed", { auditFormat: 2, eventCount: auditEvents.length, finalEventHash: previousHash });
const auditPath = path.join(destination, "audit.jsonl");
await writeFile(auditPath, `${auditEvents.map(canonicalJson).join("\n")}\n`, "utf8");
const report = await generateSessionReport(auditPath, session.startedAt);
await writeFile(path.join(destination, "session.json"), `${JSON.stringify({ ...session, staticLabel: "Read-only recorded security session" }, null, 2)}\n`, "utf8");
await writeFile(path.join(destination, "scenarios.json"), scenarios, "utf8");
await writeFile(path.join(destination, "report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
await writeFile(path.join(destination, "report.md"), renderMarkdownReport(report), "utf8");
const evaluationSummary = await readFile(path.join(root, "reports", "evaluation-summary.json"), "utf8");
JSON.parse(evaluationSummary);
await writeFile(path.join(destination, "evaluation-summary.json"), evaluationSummary, "utf8");
process.stdout.write(`Generated read-only dashboard snapshot in ${destination}\n`);
