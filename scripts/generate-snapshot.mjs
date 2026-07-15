/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { canonicalJson, sha256 } from "@mcp-warden/shared";
import { generateSessionReport, renderMarkdownReport } from "@mcp-warden/reports";

const root = process.cwd();
const session = JSON.parse(await readFile(path.join(root, "fixtures", "dashboard-snapshot", "session.json"), "utf8"));
const scenarios = await readFile(path.join(root, "fixtures", "dashboard-snapshot", "scenarios.json"), "utf8");
const destination = path.join(root, "apps", "dashboard", "public", "snapshot");
await mkdir(destination, { recursive: true });
let previousHash = "GENESIS";
const auditEvents = session.events.map((event, index) => {
  const unsigned = { sequence: index + 1, eventId: event.eventId, sessionId: session.sessionId, timestamp: event.timestamp, eventType: event.eventType, payload: { toolName: event.toolName, decision: event.decision, riskLevel: event.riskLevel, summary: event.summary }, previousHash };
  const completed = { ...unsigned, eventHash: sha256(unsigned) };
  previousHash = completed.eventHash;
  return completed;
});
const auditPath = path.join(destination, "audit.jsonl");
await writeFile(auditPath, `${auditEvents.map(canonicalJson).join("\n")}\n`, "utf8");
const report = await generateSessionReport(auditPath, session.startedAt);
await writeFile(path.join(destination, "session.json"), `${JSON.stringify({ ...session, staticLabel: "Read-only recorded security session" }, null, 2)}\n`, "utf8");
await writeFile(path.join(destination, "scenarios.json"), scenarios, "utf8");
await writeFile(path.join(destination, "report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
await writeFile(path.join(destination, "report.md"), renderMarkdownReport(report), "utf8");
try { await writeFile(path.join(destination, "evaluation-summary.json"), await readFile(path.join(root, "reports", "evaluation-summary.json"), "utf8"), "utf8"); }
catch { /* Evaluation is generated separately and is optional for a partial local build. */ }
process.stdout.write(`Generated read-only dashboard snapshot in ${destination}\n`);
