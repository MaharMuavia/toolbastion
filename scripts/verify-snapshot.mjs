import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { verifyAndReadAuditFile } from "@toolbastion/audit";
import { generateSessionReport, renderMarkdownReport, sessionReportSchema } from "@toolbastion/reports";
import { canonicalJson } from "@toolbastion/shared";
import { z } from "zod";

/** @typedef {{ eventId: string, sessionId: string, timestamp: string, eventType: string, [key: string]: unknown }} SnapshotEvent */
/** @typedef {{ sessionId: string, startedAt: string, events: SnapshotEvent[], [key: string]: unknown }} SnapshotSession */
/** @typedef {{ passed: boolean, [key: string]: unknown }} EvaluationResult */
/** @typedef {{ totalFixtures: number, passedFixtures: number, failedFixtures: number, results: EvaluationResult[], [key: string]: unknown }} EvaluationSummary */

const snapshotDirectory = path.resolve("apps", "dashboard", "public", "snapshot");
const fixtureDirectory = path.resolve("fixtures", "dashboard-snapshot");
const paths = {
  audit: path.join(snapshotDirectory, "audit.jsonl"),
  session: path.join(snapshotDirectory, "session.json"),
  scenarios: path.join(snapshotDirectory, "scenarios.json"),
  report: path.join(snapshotDirectory, "report.json"),
  markdown: path.join(snapshotDirectory, "report.md"),
  evaluation: path.join(snapshotDirectory, "evaluation-summary.json"),
  fixtureSession: path.join(fixtureDirectory, "session.json"),
  fixtureScenarios: path.join(fixtureDirectory, "scenarios.json"),
  generatedEvaluation: path.resolve("reports", "evaluation-summary.json")
};

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** @param {unknown} value @returns {value is SnapshotEvent} */
function isSnapshotEvent(value) {
  return isRecord(value)
    && typeof value.eventId === "string"
    && typeof value.sessionId === "string"
    && typeof value.timestamp === "string"
    && typeof value.eventType === "string";
}

/** @param {unknown} value @returns {value is SnapshotSession} */
function isSnapshotSession(value) {
  return isRecord(value)
    && typeof value.sessionId === "string"
    && typeof value.startedAt === "string"
    && Array.isArray(value.events)
    && value.events.every(isSnapshotEvent);
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isScenario(value) {
  return isRecord(value)
    && typeof value.id === "string"
    && typeof value.title === "string"
    && typeof value.category === "string"
    && typeof value.expected === "string"
    && typeof value.actual === "string"
    && typeof value.summary === "string";
}

/** @param {unknown} value @returns {value is Record<string, unknown>[]} */
function isScenarioList(value) {
  return Array.isArray(value) && value.length > 0 && value.every(isScenario);
}

/** @param {unknown} value @returns {value is EvaluationSummary} */
function isPassingEvaluation(value) {
  return isRecord(value)
    && typeof value.totalFixtures === "number"
    && Number.isInteger(value.totalFixtures)
    && value.totalFixtures > 0
    && typeof value.passedFixtures === "number"
    && Number.isInteger(value.passedFixtures)
    && typeof value.failedFixtures === "number"
    && Number.isInteger(value.failedFixtures)
    && value.passedFixtures + value.failedFixtures === value.totalFixtures
    && value.failedFixtures === 0
    && Array.isArray(value.results)
    && value.results.length === value.totalFixtures
    && value.results.every((result) => isRecord(result) && result.passed === true);
}

/** @param {string} file @returns {Promise<unknown>} */
async function readJson(file) {
  return z.unknown().parse(JSON.parse(await readFile(file, "utf8")));
}

/** @param {SnapshotSession} session */
function deriveSnapshotMetrics(session) {
  const decisions = session.events.filter((event) => typeof event.decision === "string");
  const count = (decision) => decisions.filter((event) => event.decision === decision).length;
  return {
    totalToolCalls: decisions.length,
    allows: count("ALLOW"),
    blocks: count("BLOCK"),
    askUser: count("ASK_USER"),
    quarantines: count("QUARANTINE"),
    deterministicResolutionRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.judgeTokens === 0).length / decisions.length,
    judgeEscalationRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.judgeTokens > 0).length / decisions.length,
    judgeTokens: session.events.reduce((sum, event) => sum + (typeof event.judgeTokens === "number" ? event.judgeTokens : 0), 0),
    cacheHitRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.cacheHit === true).length / decisions.length
  };
}

const errors = [];
let verification = { valid: false, eventCount: 0, errors: ["Snapshot verification did not run"] };

try {
  const [fixtureSession, session, fixtureScenarios, scenarios, reportJson, reportMarkdown, generatedEvaluation, evaluation] = await Promise.all([
    readJson(paths.fixtureSession),
    readJson(paths.session),
    readJson(paths.fixtureScenarios),
    readJson(paths.scenarios),
    readJson(paths.report),
    readFile(paths.markdown, "utf8"),
    readJson(paths.generatedEvaluation),
    readJson(paths.evaluation)
  ]);
  const snapshot = await verifyAndReadAuditFile(paths.audit);
  verification = snapshot.verification;
  if (!verification.valid) errors.push(...verification.errors);

  if (!isSnapshotSession(session)) {
    errors.push("session.json is not a valid recorded session");
  } else if (snapshot.events.length > 0) {
    if (session.sessionId !== snapshot.events[0].sessionId) errors.push("session.json sessionId does not match the audit session");
    const recordedEvents = snapshot.events.filter((event) => event.eventType !== "audit_session_started" && event.eventType !== "audit_session_sealed");
    if (session.events.length !== recordedEvents.length) {
      errors.push("session.json event count does not match the recorded audit events");
    } else {
      for (let index = 0; index < recordedEvents.length; index += 1) {
        const displayed = session.events[index];
        const recorded = recordedEvents[index];
        if (displayed === undefined || recorded === undefined || displayed.eventId !== recorded.eventId || displayed.sessionId !== recorded.sessionId || displayed.timestamp !== recorded.timestamp || displayed.eventType !== recorded.eventType) {
          errors.push(`session.json event ${index + 1} does not match the audit event`);
          break;
        }
      }
    }
  }
  if (!isSnapshotSession(fixtureSession) || !isSnapshotSession(session) || canonicalJson(session) !== canonicalJson({ ...fixtureSession, metrics: deriveSnapshotMetrics(fixtureSession), staticLabel: "Read-only recorded security session" })) {
    errors.push("session.json does not match the recorded-session fixture");
  }

  if (!isScenarioList(scenarios) || !isScenarioList(fixtureScenarios) || canonicalJson(scenarios) !== canonicalJson(fixtureScenarios)) {
    errors.push("scenarios.json does not match the recorded scenario fixture");
  }

  const parsedReport = sessionReportSchema.safeParse(reportJson);
  if (!parsedReport.success) {
    errors.push("report.json does not match the report schema");
  } else if (isSnapshotSession(session) && verification.valid) {
    const expectedReport = await generateSessionReport(paths.audit, session.startedAt);
    if (canonicalJson(parsedReport.data) !== canonicalJson(expectedReport)) errors.push("report.json does not match the verified audit data");
    if (reportMarkdown !== renderMarkdownReport(expectedReport)) errors.push("report.md does not match report.json");
  }

  if (!isPassingEvaluation(evaluation) || !isPassingEvaluation(generatedEvaluation) || canonicalJson(evaluation) !== canonicalJson(generatedEvaluation)) {
    errors.push("evaluation-summary.json does not match a complete passing fixture evaluation");
  }
} catch (error) {
  errors.push(error instanceof Error ? error.message : "Snapshot verification failed");
}

const result = { paths, valid: errors.length === 0, eventCount: verification.eventCount, errors };
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.valid) process.exitCode = 2;
