import { readFile, stat } from "node:fs/promises";
import { z } from "zod";
import { riskLevelSchema } from "@toolbastion/shared";

const lifecycleEventSchema = z.object({
  eventId: z.string(),
  timestamp: z.string().datetime(),
  eventType: z.string(),
  payload: z.record(z.string(), z.unknown())
});

function nestedRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function summary(eventType: string, payload: Record<string, unknown>): string {
  const toolName = stringValue(payload.toolName);
  const reason = stringValue(payload.reason);
  const decision = stringValue(payload.decision);
  const messages: Record<string, string> = {
    session_started: "Enforcement session initialized",
    target_connecting: "Connecting to protected MCP target",
    target_connected: "Protected MCP target connected",
    tools_listed: "Target tool inventory loaded",
    tools_changed: "Target reported a tool-list change",
    trust_verified: payload.approved === true ? "Tool metadata matches the approved baseline" : "Tool metadata requires approval",
    policy_evaluated: `${toolName ?? "Tool call"} evaluated${decision ? `: ${decision}` : ""}`,
    call_blocked: `${toolName ?? "Tool call"} stopped before execution${reason ? `: ${reason}` : ""}`,
    tool_forwarded: `${toolName ?? "Tool call"} forwarded to the protected target`,
    target_call_failed: `${toolName ?? "Target tool"} failed or exceeded its deadline`,
    output_inspected: `${toolName ?? "Tool output"} inspected${decision ? `: ${decision}` : ""}`,
    audit_failed: "Audit persistence failed; enforce mode fails closed",
    target_closed: "Protected MCP target closed"
  };
  return messages[eventType] ?? "Runtime lifecycle event";
}

export async function loadRuntimeSession(filePath: string, fallbackTargetName: string, runtimeMode: string): Promise<unknown> {
  const metadata = await stat(filePath);
  if (metadata.size > 5 * 1024 * 1024) throw new Error("Runtime event log exceeds the 5 MiB dashboard limit");
  if (Date.now() - metadata.mtimeMs > 15_000) throw new Error("Runtime event log is stale");
  const allEvents = (await readFile(filePath, "utf8"))
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => lifecycleEventSchema.parse(JSON.parse(line)));
  const lastLifecycleEvent = [...allEvents].reverse().find((event) => event.eventType !== "heartbeat");
  if (lastLifecycleEvent?.eventType === "target_closed") throw new Error("Runtime session is closed");
  const events = allEvents.filter((event) => event.eventType !== "heartbeat");
  const started = events.find((event) => event.eventType === "session_started");
  const sessionId = stringValue(started?.payload.sessionId);
  if (!sessionId) throw new Error("Runtime event log has no session identifier");
  const connected = events.find((event) => event.eventType === "target_connected");
  const targetName = stringValue(connected?.payload.targetName) ?? fallbackTargetName;

  return {
    sessionId,
    label: "LIVE LOCAL SESSION",
    targetName,
    startedAt: started?.timestamp ?? events[0]?.timestamp ?? new Date().toISOString(),
    mode: runtimeMode,
    events: events.map((event) => {
      const deterministic = nestedRecord(event.payload.deterministic);
      const judge = nestedRecord(event.payload.judge);
      const directRisk = riskLevelSchema.safeParse(event.payload.riskLevel);
      const deterministicRisk = riskLevelSchema.safeParse(deterministic.riskLevel);
      const judgeRisk = riskLevelSchema.safeParse(judge.riskLevel);
      let decision: string | undefined;
      if (event.eventType === "call_blocked") decision = event.payload.reason === "operator_approval_required" ? "ASK_USER" : "BLOCK";
      if (event.eventType === "output_inspected") decision = event.payload.decision === "PASS" ? "ALLOW" : stringValue(event.payload.decision);
      const inputTokens = typeof judge.inputTokens === "number" ? judge.inputTokens : 0;
      const outputTokens = typeof judge.outputTokens === "number" ? judge.outputTokens : 0;
      return {
        eventId: event.eventId,
        sessionId,
        timestamp: event.timestamp,
        eventType: event.eventType,
        riskLevel: directRisk.success ? directRisk.data : deterministicRisk.success ? deterministicRisk.data : judgeRisk.success ? judgeRisk.data : "none",
        ...(stringValue(event.payload.toolName) === undefined ? {} : { toolName: stringValue(event.payload.toolName) }),
        ...(decision === undefined ? {} : { decision }),
        summary: summary(event.eventType, event.payload),
        latencyMs: typeof judge.latencyMs === "number" ? judge.latencyMs : 0,
        judgeTokens: inputTokens + outputTokens,
        cacheHit: event.payload.cacheHit === true
      };
    })
  };
}
