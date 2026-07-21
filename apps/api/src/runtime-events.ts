import { stat, readFile } from "node:fs/promises";
import { runtimeEventSchema, type RuntimeEvent } from "@toolbastion/shared";

export const RUNTIME_LOG_MAX_BYTES = 64 * 1024 * 1024;
export const RUNTIME_LOG_STALE_MS = 15_000;
export const runtimeSourceStates = ["LIVE_HEALTHY", "LIVE_PARTIAL", "LIVE_STALE", "LIVE_INVALID", "LIVE_CLOSED", "RECORDED_SNAPSHOT"] as const;
export type RuntimeSourceState = typeof runtimeSourceStates[number];

export type RuntimeEventSummary = {
  eventId: string;
  sessionId: string;
  callId?: string;
  timestamp: string;
  eventType: RuntimeEvent["eventType"];
  riskLevel: RuntimeEvent["riskLevel"];
  toolName?: string;
  decision?: "ALLOW" | "ASK_USER" | "BLOCK" | "REDACT" | "QUARANTINE";
  summary: string;
  latencyMs: number;
  judgeTokens: number;
  cacheHit: boolean;
  authorizationDecision?: RuntimeEvent["authorizationDecision"];
  executionState?: RuntimeEvent["executionState"];
  outputDecision?: RuntimeEvent["outputDecision"];
  decisionSource: RuntimeEvent["decisionSource"];
  evidenceState: RuntimeEvent["evidenceState"];
  reasonCodes: string[];
};

export type LiveRuntimeSession = {
  sessionId: string;
  label: "LIVE LOCAL SESSION";
  targetName: string;
  startedAt: string;
  mode: string;
  events: RuntimeEventSummary[];
};

export type RuntimeLoadResult =
  | { sourceState: "LIVE_HEALTHY" | "LIVE_PARTIAL"; reasonCode: "live_evidence_available" | "runtime_log_retention_boundary"; session: LiveRuntimeSession }
  | { sourceState: Exclude<RuntimeSourceState, "LIVE_HEALTHY" | "LIVE_PARTIAL" | "RECORDED_SNAPSHOT">; reasonCode: string };

function summary(event: RuntimeEvent): string {
  const tool = event.toolName ?? "Tool call";
  switch (event.eventType) {
    case "session_started": return "Enforcement session initialized";
    case "target_connecting": return "Connecting to protected MCP target";
    case "target_connected": return "Protected MCP target connected";
    case "tools_listed": return "Target tool inventory loaded";
    case "tools_changed": return "Target tool inventory changed; trust is being revalidated";
    case "trust_verified": return "Tool metadata trust baseline evaluated";
    case "policy_evaluated": return `${tool} authorization evaluated`;
    case "tool_call_received": return `${tool} received by enforcement`;
    case "authorization_completed": return `${tool} authorization completed`;
    case "tool_dispatch_started": return `${tool} dispatched to protected target`;
    case "tool_dispatch_completed": return `${tool} target execution completed`;
    case "tool_dispatch_failed": return `${tool} target execution failed`;
    case "tool_dispatch_timed_out": return `${tool} exceeded its execution deadline`;
    case "target_termination_started": return "Timed-out target termination started";
    case "target_terminated": return "Timed-out target termination confirmed";
    case "target_restart_started": return "Protected target restart started";
    case "target_restarted": return "Protected target restart completed";
    case "output_inspected": return `${tool} output inspected before release`;
    case "call_completed": return `${tool} lifecycle completed`;
    case "call_blocked": return `${tool} stopped before target execution`;
    case "audit_failed": return "Evidence persistence failed; session is fail-closed";
    case "target_closed": return "Protected target closed";
    case "runtime_log_rotated": return "Runtime evidence log rotated; earlier history is retained only within the configured bound";
    case "heartbeat": return "Live runtime heartbeat";
  }
}

function dashboardDecision(event: RuntimeEvent): RuntimeEventSummary["decision"] | undefined {
  if (event.eventType === "call_blocked") return event.authorizationDecision === "ASK_USER" ? "ASK_USER" : "BLOCK";
  if (event.eventType === "output_inspected" || event.eventType === "call_completed") {
    if (event.outputDecision === "REDACT" || event.outputDecision === "QUARANTINE") return event.outputDecision;
    if (event.authorizationDecision === "ALLOW") return "ALLOW";
  }
  return undefined;
}

export function summarizeRuntimeEvent(event: RuntimeEvent): RuntimeEventSummary {
  const decision = dashboardDecision(event);
  return {
    eventId: event.eventId,
    sessionId: event.sessionId,
    ...(event.callId === undefined ? {} : { callId: event.callId }),
    timestamp: event.timestamp,
    eventType: event.eventType,
    riskLevel: event.riskLevel,
    ...(event.toolName === undefined ? {} : { toolName: event.toolName }),
    ...(decision === undefined ? {} : { decision }),
    summary: summary(event),
    latencyMs: event.judgeLatencyMs,
    judgeTokens: event.inputTokens + event.outputTokens,
    cacheHit: event.cacheHit,
    ...(event.authorizationDecision === undefined ? {} : { authorizationDecision: event.authorizationDecision }),
    ...(event.executionState === undefined ? {} : { executionState: event.executionState }),
    ...(event.outputDecision === undefined ? {} : { outputDecision: event.outputDecision }),
    decisionSource: event.decisionSource,
    evidenceState: event.evidenceState,
    reasonCodes: event.reasonCodes
  };
}

export function invalidRuntimeLog(reasonCode: string): RuntimeLoadResult {
  return { sourceState: "LIVE_INVALID", reasonCode };
}

export function runtimeSessionFromEvents(events: RuntimeEvent[], fallbackTargetName: string, runtimeMode: string): RuntimeLoadResult {
  if (events.length === 0) return invalidRuntimeLog("runtime_log_empty");
  const sessionIds = new Set(events.map((event) => event.sessionId));
  if (sessionIds.size !== 1) return invalidRuntimeLog("runtime_log_mixed_sessions");
  const lifecycle = events.filter((event) => event.eventType !== "heartbeat");
  const started = lifecycle.find((event) => event.eventType === "session_started");
  const rotated = lifecycle.find((event) => event.eventType === "runtime_log_rotated" && event.sessionStartedAt !== undefined);
  if (!started && !rotated) return invalidRuntimeLog("runtime_log_missing_session_start");
  const terminal = lifecycle.at(-1);
  if (terminal?.eventType === "target_closed") return { sourceState: "LIVE_CLOSED", reasonCode: "runtime_session_closed" };
  const sourceState = rotated === undefined ? "LIVE_HEALTHY" : "LIVE_PARTIAL";
  const reasonCode = rotated === undefined ? "live_evidence_available" : "runtime_log_retention_boundary";
  return {
    sourceState,
    reasonCode,
    session: {
      sessionId: (started ?? rotated)!.sessionId,
      label: "LIVE LOCAL SESSION",
      targetName: fallbackTargetName,
      startedAt: started?.timestamp ?? rotated!.sessionStartedAt!,
      mode: runtimeMode,
      events: lifecycle.map(summarizeRuntimeEvent)
    }
  };
}

export async function loadRuntimeSession(filePath: string, fallbackTargetName: string, runtimeMode: string, retainFiles = 0): Promise<RuntimeLoadResult> {
  let metadata: Awaited<ReturnType<typeof stat>>;
  try {
    metadata = await stat(filePath);
  } catch (error) {
    const code = error instanceof Error && "code" in error ? String(error.code) : "unknown";
    return invalidRuntimeLog(code === "ENOENT" ? "runtime_log_missing" : "runtime_log_unreadable");
  }
  if (!metadata.isFile()) return invalidRuntimeLog("runtime_log_not_a_file");
  if (Date.now() - metadata.mtimeMs > RUNTIME_LOG_STALE_MS) return { sourceState: "LIVE_STALE", reasonCode: "runtime_log_stale" };
  if (metadata.size > RUNTIME_LOG_MAX_BYTES) return invalidRuntimeLog("runtime_log_size_limit_exceeded");
  const files = [
    ...Array.from({ length: retainFiles }, (_value, index) => `${filePath}.${retainFiles - index}`),
    filePath
  ];
  let combined = "";
  let totalBytes = 0;
  try {
    for (const candidate of files) {
      let candidateMetadata = metadata;
      if (candidate !== filePath) {
        try {
          candidateMetadata = await stat(candidate);
        } catch (error) {
          const code = error instanceof Error && "code" in error ? String(error.code) : "unknown";
          if (code === "ENOENT") continue;
          return invalidRuntimeLog("runtime_log_unreadable");
        }
      }
      if (!candidateMetadata.isFile()) return invalidRuntimeLog(candidate === filePath ? "runtime_log_not_a_file" : "runtime_log_archive_not_a_file");
      totalBytes += candidateMetadata.size;
      if (candidateMetadata.size > RUNTIME_LOG_MAX_BYTES || totalBytes > RUNTIME_LOG_MAX_BYTES) return invalidRuntimeLog("runtime_log_size_limit_exceeded");
      combined += await readFile(candidate, "utf8");
      if (Buffer.byteLength(combined, "utf8") > RUNTIME_LOG_MAX_BYTES) return invalidRuntimeLog("runtime_log_size_limit_exceeded");
    }
  } catch {
    return invalidRuntimeLog("runtime_log_unreadable");
  }
  let events: RuntimeEvent[];
  try {
    events = combined.split(/\r?\n/).filter(Boolean).map((line) => runtimeEventSchema.parse(JSON.parse(line)));
  } catch {
    return invalidRuntimeLog("runtime_log_malformed");
  }
  return runtimeSessionFromEvents(events, fallbackTargetName, runtimeMode);
}
