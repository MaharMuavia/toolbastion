import { describe, expect, it } from "vitest";
import { runtimeEventSchema, sanitizeRuntimeEvent } from "@toolbastion/shared";

describe("runtime event contract", () => {
  it("allowlists lifecycle metrics while excluding private payloads", () => {
    const secret = "RUNTIME_EVENT_SECRET_SENTINEL";
    const event = sanitizeRuntimeEvent({
      eventId: "event-1",
      sessionId: "session-1",
      timestamp: "2026-07-21T00:00:00.000Z",
      eventType: "authorization_completed",
      judgeRequestedModel: "gpt-5.6",
      payload: {
        callId: "call-1",
        toolName: "run_project_command",
        authorizationDecision: "ALLOW",
        executionState: "NOT_DISPATCHED",
        outputDecision: "NOT_INSPECTED",
        deterministic: { riskLevel: "medium", evidence: [{ rawValue: secret }] },
        judge: { model: "gpt-5.6-2026-07-01", inputTokens: 17, outputTokens: 9, latencyMs: 42, offlineReplay: false },
        cacheHit: true,
        reasonCodes: ["ambiguous_operation"],
        args: { command: secret },
        policy: { private: secret },
        context: secret,
        rationale: secret,
        credential: secret
      }
    });

    expect(runtimeEventSchema.parse(event)).toMatchObject({
      schemaVersion: 1,
      callId: "call-1",
      decisionSource: "cache",
      inputTokens: 17,
      outputTokens: 9,
      judgeLatencyMs: 42,
      cacheHit: true
    });
    expect(JSON.stringify(event)).not.toContain(secret);
    expect(event).not.toHaveProperty("args");
    expect(event).not.toHaveProperty("policy");
  });

  it("represents audit failure without a synthetic pre-execution decision", () => {
    const event = sanitizeRuntimeEvent({
      eventId: "event-2",
      sessionId: "session-2",
      timestamp: "2026-07-21T00:00:00.000Z",
      eventType: "call_completed",
      payload: {
        callId: "call-2",
        toolName: "read_project_file",
        authorizationDecision: "ALLOW",
        executionState: "COMPLETED",
        outputDecision: "NOT_RELEASED",
        evidenceState: "UNAVAILABLE",
        reason: "audit_unavailable_after_execution"
      }
    });

    expect(event).toMatchObject({ authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "NOT_RELEASED", evidenceState: "UNAVAILABLE" });
  });

  it("preserves lifecycle decisions, semantic metrics, cache state, redaction, and quarantine without raw call data", () => {
    const cases = [
      { eventType: "call_completed" as const, authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "PASS", expectedSource: "deterministic" },
      { eventType: "call_blocked" as const, authorizationDecision: "BLOCK_BEFORE_EXECUTION", executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED", expectedSource: "deterministic" },
      { eventType: "call_blocked" as const, authorizationDecision: "ASK_USER", executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED", expectedSource: "semantic_judge" },
      { eventType: "call_completed" as const, authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "REDACT", expectedSource: "semantic_judge" },
      { eventType: "call_completed" as const, authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "QUARANTINE", expectedSource: "cache" }
    ];
    for (const [index, fixture] of cases.entries()) {
      const event = sanitizeRuntimeEvent({
        eventId: `event-${index}`,
        sessionId: "session-lifecycle",
        timestamp: "2026-07-21T00:00:00.000Z",
        eventType: fixture.eventType,
        payload: {
          callId: `call-${index}`,
          toolName: "safe_tool",
          authorizationDecision: fixture.authorizationDecision,
          executionState: fixture.executionState,
          outputDecision: fixture.outputDecision,
          cacheHit: fixture.expectedSource === "cache",
          judge: fixture.expectedSource === "deterministic" ? undefined : { model: "gpt-5.6", inputTokens: 31, outputTokens: 11, latencyMs: 17 },
          reasonCodes: ["test_lifecycle"],
          args: { private: "must-not-leak" }
        }
      });
      expect(event).toMatchObject({
        authorizationDecision: fixture.authorizationDecision,
        executionState: fixture.executionState,
        outputDecision: fixture.outputDecision,
        decisionSource: fixture.expectedSource,
        cacheHit: fixture.expectedSource === "cache"
      });
      if (fixture.expectedSource !== "deterministic") expect(event).toMatchObject({ inputTokens: 31, outputTokens: 11, judgeLatencyMs: 17 });
      expect(JSON.stringify(event)).not.toContain("must-not-leak");
    }
  });
});
