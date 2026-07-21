import { appendFile, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { RuntimeEventTailer } from "../../apps/api/src/runtime-event-tailer.js";
import { loadRuntimeSession } from "../../apps/api/src/runtime-events.js";

const directories: string[] = [];

function event(eventId: string, eventType: string, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    eventId,
    sessionId: "runtime-tailer-session",
    timestamp: new Date().toISOString(),
    eventType,
    decisionSource: "deterministic",
    riskLevel: "none",
    inputTokens: 0,
    outputTokens: 0,
    judgeLatencyMs: 0,
    cacheHit: false,
    reasonCodes: [],
    evidenceState: "AVAILABLE",
    ...overrides
  };
}

afterEach(async () => {
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe("runtime event tailer", () => {
  it("shares incremental event updates and marks malformed appended data invalid", async () => {
    const directory = path.resolve(".test-tmp", `runtime-tailer-${crypto.randomUUID()}`);
    const file = path.join(directory, "runtime-events.jsonl");
    directories.push(directory);
    await mkdir(directory, { recursive: true });
    await writeFile(file, `${JSON.stringify(event("start", "session_started"))}\n${JSON.stringify(event("connected", "target_connected"))}\n`, "utf8");
    const tailer = new RuntimeEventTailer(file, "test-target", "enforce", 1);
    const updates: Array<{ type: string; eventId?: string; sourceState?: string }> = [];
    let fanoutCount = 0;
    const fanoutUnsubscribers = Array.from({ length: 15 }, () => tailer.subscribe((update) => {
      if (update.type === "event" && update.event.eventId === "blocked") fanoutCount += 1;
    }));
    const unsubscribe = tailer.subscribe((update) => {
      if (update.type === "event") updates.push({ type: update.type, eventId: update.event.eventId });
      else updates.push({ type: update.type, sourceState: update.state.sourceState });
    });
    try {
      expect((await tailer.snapshot()).sourceState).toBe("LIVE_HEALTHY");
      await appendFile(file, `${JSON.stringify(event("blocked", "call_blocked", { callId: "call-1", toolName: "read_file", authorizationDecision: "BLOCK_BEFORE_EXECUTION", executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED" }))}\n`, "utf8");
      await expect.poll(() => updates.some((update) => update.eventId === "blocked"), { timeout: 3_000 }).toBe(true);
      expect(fanoutCount).toBe(15);
      await appendFile(file, "{malformed}\n", "utf8");
      await expect.poll(() => updates.some((update) => update.sourceState === "LIVE_INVALID"), { timeout: 3_000 }).toBe(true);
    } finally {
      unsubscribe();
      for (const unsubscribeFanout of fanoutUnsubscribers) unsubscribeFanout();
      tailer.close();
    }
  });

  it("labels a bounded rotated lifecycle as partial instead of complete", async () => {
    const directory = path.resolve(".test-tmp", `runtime-rotation-${crypto.randomUUID()}`);
    const file = path.join(directory, "runtime-events.jsonl");
    directories.push(directory);
    await mkdir(directory, { recursive: true });
    await writeFile(`${file}.1`, `${JSON.stringify(event("start", "session_started"))}\n`, "utf8");
    await writeFile(file, `${JSON.stringify(event("rotation", "runtime_log_rotated", { sessionStartedAt: "2026-07-21T00:00:00.000Z", reasonCodes: ["runtime_log_rotated"] }))}\n${JSON.stringify(event("later", "target_connected"))}\n`, "utf8");
    const loaded = await loadRuntimeSession(file, "test-target", "enforce", 1);
    expect(loaded).toMatchObject({ sourceState: "LIVE_PARTIAL", reasonCode: "runtime_log_retention_boundary" });
  });
});
