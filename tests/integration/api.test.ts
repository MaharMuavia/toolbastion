import { mkdir, rm, symlink, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApi, startApi } from "../../apps/api/src/index.js";
import { createTrustBaseline, writeTrustBaseline } from "@toolbastion/policy";

const root = path.resolve(".");
const app = await createApi({ rootDir: root, configPath: path.join(root, "toolbastion.config.example.yaml"), eventLogPath: path.join(root, ".test-tmp", "missing-runtime-events.jsonl"), dashboardRoot: path.join(root, "apps", "dashboard", "dist") });

function runtimeEvent(eventId: string, eventType: string, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    eventId,
    sessionId: "live-session-1",
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

beforeAll(async () => app.ready());
afterAll(async () => app.close());

describe("dashboard API", () => {
  it("serves health and a completed fixture session", async () => {
    const health = await app.inject({ method: "GET", url: "/api/health" });
    expect(health.json()).toEqual({ status: "ok" });
    expect(health.headers["content-security-policy"]).toContain("default-src 'self'");
    expect(health.headers["x-content-type-options"]).toBe("nosniff");
    const response = await app.inject({ method: "GET", url: "/api/sessions/offline-day3-demo" });
    expect(response.statusCode).toBe(200);
    const body = response.json<{ label: string; metrics: { blocks: number } }>();
    expect(body.label).toBe("OFFLINE FIXTURE REPLAY");
    expect(body.metrics.blocks).toBe(2);
  });

  it("requires explicit acknowledgement before a non-localhost bind", async () => {
    await expect(startApi({ rootDir: root }, 4782, "0.0.0.0")).rejects.toThrow(/--expose acknowledgement/);
    await expect(startApi({ rootDir: root, allowRemote: true }, 4782, "0.0.0.0")).rejects.toThrow(/TOOLBASTION_API_TOKEN/);
  });

  it("requires a bearer token when API authentication is configured", async () => {
    const token = "a".repeat(32);
    const protectedApp = await createApi({ rootDir: root, accessToken: token, dashboardRoot: path.join(root, "apps", "dashboard", "dist") });
    try {
      await protectedApp.ready();
      expect((await protectedApp.inject({ method: "GET", url: "/api/health" })).statusCode).toBe(200);
      expect((await protectedApp.inject({ method: "GET", url: "/api/sessions" })).statusCode).toBe(401);
      expect((await protectedApp.inject({ method: "GET", url: "/api/sessions", headers: { authorization: `Bearer ${token}` } })).statusCode).toBe(200);
      expect((await protectedApp.inject({ method: "GET", url: "/" })).statusCode).toBe(200);
    } finally { await protectedApp.close(); }
  });

  it("serves the production dashboard from the localhost API", async () => {
    const response = await app.inject({ method: "GET", url: "/" });
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain("ToolBastion | Secure MCP tooling");
  });

  it("validates policy YAML without writing it", async () => {
    const response = await app.inject({ method: "POST", url: "/api/policy/validate", payload: { yaml: "version: 2\ntarget: {}" } });
    expect(response.statusCode).toBe(400);
    const body = response.json<{ issues: string[] }>();
    expect(body.issues[0]).toContain("version");
  });

  it("does not expose stack traces for invalid requests", async () => {
    const response = await app.inject({ method: "POST", url: "/api/demo/run", payload: { scenarioId: "../../attack" } });
    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain("stack");
  });

  it("runs an Attack Lab fixture and downloads all report formats", async () => {
    const scenarios = await app.inject({ method: "GET", url: "/api/demo/scenarios" });
    expect(scenarios.statusCode).toBe(200);
    expect(scenarios.json<unknown[]>()).toHaveLength(12);
    const replay = await app.inject({ method: "POST", url: "/api/demo/run", payload: { scenarioId: "path-traversal" } });
    expect(replay.json<{ matched: boolean; actual: string }>()).toMatchObject({ matched: true, actual: "BLOCK" });
    for (const url of ["/api/sessions/offline-day3-demo/report?format=markdown", "/api/sessions/offline-day3-demo/report?format=json", "/api/sessions/offline-day3-demo/audit", "/api/evaluation"]) {
      const download = await app.inject({ method: "GET", url });
      expect(download.statusCode).toBe(200);
      expect(download.headers["content-disposition"]).toContain("attachment");
      expect(download.body.length).toBeGreaterThan(20);
    }
  });

  it("labels healthy, stale, invalid, closed, and recorded runtime evidence explicitly", async () => {
    const directory = path.join(root, ".test-tmp", "api-live-events");
    const eventLogPath = path.join(directory, "runtime-events.jsonl");
    await mkdir(directory, { recursive: true });
    const lifecycle = [
      runtimeEvent("live-1", "session_started"),
      runtimeEvent("live-2", "target_connected"),
      runtimeEvent("live-3", "authorization_completed", { callId: "call-1", toolName: "read_file", authorizationDecision: "BLOCK_BEFORE_EXECUTION", executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED", riskLevel: "critical", reasonCodes: ["path_outside_project_root"] }),
      runtimeEvent("live-4", "call_blocked", { callId: "call-1", toolName: "read_file", authorizationDecision: "BLOCK_BEFORE_EXECUTION", executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED", riskLevel: "critical", reasonCodes: ["path_outside_project_root"] })
    ];
    await writeFile(eventLogPath, `${lifecycle.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
    const liveApp = await createApi({ rootDir: root, configPath: path.join(root, "toolbastion.config.example.yaml"), eventLogPath });
    try {
      await liveApp.ready();
      const sessions = (await liveApp.inject({ method: "GET", url: "/api/sessions" })).json<Array<{ sessionId: string; label: string; sourceState: string }>>();
      expect(sessions[0]).toMatchObject({ sessionId: "live-session-1", label: "LIVE LOCAL SESSION", sourceState: "LIVE_HEALTHY" });
      const detail = (await liveApp.inject({ method: "GET", url: "/api/sessions/live-session-1" })).json<{ targetName: string; metrics: { blocks: number } }>();
      expect(detail.targetName).toBe("benign-demo");
      expect(detail.metrics.blocks).toBe(1);
      await utimes(eventLogPath, new Date(Date.now() - 20_000), new Date(Date.now() - 20_000));
      expect((await liveApp.inject({ method: "GET", url: "/api/evidence/status" })).json()).toMatchObject({ sourceState: "LIVE_STALE", reasonCode: "runtime_log_stale" });
      await writeFile(eventLogPath, "{invalid-json}\n", "utf8");
      expect((await liveApp.inject({ method: "GET", url: "/api/evidence/status" })).json()).toMatchObject({ sourceState: "LIVE_INVALID", reasonCode: "runtime_log_malformed" });
      const closed = [...lifecycle, runtimeEvent("live-5", "target_closed")];
      await writeFile(eventLogPath, `${closed.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
      expect((await liveApp.inject({ method: "GET", url: "/api/evidence/status" })).json()).toMatchObject({ sourceState: "LIVE_CLOSED", reasonCode: "runtime_session_closed" });
      const recordedApp = await createApi({ rootDir: root });
      try {
        await recordedApp.ready();
        expect((await recordedApp.inject({ method: "GET", url: "/api/evidence/status" })).json()).toMatchObject({ sourceState: "RECORDED_SNAPSHOT", reasonCode: "recorded_snapshot_selected" });
      } finally { await recordedApp.close(); }
    } finally {
      await liveApp.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("does not serve a live audit or report through an escaped audit-directory symlink", async () => {
    const directory = path.join(root, ".test-tmp", `api-audit-confinement-${crypto.randomUUID()}`);
    const projectRoot = path.join(directory, "project");
    const outsideDirectory = path.join(directory, "outside");
    const eventLogPath = path.join(directory, "runtime-events.jsonl");
    const configPath = path.join(directory, "toolbastion.config.json");
    await mkdir(projectRoot, { recursive: true });
    await mkdir(outsideDirectory, { recursive: true });
    await writeFile(path.join(outsideDirectory, "live-session-1.jsonl"), "outside-only-secret\n", "utf8");
    await symlink(outsideDirectory, path.join(projectRoot, "linked-audit"), process.platform === "win32" ? "junction" : "dir");
    await writeFile(configPath, JSON.stringify({
      version: 1,
      mode: "shadow",
      project_root: projectRoot,
      target: { name: "live-target", command: process.execPath, args: [], env_allowlist: [] },
      audit: { directory: "linked-audit" }
    }), "utf8");
    await writeFile(eventLogPath, `${JSON.stringify(runtimeEvent("audit-live-1", "session_started"))}\n${JSON.stringify(runtimeEvent("audit-live-2", "target_connected"))}\n`, "utf8");
    const liveApp = await createApi({ rootDir: root, configPath, eventLogPath });
    try {
      await liveApp.ready();
      for (const url of ["/api/sessions/live-session-1/audit", "/api/sessions/live-session-1/report?format=json"]) {
        const response = await liveApp.inject({ method: "GET", url });
        expect(response.statusCode).toBe(409);
        expect(response.body).not.toContain("outside-only-secret");
      }
    } finally {
      await liveApp.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("reads the trust baseline from the configured project root", async () => {
    const directory = path.join(root, ".test-tmp", `api-trust-root-${crypto.randomUUID()}`);
    const projectRoot = path.join(directory, "project");
    const configPath = path.join(directory, "toolbastion.config.json");
    await mkdir(projectRoot, { recursive: true });
    await writeTrustBaseline(path.join(projectRoot, ".toolbastion", "toolbastion.lock.json"), createTrustBaseline("configured-target", []));
    await writeFile(configPath, JSON.stringify({
      version: 1,
      mode: "shadow",
      project_root: projectRoot,
      target: { name: "configured-target", command: process.execPath, args: [], env_allowlist: [] }
    }), "utf8");
    const configuredApp = await createApi({ rootDir: root, configPath });
    try {
      await configuredApp.ready();
      const response = await configuredApp.inject({ method: "GET", url: "/api/trust" });
      expect(response.statusCode).toBe(200);
      expect(response.json<{ targetName: string }>().targetName).toBe("configured-target");
    } finally {
      await configuredApp.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
});
