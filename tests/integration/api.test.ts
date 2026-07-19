import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApi, startApi } from "../../apps/api/src/index.js";
import { createTrustBaseline, writeTrustBaseline } from "@toolbastion/policy";

const root = path.resolve(".");
const app = await createApi({ rootDir: root, configPath: path.join(root, "toolbastion.config.example.yaml"), eventLogPath: path.join(root, ".test-tmp", "missing-runtime-events.jsonl"), dashboardRoot: path.join(root, "apps", "dashboard", "dist") });

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
    const protectedApp = await createApi({ rootDir: root, accessToken: token });
    try {
      await protectedApp.ready();
      expect((await protectedApp.inject({ method: "GET", url: "/api/health" })).statusCode).toBe(200);
      expect((await protectedApp.inject({ method: "GET", url: "/api/sessions" })).statusCode).toBe(401);
      expect((await protectedApp.inject({ method: "GET", url: "/api/sessions", headers: { authorization: `Bearer ${token}` } })).statusCode).toBe(200);
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

  it("switches to a redacted live lifecycle session when a runtime log is present", async () => {
    const directory = path.join(root, ".test-tmp", "api-live-events");
    const eventLogPath = path.join(directory, "runtime-events.jsonl");
    await mkdir(directory, { recursive: true });
    const timestamp = new Date().toISOString();
    const lifecycle = [
      { eventId: "live-1", timestamp, eventType: "session_started", payload: { sessionId: "live-session-1" } },
      { eventId: "live-2", timestamp, eventType: "target_connected", payload: { targetName: "live-target" } },
      { eventId: "live-3", timestamp, eventType: "call_blocked", payload: { toolName: "read_file", reason: "deterministic_block", riskLevel: "critical" } }
    ];
    await writeFile(eventLogPath, `${lifecycle.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
    const liveApp = await createApi({ rootDir: root, configPath: path.join(root, "toolbastion.config.example.yaml"), eventLogPath });
    try {
      await liveApp.ready();
      const sessions = (await liveApp.inject({ method: "GET", url: "/api/sessions" })).json<Array<{ sessionId: string; label: string }>>();
      expect(sessions[0]).toMatchObject({ sessionId: "live-session-1", label: "LIVE LOCAL SESSION" });
      const detail = (await liveApp.inject({ method: "GET", url: "/api/sessions/live-session-1" })).json<{ targetName: string; metrics: { blocks: number } }>();
      expect(detail.targetName).toBe("live-target");
      expect(detail.metrics.blocks).toBe(1);
      const closed = [...lifecycle, { eventId: "live-4", timestamp: new Date().toISOString(), eventType: "target_closed", payload: { targetName: "live-target" } }];
      await writeFile(eventLogPath, `${closed.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
      const fallback = (await liveApp.inject({ method: "GET", url: "/api/sessions" })).json<Array<{ label: string }>>();
      expect(fallback[0]?.label).toBe("OFFLINE FIXTURE REPLAY");
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
    const timestamp = new Date().toISOString();
    await writeFile(eventLogPath, `${JSON.stringify({ eventId: "audit-live-1", timestamp, eventType: "session_started", payload: { sessionId: "live-session-1" } })}\n${JSON.stringify({ eventId: "audit-live-2", timestamp, eventType: "target_connected", payload: { targetName: "live-target" } })}\n`, "utf8");
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
