import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApi } from "../../apps/api/src/index.js";

const root = path.resolve(".");
const app = await createApi({ rootDir: root, configPath: path.join(root, "warden.config.example.yaml"), dashboardRoot: path.join(root, "apps", "dashboard", "dist") });

beforeAll(async () => app.ready());
afterAll(async () => app.close());

describe("dashboard API", () => {
  it("serves health and a completed fixture session", async () => {
    expect((await app.inject({ method: "GET", url: "/api/health" })).json()).toEqual({ status: "ok" });
    const response = await app.inject({ method: "GET", url: "/api/sessions/offline-day3-demo" });
    expect(response.statusCode).toBe(200);
    const body = response.json<{ label: string; metrics: { blocks: number } }>();
    expect(body.label).toBe("OFFLINE FIXTURE REPLAY");
    expect(body.metrics.blocks).toBe(2);
  });

  it("serves the production dashboard from the localhost API", async () => {
    const response = await app.inject({ method: "GET", url: "/" });
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain("MCP Warden Security Console");
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
});
