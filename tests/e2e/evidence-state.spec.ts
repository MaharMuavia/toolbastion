import { mkdir, rm, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { createApi } from "../../apps/api/src/index.js";

const root = path.resolve(".");
const port = 4783;

function runtimeEvent(eventId: string, eventType: string) {
  return {
    schemaVersion: 1,
    eventId,
    sessionId: "browser-evidence-session",
    timestamp: new Date().toISOString(),
    eventType,
    decisionSource: "deterministic",
    riskLevel: "none",
    inputTokens: 0,
    outputTokens: 0,
    judgeLatencyMs: 0,
    cacheHit: false,
    reasonCodes: [],
    evidenceState: "AVAILABLE"
  };
}

async function openConsole(page: Page): Promise<void> {
  await page.goto(`http://127.0.0.1:${port}/`);
  await page.getByRole("button", { name: "Open security console" }).click();
  await expect(page.getByRole("heading", { name: "Runtime overview" })).toBeVisible();
}

test("browser labels healthy, stale, invalid, closed, and recorded evidence states", async ({ page }) => {
  const directory = path.join(root, ".test-tmp", `e2e-evidence-${crypto.randomUUID()}`);
  const file = path.join(directory, "runtime-events.jsonl");
  await mkdir(directory, { recursive: true });
  const lifecycle = [runtimeEvent("start", "session_started"), runtimeEvent("connected", "target_connected")];
  await writeFile(file, `${lifecycle.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
  let app = await createApi({ rootDir: root, configPath: path.join(root, "toolbastion.config.example.yaml"), eventLogPath: file, dashboardRoot: path.join(root, "apps", "dashboard", "dist") });
  try {
    await app.listen({ host: "127.0.0.1", port });
    await openConsole(page);
    await expect(page.getByText("NOT LIVE EVIDENCE")).toHaveCount(0);

    await utimes(file, new Date(Date.now() - 20_000), new Date(Date.now() - 20_000));
    await page.reload();
    await expect(page.getByText("NOT LIVE EVIDENCE")).toBeVisible();
    await expect(page.getByText(/LIVE STALE/)).toBeVisible();

    await writeFile(file, "{malformed}\n", "utf8");
    await page.reload();
    await expect(page.getByText(/LIVE INVALID/)).toBeVisible();

    await writeFile(file, `${[...lifecycle, runtimeEvent("closed", "target_closed")].map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
    await page.reload();
    await expect(page.getByText(/LIVE CLOSED/)).toBeVisible();

    await app.close();
    app = await createApi({ rootDir: root, dashboardRoot: path.join(root, "apps", "dashboard", "dist") });
    await app.listen({ host: "127.0.0.1", port });
    await openConsole(page);
    await expect(page.getByText("NOT LIVE EVIDENCE")).toBeVisible();
    await expect(page.getByText(/RECORDED SNAPSHOT/)).toBeVisible();
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});
