import path from "node:path";
import { expect, test } from "@playwright/test";
import { createApi } from "../../apps/api/src/index.js";

const root = path.resolve(".");
const port = 4784;
let app: Awaited<ReturnType<typeof createApi>>;
test.beforeAll(async () => {
  app = await createApi({ rootDir: root, configPath: path.join(root, "toolbastion.config.example.yaml"), eventLogPath: path.join(root, ".test-tmp", "missing-runtime-events.jsonl"), dashboardRoot: path.join(root, "apps", "dashboard", "dist") });
  await app.listen({ host: "127.0.0.1", port });
});
test.afterAll(async () => app.close());

test("landing page opens the console, where routes, Attack Lab, and report download work", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Make every MCP action earn execution." })).toBeVisible();
  await expect(page.getByText("A target can only receive a call after the gateway produces an allow decision.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Audit evidence, not security theater." })).toBeVisible();
  await page.getByRole("button", { name: "Open security console" }).click();
  await expect(page.getByRole("heading", { name: "Runtime overview" })).toBeVisible();
  for (const [label, target] of [["Overview", "overview"], ["Session timeline", "timeline"], ["Attack Lab", "attack-lab"], ["Policy", "policy"], ["Reports", "reports"]] as const) {
    const link = page.getByRole("link", { name: label, exact: true });
    await expect(link).toHaveAttribute("href", `#${target}`);
    await link.click();
    await expect(page.locator(`#${target}`)).toBeAttached();
  }
  const traversal = page.getByRole("button", { name: /Path traversal/ });
  await expect(traversal).toContainText("Expected: BLOCK");
  await traversal.click();
  await expect(page.getByText("ACTUAL RESULT")).toBeVisible();
  await expect(page.locator(".lab-result")).toContainText("BLOCK");
  await expect(page.locator(".lab-result")).toContainText("matched");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: /Markdown report/ }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/toolbastion-.*\.md/);
});

test("landing navigation leads to the decision receipt", async ({ page }) => {
  await page.goto("/");
  const boundaryLink = page.getByRole("link", { name: "The boundary", exact: true });
  await expect(boundaryLink).toHaveAttribute("href", "#boundary");
  await boundaryLink.click();
  await expect(page).toHaveURL(/#boundary$/);
  await expect(page.getByRole("heading", { name: "Audit evidence, not security theater." })).toBeVisible();
  await expect(page.locator(".receipt-step")).toHaveCount(3);
  await expect(page.locator(".decision-step")).toContainText("BLOCKED");
});

test("static dashboard fallback requires an explicit user choice", async ({ page }) => {
  await page.route("**/api/**", (route) => route.abort());
  await page.goto("/");
  await page.getByRole("button", { name: "Open security console" }).click();
  await expect(page.getByRole("heading", { name: "Live runtime unavailable" })).toBeVisible();
  await page.getByRole("button", { name: "Open verified recorded snapshot" }).click();
  await expect(page.getByText("READ-ONLY SNAPSHOT")).toBeVisible();
  await expect(page.getByText("Read-only recorded security session")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recorded scenario explorer" })).toBeVisible();
});
