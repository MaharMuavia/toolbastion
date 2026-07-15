import path from "node:path";
import { expect, test } from "@playwright/test";
import { createApi } from "../../apps/api/src/index.js";

const root = path.resolve(".");
let app: Awaited<ReturnType<typeof createApi>>;
test.beforeAll(async () => {
  app = await createApi({ rootDir: root, configPath: path.join(root, "toolbastion.config.example.yaml"), eventLogPath: path.join(root, ".test-tmp", "missing-runtime-events.jsonl"), dashboardRoot: path.join(root, "apps", "dashboard", "dist") });
  await app.listen({ host: "127.0.0.1", port: 4782 });
});
test.afterAll(async () => app.close());

test("critical dashboard routes, Attack Lab, and report download work", async ({ page }) => {
  await page.goto("/");
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

test("static dashboard fallback is clearly read-only", async ({ page }) => {
  await page.route("**/api/**", (route) => route.abort());
  await page.goto("/");
  await expect(page.getByText("READ-ONLY SNAPSHOT")).toBeVisible();
  await expect(page.getByText("Read-only recorded security session")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recorded scenario explorer" })).toBeVisible();
});
