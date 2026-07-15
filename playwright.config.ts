import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? "github" : "line",
  outputDir: "output/playwright/test-results",
  use: {
    baseURL: "http://127.0.0.1:4782",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ...(!process.env.CI ? { channel: "chrome" as const } : {})
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }]
});
