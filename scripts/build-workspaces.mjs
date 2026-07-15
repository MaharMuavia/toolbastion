import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const workspaces = [
  { directory: "packages/shared", declarations: true },
  { directory: "packages/detectors", declarations: true },
  { directory: "packages/policy", declarations: true },
  { directory: "packages/judge", declarations: true },
  { directory: "packages/core", declarations: true },
  { directory: "examples/benign-server", declarations: false },
  { directory: "examples/vulnerable-server", declarations: false },
  { directory: "apps/api", declarations: true },
  { directory: "apps/cli", declarations: true }
];
const tsupCli = path.join(root, "node_modules", "tsup", "dist", "cli-default.js");

for (const workspace of workspaces) {
  const cwd = path.join(root, workspace.directory);
  const entry = path.join(cwd, "src", "index.ts");
  const args = [tsupCli, entry, "--format", "esm", "--clean"];
  if (workspace.declarations) args.push("--dts");
  const result = spawnSync(process.execPath, args, {
    cwd,
    env: { ...process.env, INIT_CWD: cwd },
    shell: false,
    stdio: "inherit"
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const dashboard = path.join(root, "apps", "dashboard");
const viteCli = path.join(dashboard, "node_modules", "vite", "bin", "vite.js");
const dashboardResult = spawnSync(process.execPath, [viteCli, "build"], { cwd: dashboard, env: { ...process.env, INIT_CWD: dashboard }, shell: false, stdio: "inherit" });
if (dashboardResult.status !== 0) process.exit(dashboardResult.status ?? 1);
