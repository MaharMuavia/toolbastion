import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const workspaces = [
  "packages/shared",
  "packages/audit",
  "packages/output-firewall",
  "packages/reports",
  "packages/detectors",
  "packages/policy",
  "packages/remediation",
  "packages/judge",
  "packages/core",
  "examples/benign-server",
  "examples/vulnerable-server",
  "apps/api",
  "apps/cli"
];
const tsc = path.join(root, "node_modules", "typescript", "bin", "tsc");

for (const workspace of workspaces) {
  rmSync(path.join(root, workspace, "dist"), { recursive: true, force: true });
  const result = spawnSync(process.execPath, [tsc, "-p", path.join(root, workspace, "tsconfig.json"), "--pretty", "false"], { cwd: root, env: process.env, shell: false, stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("npm_execpath is unavailable; run this build through npm");
const dashboard = spawnSync(process.execPath, [npmCli, "run", "build", "--workspace", "@mcp-warden/dashboard"], { cwd: root, env: process.env, shell: false, stdio: "inherit" });
if (dashboard.status !== 0) process.exit(dashboard.status ?? 1);
