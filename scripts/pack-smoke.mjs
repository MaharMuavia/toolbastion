/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
import { execFile, spawn } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const run = (command, args, options = {}) => exec(command, args, { ...options, shell: process.platform === "win32" && command.toLowerCase().endsWith("npm.cmd") });
const root = process.cwd();
const temporary = await mkdtemp(path.join(os.tmpdir(), "toolbastion-pack-smoke-"));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
let dashboard;

try {
  const npmEnvironment = { ...process.env, npm_config_cache: path.join(temporary, "npm-cache") };
  const packed = JSON.parse((await run(npm, ["pack", "--json", "--ignore-scripts", "--pack-destination", temporary], { cwd: root, env: npmEnvironment, maxBuffer: 2 * 1024 * 1024 })).stdout);
  const archive = path.join(temporary, packed[0].filename);
  const installRoot = path.join(temporary, "install");
  await mkdir(installRoot, { recursive: true });
  await run(npm, ["install", "--prefix", installRoot, "--ignore-scripts", "--no-audit", "--no-fund", archive], { cwd: root, env: npmEnvironment, maxBuffer: 4 * 1024 * 1024 });
  const bin = path.join(installRoot, "node_modules", "toolbastion", "dist", "standalone", "index.js");
  const command = async (...args) => run(process.execPath, [bin, ...args], { cwd: installRoot, env: { ...process.env, OPENAI_API_KEY: undefined }, maxBuffer: 4 * 1024 * 1024 });
  const version = await command("--version");
  if (version.stdout.trim() !== "0.1.4") throw new Error(`Unexpected packaged version: ${version.stdout}`);
  const initPath = path.join(installRoot, "smoke.config.yaml");
  await command("init", "--output", initPath);
  await command("policy", "validate", "--config", initPath);
  await command("doctor", "--config", initPath);

  const port = 49000 + Math.floor(Math.random() * 500);
  dashboard = spawn(process.execPath, [bin, "dashboard", "--port", String(port)], { cwd: installRoot, env: { ...process.env, TOOLBASTION_API_HOST: "127.0.0.1" }, stdio: ["ignore", "pipe", "pipe"], shell: false, windowsHide: true });
  const deadline = Date.now() + 15_000;
  let healthy = false;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/health`);
      if (response.ok) { healthy = true; break; }
    } catch { /* server is still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!healthy) throw new Error("Packaged dashboard did not become healthy on localhost");
  process.stdout.write(`PACK SMOKE PASS version=${version.stdout.trim()} dashboard=http://127.0.0.1:${port}\n`);
} finally {
  dashboard?.kill();
  await rm(temporary, { recursive: true, force: true });
}
