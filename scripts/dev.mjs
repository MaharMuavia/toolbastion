import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const cli = path.join(root, "apps", "cli", "dist", "index.js");
const vite = path.join(root, "apps", "dashboard", "node_modules", "vite", "bin", "vite.js");
const config = path.resolve(root, process.env.TOOLBASTION_DEV_CONFIG ?? "toolbastion.config.example.yaml");
/** @type {import("node:child_process").ChildProcess[]} */
const services = [];
let stopping = false;

/**
 * @param {string} command
 * @param {string[]} args
 * @param {import("node:child_process").StdioOptions} [stdio]
 * @param {string} [cwd]
 * @returns {import("node:child_process").ChildProcess}
 */
function run(command, args, stdio = "inherit", cwd = root) {
  return spawn(command, args, { cwd, env: process.env, shell: false, stdio, windowsHide: true });
}

/** @param {import("node:child_process").ChildProcess} child @returns {Promise<void>} */
function waitForExit(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("exit", () => resolve());
    child.once("error", () => resolve());
  });
}

/** @param {number} exitCode @returns {Promise<void>} */
async function stop(exitCode) {
  if (stopping) return;
  stopping = true;
  for (const service of services) {
    if (service.exitCode === null && service.signalCode === null) service.kill();
  }
  await Promise.race([
    Promise.all(services.map(waitForExit)),
    new Promise((resolve) => setTimeout(resolve, 5_000))
  ]);
  process.exitCode = exitCode;
}

/** @param {import("node:child_process").ChildProcess} child @returns {Promise<number>} */
function waitForCode(child) {
  return new Promise((resolve) => {
    child.once("error", () => resolve(1));
    child.once("exit", (exitCode) => resolve(exitCode ?? 1));
  });
}

/** @returns {Promise<void>} */
async function build() {
  const child = run(process.execPath, [path.join(root, "scripts", "build-workspaces.mjs")]);
  const code = await waitForCode(child);
  if (code !== 0) throw new Error("Initial build failed");
}

/**
 * @param {string} label
 * @param {string} command
 * @param {string[]} args
 * @param {string} cwd
 * @returns {import("node:child_process").ChildProcess}
 */
function startService(label, command, args, cwd) {
  const service = run(command, args, "inherit", cwd);
  services.push(service);
  service.once("error", (error) => {
    process.stderr.write(`ToolBastion ${label} failed to start: ${error.message}\n`);
    void stop(1);
  });
  service.once("exit", (code, signal) => {
    if (!stopping) {
      process.stderr.write(`ToolBastion ${label} stopped unexpectedly (${signal ?? code ?? "unknown"})\n`);
      void stop(1);
    }
  });
  return service;
}

await build();

startService("API", process.execPath, [cli, "dashboard", "--config", config, "--port", "4782"], root);
startService("frontend", process.execPath, [vite, "--host", "127.0.0.1", "--port", "5173", "--strictPort"], path.join(root, "apps", "dashboard"));

process.stderr.write("ToolBastion development stack is ready: frontend http://127.0.0.1:5173, API http://127.0.0.1:4782\n");
process.stderr.write("Run `npm run dev:proxy` separately when an MCP client is ready to connect. Press Ctrl+C to stop the web stack.\n");

process.once("SIGINT", () => { void stop(0); });
process.once("SIGTERM", () => { void stop(0); });
