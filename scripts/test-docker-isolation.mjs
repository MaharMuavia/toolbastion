import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const docker = spawnSync("docker", ["build", "-q", "-f", "examples/vulnerable-server/Dockerfile.isolated", "."], {
  cwd: root,
  encoding: "utf8",
  shell: false,
  stdio: ["ignore", "pipe", "inherit"],
  windowsHide: true
});

if (docker.error !== undefined) throw new Error(`Docker build could not start: ${docker.error.message}`);
if (docker.status !== 0) process.exit(docker.status ?? 1);

const image = docker.stdout.trim();
if (image.length === 0) throw new Error("Docker build did not return an image ID");

const vitest = path.join(root, "node_modules", "vitest", "vitest.mjs");
const test = spawnSync(process.execPath, [vitest, "run", "tests/integration/docker-isolation.test.ts"], {
  cwd: root,
  env: { ...process.env, TOOLBASTION_DOCKER_TEST_IMAGE: image },
  shell: false,
  stdio: "inherit",
  windowsHide: true
});

if (test.error !== undefined) throw new Error(`Docker isolation test could not start: ${test.error.message}`);
process.exitCode = test.status ?? 1;
