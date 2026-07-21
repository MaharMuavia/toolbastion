import { access, constants, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterEach, describe, expect, it } from "vitest";
import { ToolBastionTargetClient } from "@toolbastion/core";
import { createTrustBaseline, writeTrustBaseline } from "@toolbastion/policy";
import type { CapabilityContract } from "@toolbastion/shared";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
let transport: StdioClientTransport | undefined;
const auditFailureStages: Array<[label: string, failedEvent: string, expectedExecution: boolean]> = [
  ["call received", "tool_call_received", false],
  ["authorization completed", "authorization_completed", false],
  ["dispatch started", "tool_dispatch_started", false],
  ["dispatch completed", "tool_dispatch_completed", true],
  ["output inspected", "output_inspected", true],
  ["call completed", "call_completed", true]
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function isUnknownArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

function responseText(result: unknown): string {
  if (!isRecord(result)) throw new Error("Expected a text MCP response");
  const content = result["content"];
  if (!isUnknownArray(content)) throw new Error("Expected a text MCP response");
  const first = content[0];
  if (!isRecord(first) || typeof first["text"] !== "string") throw new Error("Expected a text MCP response");
  return first["text"];
}

const noCapability: CapabilityContract = { filesystem: "none", network: "none", command_exec: false, subprocess: false, destructive: false };
function capabilitiesFor(tools: Array<{ name: string }>, overrides: Record<string, CapabilityContract> = {}): Record<string, CapabilityContract> {
  return Object.fromEntries(tools.map((tool) => [tool.name, overrides[tool.name] ?? noCapability]));
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

const proxyRunner = `
  import { readFile } from "node:fs/promises";
  import path from "node:path";
  import { AuditLog } from "@toolbastion/audit";
  import { ToolBastionProxy } from "@toolbastion/core";
  import { toolbastionConfigSchema } from "@toolbastion/shared";
  const config = toolbastionConfigSchema.parse(JSON.parse(await readFile(process.env.TOOLBASTION_TEST_CONFIG, "utf8")));
  const audit = new AuditLog(path.resolve(config.project_root, config.audit.directory), undefined, {
    retainRawContent: false,
    failWriteForEvent: (eventType) => eventType === process.env.TOOLBASTION_TEST_AUDIT_FAIL_EVENT
  });
  const proxy = new ToolBastionProxy(config, () => undefined, { audit });
  process.stdin.once("end", () => { void proxy.close().catch(() => undefined); });
  await proxy.runStdio();
`;

afterEach(async () => {
  await transport?.close();
  transport = undefined;
});

describe("audit persistence failure", () => {
  it("does not release a completed target result and closes future calls in enforce mode", async () => {
    const projectRoot = path.join(root, ".test-tmp", `audit-failure-${crypto.randomUUID()}`);
    const configPath = path.join(projectRoot, "toolbastion.config.json");
    const target = {
      name: "benign-demo",
      command: process.execPath,
      args: [path.join(root, "examples", "benign-server", "dist", "index.js")],
      cwd: root,
      envAllowlist: []
    };
    await mkdir(projectRoot, { recursive: true });
    const discovery = new ToolBastionTargetClient(target);
    await discovery.connect();
    try {
      const tools = (await discovery.listTools()).tools;
      const capabilities = capabilitiesFor(tools, { echo: { ...noCapability } });
      await writeTrustBaseline(path.join(projectRoot, ".toolbastion", "toolbastion.lock.json"), createTrustBaseline(target.name, tools, capabilities));
      await writeFile(configPath, JSON.stringify({
        version: 1,
        mode: "enforce",
        project_root: projectRoot,
        target: { name: target.name, command: target.command, args: target.args, cwd: target.cwd, env_allowlist: [] },
        paths: { allow: ["./**"], deny: ["**/.env", "**/.ssh/**", "**/.aws/**"] },
        network: { default: "deny", allow_domains: ["api.github.com"] },
        judge: { enabled: false, mode: "offline" },
        tools: { default: "judge", rules: { echo: { base_risk: "low", action: "allow" } } },
        capabilities: { tools: capabilities }
      }), "utf8");
    } finally {
      await discovery.close();
    }
    transport = new StdioClientTransport({
      command: process.execPath,
      args: ["--input-type=module", "--eval", proxyRunner],
      cwd: root,
      env: { ...process.env, TOOLBASTION_TEST_CONFIG: configPath, TOOLBASTION_TEST_AUDIT_FAIL_EVENT: "output_inspected" },
      stderr: "pipe"
    });
    try {
      const client = new Client({ name: "audit-failure-test", version: "0.1.0" });
      await client.connect(transport);
      const executedButUnreleased = await client.callTool({ name: "echo", arguments: { text: "target-executed-but-not-released" } });
      expect(executedButUnreleased.isError).toBe(true);
      const unavailableAfterExecution = responseText(executedButUnreleased);
      expect(unavailableAfterExecution).toContain('"authorizationDecision":"ALLOW"');
      expect(unavailableAfterExecution).toContain('"executionState":"COMPLETED"');
      expect(unavailableAfterExecution).toContain('"outputDecision":"NOT_RELEASED"');
      expect(unavailableAfterExecution).not.toContain("target-executed-but-not-released");

      const blockedAfterFailure = await client.callTool({ name: "echo", arguments: { text: "must-not-dispatch" } });
      expect(blockedAfterFailure.isError).toBe(true);
      const unavailableBeforeExecution = responseText(blockedAfterFailure);
      expect(unavailableBeforeExecution).toContain("audit_unavailable_before_execution");
      expect(unavailableBeforeExecution).not.toContain("must-not-dispatch");
    } finally {
      await transport.close();
      await rm(projectRoot, { recursive: true, force: true });
    }
  }, 20_000);

  it.each(auditFailureStages)("fails closed at %s and reports target execution truthfully", async (_label, failedEvent, expectedExecution) => {
    const projectRoot = path.join(root, ".test-tmp", `audit-failure-stage-${crypto.randomUUID()}`);
    const configPath = path.join(projectRoot, "toolbastion.config.json");
    const proofFile = path.join(projectRoot, "target-executed");
    const target = {
      name: "vulnerable-demo",
      command: process.execPath,
      args: [
        path.join(root, "examples", "vulnerable-server", "dist", "index.js"),
        "--demo-project-root", projectRoot,
        "--execution-proof-file", proofFile
      ],
      cwd: root,
      envAllowlist: []
    };
    await mkdir(path.join(projectRoot, "src"), { recursive: true });
    await writeFile(path.join(projectRoot, "src", "safe.ts"), "export const safe = true;\n", "utf8");
    const discovery = new ToolBastionTargetClient(target);
    await discovery.connect();
    try {
      const tools = (await discovery.listTools()).tools;
      const capabilities = capabilitiesFor(tools, { read_project_file: { ...noCapability, filesystem: "read" } });
      await writeTrustBaseline(path.join(projectRoot, ".toolbastion", "toolbastion.lock.json"), createTrustBaseline(target.name, tools, capabilities));
      await writeFile(configPath, JSON.stringify({
        version: 1,
        mode: "enforce",
        project_root: projectRoot,
        target: { name: target.name, command: target.command, args: target.args, cwd: target.cwd, env_allowlist: [] },
        paths: { allow: ["./src/**"], deny: ["**/.env", "**/.ssh/**", "**/.aws/**"] },
        network: { default: "deny", allow_domains: ["api.github.com"] },
        judge: { enabled: false, mode: "offline" },
        tools: { default: "judge", rules: { read_project_file: { base_risk: "low", action: "allow_when_in_scope" } } },
        capabilities: { tools: capabilities }
      }), "utf8");
    } finally {
      await discovery.close();
    }
    transport = new StdioClientTransport({
      command: process.execPath,
      args: ["--input-type=module", "--eval", proxyRunner],
      cwd: root,
      env: { ...process.env, TOOLBASTION_TEST_CONFIG: configPath, TOOLBASTION_TEST_AUDIT_FAIL_EVENT: failedEvent },
      stderr: "pipe"
    });
    try {
      const client = new Client({ name: "audit-failure-stage-test", version: "0.1.0" });
      await client.connect(transport);
      const result = await client.callTool({ name: "read_project_file", arguments: { path: "src/safe.ts" } });
      expect(result.isError).toBe(true);
      const response = responseText(result);
      expect(response).toContain(expectedExecution || failedEvent !== "tool_call_received" ? '"authorizationDecision":"ALLOW"' : '"authorizationDecision":"BLOCK_BEFORE_EXECUTION"');
      expect(response).toContain(expectedExecution ? '"executionState":"COMPLETED"' : '"executionState":"NOT_DISPATCHED"');
      expect(response).toContain('"outputDecision":"NOT_RELEASED"');
      expect(await fileExists(proofFile)).toBe(expectedExecution);
    } finally {
      await transport.close();
      await rm(projectRoot, { recursive: true, force: true });
    }
  }, 20_000);

  it("rejects enforce-mode startup when the session-start audit event cannot persist", async () => {
    const projectRoot = path.join(root, ".test-tmp", `audit-failure-start-${crypto.randomUUID()}`);
    const configPath = path.join(projectRoot, "toolbastion.config.json");
    await mkdir(projectRoot, { recursive: true });
    await writeFile(configPath, JSON.stringify({
      version: 1,
      mode: "enforce",
      project_root: projectRoot,
      target: { name: "benign-demo", command: process.execPath, args: [path.join(root, "examples", "benign-server", "dist", "index.js")], cwd: root, env_allowlist: [] },
      paths: { allow: ["./**"], deny: ["**/.env", "**/.ssh/**", "**/.aws/**"] },
      network: { default: "deny", allow_domains: ["api.github.com"] },
      judge: { enabled: false, mode: "offline" }
    }), "utf8");
    transport = new StdioClientTransport({
      command: process.execPath,
      args: ["--input-type=module", "--eval", proxyRunner],
      cwd: root,
      env: { ...process.env, TOOLBASTION_TEST_CONFIG: configPath, TOOLBASTION_TEST_AUDIT_FAIL_EVENT: "session_started" },
      stderr: "pipe"
    });
    try {
      const client = new Client({ name: "audit-start-failure-test", version: "0.1.0" });
      await expect(client.connect(transport)).rejects.toThrow();
    } finally {
      await transport.close();
      await rm(projectRoot, { recursive: true, force: true });
    }
  }, 20_000);
});
