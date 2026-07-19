import path from "node:path";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { stringify } from "yaml";
import { afterEach, describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
let transport: StdioClientTransport | undefined;

afterEach(async () => {
  await transport?.close();
});

describe("MCP stdio bridge", () => {
  it("discovers and forwards a safe tool call through ToolBastion", async () => {
    const projectRoot = path.join(root, ".test-tmp", "stdio-forwarding");
    const configPath = path.join(projectRoot, "toolbastion.config.yaml");
    await mkdir(projectRoot, { recursive: true });
    await writeFile(configPath, stringify({
      version: 1,
      mode: "shadow",
      project_root: projectRoot,
      target: { name: "benign-demo", command: process.execPath, args: [path.join(root, "examples", "benign-server", "dist", "index.js")], cwd: root, env_allowlist: [] },
      tools: { default: "judge", rules: { echo: { base_risk: "low", action: "allow" } } }
    }), "utf8");
    transport = new StdioClientTransport({
      command: process.execPath,
      args: [path.join(root, "apps/cli/dist/index.js"), "run", "--config", configPath],
      cwd: root,
      stderr: "pipe"
    });
    try {
      const client = new Client({ name: "toolbastion-integration-test", version: "0.1.0" });
      await client.connect(transport);

      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name)).toContain("echo");

      const result = await client.callTool({ name: "echo", arguments: { text: "safe-through-toolbastion" } });
      expect(result.content).toEqual([{ type: "text", text: "safe-through-toolbastion" }]);
    } finally {
      await transport.close();
      await rm(projectRoot, { recursive: true, force: true });
    }
  }, 15_000);
});
