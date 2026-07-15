import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterEach, describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
let transport: StdioClientTransport | undefined;

afterEach(async () => {
  await transport?.close();
});

describe("MCP stdio bridge", () => {
  it("discovers and forwards a safe tool call through Warden", async () => {
    transport = new StdioClientTransport({
      command: process.execPath,
      args: [path.join(root, "apps/cli/dist/index.js"), "run", "--config", path.join(root, "warden.config.example.yaml")],
      cwd: root,
      stderr: "pipe"
    });
    const client = new Client({ name: "warden-integration-test", version: "0.1.0" });
    await client.connect(transport);

    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name)).toContain("echo");

    const result = await client.callTool({ name: "echo", arguments: { text: "safe-through-warden" } });
    expect(result.content).toEqual([{ type: "text", text: "safe-through-warden" }]);
  }, 15_000);
});

