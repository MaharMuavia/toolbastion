import path from "node:path";
import { describe, expect, it } from "vitest";
import { WardenTargetClient } from "@mcp-warden/core";

function processExists(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch { return false; }
}

describe("child process lifecycle", () => {
  it("terminates the target process when the transport closes", async () => {
    const client = new WardenTargetClient({ name: "cleanup-fixture", command: process.execPath, args: [path.resolve("examples/vulnerable-server/dist/index.js")], cwd: path.resolve("."), envAllowlist: [] });
    await client.connect();
    const result = await client.callTool("get_process_id", {});
    const content = result.content as Array<{ type: string; text: string }>;
    const pid = Number(content[0]?.text);
    expect(processExists(pid)).toBe(true);
    await client.close();
    await expect.poll(() => processExists(pid), { timeout: 5_000 }).toBe(false);
  });

  it("reports target startup failure without hanging", async () => {
    const client = new WardenTargetClient({ name: "missing-target", command: "warden-command-that-does-not-exist", args: [], envAllowlist: [] });
    await expect(client.connect()).rejects.toThrow();
    await expect(client.close()).resolves.toBeUndefined();
  });
});
