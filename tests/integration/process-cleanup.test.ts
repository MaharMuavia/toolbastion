import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ToolBastionTargetClient } from "@toolbastion/core";

function processExists(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch { return false; }
}

async function waitForProof(filePath: string): Promise<{ childPid: number; grandchildPid: number }> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      const parsed = JSON.parse(await readFile(filePath, "utf8")) as { childPid?: unknown; grandchildPid?: unknown };
      if (typeof parsed.childPid === "number" && typeof parsed.grandchildPid === "number") return { childPid: parsed.childPid, grandchildPid: parsed.grandchildPid };
    } catch {
      // The controlled child has not written its proof record yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("Controlled child process did not write its PID proof record");
}

describe("child process lifecycle", () => {
  it("terminates the target process when the transport closes", async () => {
    const client = new ToolBastionTargetClient({ name: "cleanup-fixture", command: process.execPath, args: [path.resolve("examples/vulnerable-server/dist/index.js")], cwd: path.resolve("."), envAllowlist: [] });
    await client.connect();
    const result = await client.callTool("get_process_id", {});
    const content = result.content as Array<{ type: string; text: string }>;
    const pid = Number(content[0]?.text);
    expect(processExists(pid)).toBe(true);
    await client.close();
    await expect.poll(() => processExists(pid), { timeout: 5_000 }).toBe(false);
  });

  it("reports target startup failure without hanging", async () => {
    const client = new ToolBastionTargetClient({ name: "missing-target", command: "toolbastion-command-that-does-not-exist", args: [], envAllowlist: [] });
    await expect(client.connect()).rejects.toThrow();
    await expect(client.close()).resolves.toBeUndefined();
  });

  it("terminates a timed-out target together with its child and grandchild before restarting", async () => {
    const directory = path.resolve(".test-tmp", `process-tree-${crypto.randomUUID()}`);
    const proofFile = path.join(directory, "pids.json");
    await mkdir(directory, { recursive: true });
    const client = new ToolBastionTargetClient({
      name: "process-tree-fixture",
      command: process.execPath,
      args: [path.resolve("examples/vulnerable-server/dist/index.js"), "--process-tree-proof-file", proofFile],
      cwd: path.resolve("."),
      envAllowlist: []
    }, () => undefined, () => Promise.resolve(), 150);
    try {
      await client.connect();
      const result = client.callTool("slow_child_tree", {});
      const proof = await waitForProof(proofFile);
      await expect(result).rejects.toMatchObject({ confirmedTermination: true });
      await expect.poll(() => processExists(proof.childPid), { timeout: 5_000 }).toBe(false);
      await expect.poll(() => processExists(proof.grandchildPid), { timeout: 5_000 }).toBe(false);
    } finally {
      await client.close().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  }, 15_000);
});
