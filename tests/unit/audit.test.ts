import { readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLog, verifyAuditFile } from "@mcp-warden/audit";

const files: string[] = [];
afterEach(async () => { for (const file of files.splice(0)) await writeFile(file, "", "utf8").catch(() => undefined); });

async function fixture() {
  const directory = path.join(os.tmpdir(), `warden-audit-${crypto.randomUUID()}`);
  const log = new AuditLog(directory, "test-session");
  await log.append("request", { tool: "read_file", authorization: "Bearer should-never-appear" });
  await log.append("decision", { decision: "ALLOW" });
  await log.append("result", { apiKey: "should-never-appear" });
  await log.close();
  files.push(log.filePath);
  return log.filePath;
}

describe("tamper-evident audit log", () => {
  it("writes a valid hash chain without raw secrets", async () => {
    const file = await fixture();
    expect(await verifyAuditFile(file)).toEqual({ valid: true, eventCount: 3, errors: [] });
    const raw = await readFile(file, "utf8");
    expect(raw).not.toContain("should-never-appear");
    expect(raw).toContain("[REDACTED:sensitive-field]");
  });

  it("detects edited, deleted, and reordered events", async () => {
    const file = await fixture();
    const lines = (await readFile(file, "utf8")).trim().split("\n");
    await writeFile(file, `${lines[0]}\n${lines[2]}\n`, "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
    await writeFile(file, `${lines[1]}\n${lines[0]}\n${lines[2]}\n`, "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
    await writeFile(file, `${lines.join("\n").replace("ALLOW", "BLOCK")}\n`, "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
  });
});
