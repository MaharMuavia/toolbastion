import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLog, resolveAuditReadFile, signReceipt, verifyAndReadAuditFile, verifyAuditFile, verifyReceipt } from "@toolbastion/audit";
import { sha256 } from "@toolbastion/shared";

const files: string[] = [];
afterEach(async () => { for (const file of files.splice(0)) await rm(path.dirname(file), { recursive: true, force: true }).catch(() => undefined); });

async function fixture() {
  const directory = path.join(os.tmpdir(), `toolbastion-audit-${crypto.randomUUID()}`);
  const log = new AuditLog(directory, "test-session");
  await log.append("request", { tool: "read_file", authorization: "Bearer should-never-appear" });
  await log.append("request", { payload: "DATABASE_URL=postgres://should-never-appear" });
  await log.append("request", {
    args: { path: "opaque-argument-sentinel", connectionString: "postgresql://user:password@db.example.test/private" },
    nested: { arguments: { token: "nested-opaque-argument-sentinel" } },
    endpoint: "postgresql://user:password@db.example.test/private"
  });
  await log.append("decision", { decision: "ALLOW" });
  await log.append("result", { apiKey: "should-never-appear" });
  await log.close();
  files.push(log.filePath);
  return log.filePath;
}

describe("tamper-evident audit log", () => {
  it("signs and independently verifies complete Ed25519 call receipts", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const receipt = signReceipt({
      version: 1, sessionId: "session", callId: "call", toolName: "read_file",
      toolManifestHash: sha256({ tools: [] }), schemaHash: sha256({}), policyHash: sha256({ mode: "enforce" }), argsHash: sha256({ path: "src/index.ts" }),
      authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "PASS",
      startedAt: "2026-07-20T00:00:00.000Z", completedAt: "2026-07-20T00:00:01.000Z"
    }, privateKeyPem);
    expect(verifyReceipt(receipt)).toEqual({ valid: true, errors: [] });
    expect(verifyReceipt({ ...receipt, toolName: "write_file" }).valid).toBe(false);
  });

  it("writes a valid hash chain without raw secrets", async () => {
    const file = await fixture();
    expect(await verifyAuditFile(file)).toEqual({ valid: true, eventCount: 7, errors: [] });
    const raw = await readFile(file, "utf8");
    expect(raw).not.toContain("should-never-appear");
    expect(raw).not.toContain("opaque-argument-sentinel");
    expect(raw).not.toContain("postgresql://user:password@db.example.test/private");
    expect(raw).toContain("argsHash");
    expect(raw).toContain("argumentsHash");
    expect(raw).toContain("[REDACTED:sensitive-field]");
  });

  it("rejects empty, unsealed, edited, reordered, and extra-field audit content", async () => {
    const file = await fixture();
    const lines = (await readFile(file, "utf8")).trim().split("\n");
    await writeFile(file, "", "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
    await writeFile(file, `${lines.slice(0, -1).join("\n")}\n`, "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
    await writeFile(file, `${lines[0]}\n${lines[2]}\n`, "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
    await writeFile(file, `${lines[1]}\n${lines[0]}\n${lines[2]}\n`, "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
    await writeFile(file, `${lines.join("\n").replace("ALLOW", "BLOCK")}\n`, "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
    const extraField = JSON.parse(lines[1]!) as Record<string, unknown>;
    extraField.unhashedAttackerField = "must-not-be-ignored";
    await writeFile(file, `${lines[0]}\n${JSON.stringify(extraField)}\n${lines.slice(2).join("\n")}\n`, "utf8");
    expect((await verifyAuditFile(file)).valid).toBe(false);
  });

  it("rejects a syntactically valid chain with mixed session identities", async () => {
    const file = await fixture();
    const events = (await readFile(file, "utf8")).trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    events[1]!.sessionId = "other-session";
    let previousHash = "GENESIS";
    for (const event of events) {
      event.previousHash = previousHash;
      const unsigned = { ...event };
      delete unsigned.eventHash;
      event.eventHash = sha256(unsigned);
      previousHash = event.eventHash as string;
    }
    const seal = events.at(-1)!;
    (seal.payload as Record<string, unknown>).finalEventHash = events.at(-2)!.eventHash;
    const unsignedSeal = { ...seal };
    delete unsignedSeal.eventHash;
    seal.eventHash = sha256(unsignedSeal);
    await writeFile(file, `${events.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
    const verification = await verifyAuditFile(file);
    expect(verification.valid).toBe(false);
    expect(verification.errors.join(" ")).toContain("session id does not match");
  });

  it("creates an exclusive sealed session and returns one verified read snapshot", async () => {
    const directory = path.join(os.tmpdir(), `toolbastion-audit-exclusive-${crypto.randomUUID()}`);
    const first = new AuditLog(directory, "exclusive-session");
    const second = new AuditLog(directory, "exclusive-session");
    files.push(first.filePath);
    await first.start();
    await expect(second.start()).rejects.toThrow();
    await first.append("decision", { decision: "BLOCK" });
    await first.close();
    const snapshot = await verifyAndReadAuditFile(first.filePath);
    expect(snapshot.verification.valid).toBe(true);
    expect(snapshot.content).toContain("audit_session_sealed");
    expect(snapshot.events).toHaveLength(3);
  });

  it("only resolves audit reads within the canonical project root", async () => {
    const root = path.join(os.tmpdir(), `toolbastion-audit-root-${crypto.randomUUID()}`);
    const auditDirectory = path.join(root, ".toolbastion", "audit");
    const outsideDirectory = path.join(os.tmpdir(), `toolbastion-audit-outside-${crypto.randomUUID()}`);
    files.push(path.join(root, "cleanup-marker"), path.join(outsideDirectory, "cleanup-marker"));
    await mkdir(auditDirectory, { recursive: true });
    const inRoot = new AuditLog(auditDirectory, "in-root-session");
    await inRoot.append("decision", { decision: "ALLOW" });
    await inRoot.close();
    const resolved = await resolveAuditReadFile(root, ".toolbastion/audit", "in-root-session");
    expect((await verifyAuditFile(resolved)).valid).toBe(true);
    await expect(resolveAuditReadFile(root, "../outside", "in-root-session")).rejects.toThrow("audit.directory must stay inside project_root");
    await expect(resolveAuditReadFile(root, outsideDirectory, "in-root-session")).rejects.toThrow("audit.directory must be relative to project_root");

    await mkdir(outsideDirectory, { recursive: true });
    const outside = new AuditLog(outsideDirectory, "outside-session");
    await outside.append("decision", { decision: "ALLOW" });
    await outside.close();
    const linkedDirectory = path.join(root, "linked-audit");
    await symlink(outsideDirectory, linkedDirectory, process.platform === "win32" ? "junction" : "dir");
    await expect(resolveAuditReadFile(root, "linked-audit", "outside-session")).rejects.toThrow("audit.directory resolves outside project_root");
  });
});
