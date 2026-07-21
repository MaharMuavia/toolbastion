import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLog, resolveAuditReadFile, signReceipt, verifyAndReadAuditFile, verifyAuditFile, verifyReceipt, writeReceiptFile } from "@toolbastion/audit";
import { bastionReceiptSchema, sha256 } from "@toolbastion/shared";

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
  it("writes receipts exclusively inside the canonical project root", async () => {
    const root = path.join(os.tmpdir(), `toolbastion-receipt-root-${crypto.randomUUID()}`);
    const receipt = bastionReceiptSchema.parse({ version: 1, sessionId: "session", callId: "call-id", toolName: "read", toolManifestHash: sha256([]), schemaHash: sha256({}), policyHash: sha256({}), argsHash: sha256({}), authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "PASS", startedAt: "2026-07-20T00:00:00.000Z", completedAt: "2026-07-20T00:00:01.000Z", signatureStatus: "unsigned" });
    files.push(path.join(root, "cleanup-marker"));
    await mkdir(root, { recursive: true });
    const file = await writeReceiptFile(root, ".toolbastion/receipts", receipt);
    await expect(writeReceiptFile(root, ".toolbastion/receipts", receipt)).rejects.toThrow();
    expect(await readFile(file, "utf8")).not.toContain("raw-argument-sentinel");
    const outside = path.join(os.tmpdir(), `toolbastion-receipt-outside-${crypto.randomUUID()}`);
    await mkdir(outside, { recursive: true });
    await symlink(outside, path.join(root, "linked-receipts"), process.platform === "win32" ? "junction" : "dir");
    await expect(writeReceiptFile(root, "linked-receipts", { ...receipt, callId: "other-call" })).rejects.toThrow(/resolves outside/);
  });

  it("cleans up failed receipt writes so a retry can finalize and duplicates are rejected", async () => {
    const root = path.join(os.tmpdir(), `toolbastion-receipt-failure-${crypto.randomUUID()}`);
    files.push(path.join(root, "cleanup-marker"));
    await mkdir(root, { recursive: true });
    const receipt = bastionReceiptSchema.parse({ version: 1, sessionId: "session", callId: "retry-call", toolName: "read", toolManifestHash: sha256([]), schemaHash: sha256({}), policyHash: sha256({}), argsHash: sha256({}), authorizationDecision: "BLOCK_BEFORE_EXECUTION", executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED", startedAt: "2026-07-20T00:00:00.000Z", completedAt: "2026-07-20T00:00:01.000Z", signatureStatus: "unsigned" });
    await expect(writeReceiptFile(root, ".toolbastion/receipts", receipt, { failAt: "write" })).rejects.toThrow("Injected receipt persistence failure");
    await expect(readFile(path.join(root, ".toolbastion", "receipts", "retry-call.json"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    const file = await writeReceiptFile(root, ".toolbastion/receipts", receipt);
    expect(JSON.parse(await readFile(file, "utf8"))).toMatchObject({ callId: "retry-call" });
    await expect(writeReceiptFile(root, ".toolbastion/receipts", receipt)).rejects.toMatchObject({ code: "EEXIST" });
    const syncFailure = { ...receipt, callId: "sync-failure" };
    await expect(writeReceiptFile(root, ".toolbastion/receipts", syncFailure, { failAt: "sync" })).rejects.toThrow("Injected receipt persistence failure");
    await expect(readFile(path.join(root, ".toolbastion", "receipts", "sync-failure.json"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("signs and independently verifies complete Ed25519 call receipts", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const receipt = signReceipt({
      version: 1, sessionId: "session", callId: "call", toolName: "read_file",
      toolManifestHash: sha256({ tools: [] }), schemaHash: sha256({}), policyHash: sha256({ mode: "enforce" }), argsHash: sha256({ path: "src/index.ts" }),
      authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "PASS",
      startedAt: "2026-07-20T00:00:00.000Z", completedAt: "2026-07-20T00:00:01.000Z"
    }, privateKeyPem);
    expect(verifyReceipt(receipt, publicKeyPem)).toEqual({ valid: true, errors: [] });
    const wrongKey = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(verifyReceipt(receipt, wrongKey).errors).toContain("receipt key is not the configured trusted operator key");
    expect(verifyReceipt({ ...receipt, toolName: "write_file" }).valid).toBe(false);
  });

  it("rejects unsigned receipts as unverifiable", () => {
    const receipt = bastionReceiptSchema.parse({ version: 1, sessionId: "session", callId: "unsigned-call", toolName: "read", toolManifestHash: sha256([]), schemaHash: sha256({}), policyHash: sha256({}), argsHash: sha256({}), authorizationDecision: "BLOCK_BEFORE_EXECUTION", executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED", startedAt: "2026-07-20T00:00:00.000Z", completedAt: "2026-07-20T00:00:01.000Z", signatureStatus: "unsigned" });
    expect(verifyReceipt(receipt)).toEqual({ valid: false, errors: ["receipt is unsigned"] });
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

  it("reports an unsealed session when audit sealing fails", async () => {
    const directory = path.join(os.tmpdir(), `toolbastion-audit-seal-${crypto.randomUUID()}`);
    const log = new AuditLog(directory, "seal-failure-session", {
      retainRawContent: false,
      failWriteForEvent: (eventType) => eventType === "audit_session_sealed"
    });
    files.push(log.filePath);
    await log.append("decision", { decision: "ALLOW" });
    await expect(log.close()).rejects.toThrow("Injected audit persistence failure");
    expect((await verifyAuditFile(log.filePath)).valid).toBe(false);
  });

  it("signs the session seal and fails closed for the wrong key or a replacement file", async () => {
    const directory = path.join(os.tmpdir(), `toolbastion-audit-signed-${crypto.randomUUID()}`);
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const log = new AuditLog(directory, "signed-session", { retainRawContent: false, signingRequired: true, privateKeyPem });
    files.push(log.filePath);
    await log.append("decision", { decision: "BLOCK" });
    await log.close();
    expect((await verifyAuditFile(log.filePath, publicKeyPem)).valid).toBe(true);
    const wrongKey = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    const wrongVerification = await verifyAuditFile(log.filePath, wrongKey);
    expect(wrongVerification.valid).toBe(false);
    expect(wrongVerification.errors.join(" ")).toContain("configured trusted operator key");
    const replacement = path.join(directory, "replacement-session.jsonl");
    await writeFile(replacement, await readFile(log.filePath, "utf8"), "utf8");
    expect((await verifyAuditFile(replacement, publicKeyPem)).errors.join(" ")).toContain("file name");
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
