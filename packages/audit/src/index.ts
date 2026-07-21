import { createPrivateKey, createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { mkdir, open, readFile, realpath, stat, type FileHandle } from "node:fs/promises";
import path from "node:path";
import { auditEventSchema, bastionReceiptSchema, canonicalJson, sha256, type AuditEvent, type BastionReceipt } from "@toolbastion/shared";

const SECRET_KEY = /(?:api[_-]?key|authorization|credential|password|passwd|secret|token|private[_-]?key|cookie|connection(?:[_-]?(?:string|uri|url))?|database(?:[_-]?(?:url|uri))?|dsn)/i;
const SECRET_VALUE = /(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/gi;
const SECRET_ASSIGNMENT = /\b(?:OPENAI_API_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|CLIENT_SECRET|DATABASE_URL|DATABASE_URI|CONNECTION_STRING|DSN)\s*[:=]\s*[^\s"']+/gi;
const CONNECTION_URI = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp(?:s)?|mssql):\/\/[^\s"'`<>]+/gi;
const RAW_ARGUMENT_KEY = /^(?:args|arguments)$/i;
const AUDIT_FORMAT_VERSION = 2;
const SESSION_START_EVENT = "audit_session_started";
const SESSION_SEAL_EVENT = "audit_session_sealed";

type UnsignedReceipt = Omit<BastionReceipt, "signature" | "signatureStatus">;

function unsignedReceipt(receipt: BastionReceipt): UnsignedReceipt {
  const unsigned = { ...receipt };
  delete (unsigned as Partial<BastionReceipt>).signature;
  delete (unsigned as Partial<BastionReceipt>).signatureStatus;
  return unsigned as UnsignedReceipt;
}

export function signReceipt(unsigned: UnsignedReceipt, privateKeyPem = process.env.TOOLBASTION_RECEIPT_PRIVATE_KEY): BastionReceipt {
  if (!privateKeyPem) throw new Error("TOOLBASTION_RECEIPT_PRIVATE_KEY must contain an operator-held Ed25519 PEM private key");
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("TOOLBASTION_RECEIPT_PRIVATE_KEY must be an Ed25519 private key");
  const publicKey = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
  const signature = sign(null, Buffer.from(canonicalJson(unsigned), "utf8"), privateKey).toString("base64");
  return bastionReceiptSchema.parse({
    ...unsigned,
    signatureStatus: "signed",
    signature: { algorithm: "ed25519", keyId: sha256(publicKey), publicKey, value: signature }
  });
}

export function verifyReceipt(receipt: unknown, trustedPublicKeyPem?: string): { valid: boolean; errors: string[] } {
  const parsed = bastionReceiptSchema.safeParse(receipt);
  if (!parsed.success) return { valid: false, errors: parsed.error.issues.map((issue) => issue.message) };
  const value = parsed.data;
  const errors: string[] = [];
  if (value.signatureStatus !== "signed" || value.signature === undefined) return { valid: false, errors: ["receipt is unsigned"] };
  if (value.signature.keyId !== sha256(value.signature.publicKey)) errors.push("receipt public key id is invalid");
  try {
    const key = createPublicKey(value.signature.publicKey);
    if (key.asymmetricKeyType !== "ed25519") errors.push("receipt public key is not Ed25519");
    else if (!verify(null, Buffer.from(canonicalJson(unsignedReceipt(value)), "utf8"), key, Buffer.from(value.signature.value, "base64"))) errors.push("receipt signature is invalid");
    if (trustedPublicKeyPem !== undefined) {
      const trustedKey = createPublicKey(trustedPublicKeyPem);
      const trustedPublicKey = trustedKey.export({ type: "spki", format: "pem" }).toString();
      if (trustedKey.asymmetricKeyType !== "ed25519" || trustedPublicKey !== value.signature.publicKey || sha256(trustedPublicKey) !== value.signature.keyId) {
        errors.push("receipt key is not the configured trusted operator key");
      }
    }
  } catch { errors.push("receipt public key is invalid"); }
  if (value.authorizationDecision === "BLOCK_BEFORE_EXECUTION" && value.executionState !== "NOT_DISPATCHED") errors.push("pre-execution block has an invalid execution state");
  if (value.executionState === "NOT_DISPATCHED" && value.outputDecision !== "NOT_INSPECTED") errors.push("undispatched call has an invalid output decision");
  if (value.completedAt === undefined) errors.push("receipt is incomplete");
  else if (Date.parse(value.completedAt) < Date.parse(value.startedAt)) errors.push("receipt completion time precedes start time");
  return { valid: errors.length === 0, errors };
}

export async function writeReceiptFile(projectRoot: string, configuredDirectory: string, receipt: BastionReceipt): Promise<string> {
  if (!/^[A-Za-z0-9-]+$/.test(receipt.callId)) throw new Error("receipt call id contains invalid characters");
  if (path.isAbsolute(configuredDirectory)) throw new Error("receipts.directory must be relative to project_root");
  const root = await realpath(path.resolve(projectRoot));
  const directory = path.resolve(root, configuredDirectory);
  if (!isWithinDirectory(root, directory)) throw new Error("receipts.directory must stay inside project_root");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const canonicalDirectory = await realpath(directory);
  if (!isWithinDirectory(root, canonicalDirectory)) throw new Error("receipts.directory resolves outside project_root");
  const filePath = path.join(canonicalDirectory, `${receipt.callId}.json`);
  const handle = await open(filePath, "wx", 0o600);
  try { await handle.writeFile(`${canonicalJson(receipt)}\n`, "utf8"); await handle.sync(); }
  finally { await handle.close(); }
  return filePath;
}

export function redactAuditPayload(value: unknown, key = ""): unknown {
  if (SECRET_KEY.test(key)) return "[REDACTED:sensitive-field]";
  if (typeof value === "string") return value
    .replace(SECRET_VALUE, "[REDACTED:secret]")
    .replace(SECRET_ASSIGNMENT, "[REDACTED:secret]")
    .replace(CONNECTION_URI, "[REDACTED:connection-uri]");
  if (Array.isArray(value)) return value.map((child) => redactAuditPayload(child));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([childKey, child]) => [childKey, redactAuditPayload(child, childKey)]));
  }
  return value;
}

function projectRawArguments(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(projectRawArguments);
  if (value === null || typeof value !== "object") return value;
  const source = value as Record<string, unknown>;
  const projected: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(source)) {
    if (RAW_ARGUMENT_KEY.test(key)) {
      const hashKey = key.toLowerCase() === "args" ? "argsHash" : "argumentsHash";
      projected[hashKey] = sha256(child);
      projected[`${key}Omitted`] = true;
      continue;
    }
    projected[key] = projectRawArguments(child);
  }
  return projected;
}

function unsignedEvent(event: Omit<AuditEvent, "eventHash">): Omit<AuditEvent, "eventHash"> { return event; }

export function auditFilePath(directory: string, sessionId: string): string {
  if (!/^[A-Za-z0-9-]+$/.test(sessionId)) throw new Error("Audit session id contains invalid characters");
  return path.join(directory, `${sessionId}.jsonl`);
}

function isWithinDirectory(root: string, candidate: string): boolean {
  const normalizeCase = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
  const relative = path.relative(normalizeCase(root), normalizeCase(candidate));
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

/** Resolves a sealed audit file only when every path component remains inside projectRoot. */
export async function resolveAuditReadFile(projectRoot: string, configuredDirectory: string, sessionId: string): Promise<string> {
  if (path.isAbsolute(configuredDirectory)) throw new Error("audit.directory must be relative to project_root");
  const canonicalRoot = await realpath(path.resolve(projectRoot));
  const lexicalDirectory = path.resolve(canonicalRoot, configuredDirectory);
  if (!isWithinDirectory(canonicalRoot, lexicalDirectory)) throw new Error("audit.directory must stay inside project_root");
  const canonicalDirectory = await realpath(lexicalDirectory);
  if (!isWithinDirectory(canonicalRoot, canonicalDirectory)) throw new Error("audit.directory resolves outside project_root");
  const canonicalFile = await realpath(auditFilePath(canonicalDirectory, sessionId));
  if (!isWithinDirectory(canonicalRoot, canonicalFile)) throw new Error("audit file resolves outside project_root");
  if (!(await stat(canonicalFile)).isFile()) throw new Error("audit session path is not a regular file");
  return canonicalFile;
}

export type AuditLogOptions = {
  retainRawContent: false;
  /** Test-only dependency seam for exercising the proxy's fail-closed path. */
  failWriteForEvent?: (eventType: string) => boolean;
};

export class AuditLog {
  readonly sessionId: string;
  readonly filePath: string;
  #sequence = 0;
  #previousHash = "GENESIS";
  #queue: Promise<void> = Promise.resolve();
  #handle: FileHandle | undefined;
  #started = false;
  #closed = false;
  #writeFailed = false;
  readonly #retainRawContent: false;
  readonly #failWriteForEvent: ((eventType: string) => boolean) | undefined;

  constructor(directory: string, sessionId: string = randomUUID(), options: AuditLogOptions = { retainRawContent: false }) {
    this.sessionId = sessionId;
    this.filePath = auditFilePath(directory, sessionId);
    this.#retainRawContent = options.retainRawContent;
    this.#failWriteForEvent = options.failWriteForEvent;
  }

  async start(): Promise<void> {
    await this.#enqueue(async () => {
      this.#assertOpen();
      await this.#ensureStarted();
    });
  }

  async append(eventType: string, payload: Record<string, unknown>): Promise<AuditEvent> {
    return this.#enqueue(async () => {
      this.#assertOpen();
      await this.#ensureStarted();
      try {
        return await this.#writeEvent(eventType, payload);
      } catch (error) {
        this.#writeFailed = true;
        throw error;
      }
    });
  }

  async close(): Promise<void> {
    await this.#enqueue(async () => {
      if (this.#closed) return;
      try {
        if (this.#writeFailed) throw new Error("Audit session cannot be sealed after a failed write");
        if (this.#started) {
          await this.#writeEvent(SESSION_SEAL_EVENT, {
            auditFormat: AUDIT_FORMAT_VERSION,
            eventCount: this.#sequence,
            finalEventHash: this.#previousHash
          });
        }
      } finally {
        this.#closed = true;
        const handle = this.#handle;
        this.#handle = undefined;
        await handle?.close();
      }
    });
  }

  async #enqueue<T>(task: () => Promise<T>): Promise<T> {
    const operation = this.#queue.then(task, task);
    this.#queue = operation.then(() => undefined, () => undefined);
    return operation;
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error("Audit session is already closed");
    if (this.#writeFailed) throw new Error("Audit session has a failed write and cannot accept more events");
  }

  async #ensureStarted(): Promise<void> {
    if (this.#started) return;
    await mkdir(path.dirname(this.filePath), { recursive: true });
    const handle = await open(this.filePath, "wx", 0o600);
    this.#handle = handle;
    try {
      await this.#writeEvent(SESSION_START_EVENT, { auditFormat: AUDIT_FORMAT_VERSION });
      this.#started = true;
    } catch (error) {
      this.#writeFailed = true;
      this.#handle = undefined;
      await handle.close().catch(() => undefined);
      throw error;
    }
  }

  async #writeEvent(eventType: string, payload: Record<string, unknown>): Promise<AuditEvent> {
    const handle = this.#handle;
    if (!handle) throw new Error("Audit session is not open");
    if (this.#failWriteForEvent?.(eventType) === true) throw new Error("Injected audit persistence failure");
    const base = unsignedEvent({
      sequence: this.#sequence + 1,
      eventId: randomUUID(),
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      eventType,
      payload: redactAuditPayload(this.#retainRawContent ? payload : projectRawArguments(payload)) as Record<string, unknown>,
      previousHash: this.#previousHash
    });
    const created = auditEventSchema.parse({ ...base, eventHash: sha256(base) });
    await handle.writeFile(`${canonicalJson(created)}\n`, { encoding: "utf8" });
    await handle.sync();
    this.#sequence = created.sequence;
    this.#previousHash = created.eventHash;
    return created;
  }
}

export type AuditVerification = { valid: boolean; eventCount: number; errors: string[] };
export type VerifiedAuditRead = { verification: AuditVerification; events: AuditEvent[]; content: string };

function verifyAuditContent(content: string): Omit<VerifiedAuditRead, "content"> {
  const rawLines = content.split(/\r?\n/);
  if (rawLines.at(-1) === "") rawLines.pop();
  const errors: string[] = [];
  const events: AuditEvent[] = [];
  if (rawLines.length === 0 || rawLines.every((line) => line.trim().length === 0)) {
    return { verification: { valid: false, eventCount: 0, errors: ["audit log is empty or incomplete"] }, events };
  }
  let previousHash = "GENESIS";
  const eventIds = new Set<string>();
  let sessionId: string | undefined;
  for (const [index, line] of rawLines.entries()) {
    if (line.trim().length === 0) {
      errors.push(`line ${index + 1}: blank records are not permitted`);
      continue;
    }
    try {
      const event = auditEventSchema.parse(JSON.parse(line));
      events.push(event);
      if (event.sequence !== index + 1) errors.push(`line ${index + 1}: expected sequence ${index + 1}, found ${event.sequence}`);
      if (event.previousHash !== previousHash) errors.push(`line ${index + 1}: previous hash link is invalid`);
      const { eventHash, ...unsigned } = event;
      if (eventHash !== sha256(unsigned)) errors.push(`line ${index + 1}: event hash is invalid`);
      if (eventIds.has(event.eventId)) errors.push(`line ${index + 1}: event id is duplicated`);
      eventIds.add(event.eventId);
      if (sessionId === undefined) sessionId = event.sessionId;
      else if (event.sessionId !== sessionId) errors.push(`line ${index + 1}: session id does not match the audit session`);
      previousHash = eventHash;
    } catch (error) {
      errors.push(`line ${index + 1}: ${error instanceof Error ? error.message : "invalid JSON event"}`);
    }
  }

  if (events.length !== rawLines.length) return { verification: { valid: false, eventCount: events.length, errors }, events };
  const starts = events.filter((event) => event.eventType === SESSION_START_EVENT);
  const seals = events.filter((event) => event.eventType === SESSION_SEAL_EVENT);
  const first = events[0];
  const last = events.at(-1);
  if (starts.length !== 1 || first?.eventType !== SESSION_START_EVENT || first.payload.auditFormat !== AUDIT_FORMAT_VERSION) {
    errors.push("audit session start record is missing or invalid");
  }
  if (seals.length !== 1 || last?.eventType !== SESSION_SEAL_EVENT || last?.payload.auditFormat !== AUDIT_FORMAT_VERSION) {
    errors.push("audit session seal record is missing or invalid");
  } else {
    const prior = events.at(-2);
    if (last.payload.eventCount !== events.length - 1) errors.push("audit session seal event count is invalid");
    if (last.payload.finalEventHash !== prior?.eventHash) errors.push("audit session seal does not bind the final event");
  }
  return { verification: { valid: errors.length === 0, eventCount: events.length, errors }, events };
}

export async function verifyAndReadAuditFile(filePath: string): Promise<VerifiedAuditRead> {
  const content = await readFile(filePath, "utf8");
  return { ...verifyAuditContent(content), content };
}

export async function readAuditEvents(filePath: string): Promise<AuditEvent[]> {
  const { verification, events } = await verifyAndReadAuditFile(filePath);
  if (!verification.valid) throw new Error(`Audit verification failed: ${verification.errors.join("; ")}`);
  return events;
}

export async function verifyAuditFile(filePath: string): Promise<AuditVerification> {
  return (await verifyAndReadAuditFile(filePath)).verification;
}
