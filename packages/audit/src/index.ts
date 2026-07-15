import { randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { auditEventSchema, canonicalJson, sha256, type AuditEvent } from "@mcp-warden/shared";

const SECRET_KEY = /(?:api[_-]?key|authorization|credential|password|passwd|secret|token|private[_-]?key|cookie)/i;
const SECRET_VALUE = /(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/gi;

export function redactAuditPayload(value: unknown, key = ""): unknown {
  if (SECRET_KEY.test(key)) return "[REDACTED:sensitive-field]";
  if (typeof value === "string") return value.replace(SECRET_VALUE, "[REDACTED:secret]");
  if (Array.isArray(value)) return value.map((child) => redactAuditPayload(child));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([childKey, child]) => [childKey, redactAuditPayload(child, childKey)]));
  }
  return value;
}

function unsignedEvent(event: Omit<AuditEvent, "eventHash">): Omit<AuditEvent, "eventHash"> { return event; }

export function auditFilePath(directory: string, sessionId: string): string {
  if (!/^[A-Za-z0-9-]+$/.test(sessionId)) throw new Error("Audit session id contains invalid characters");
  return path.join(directory, `${sessionId}.jsonl`);
}

export class AuditLog {
  readonly sessionId: string;
  readonly filePath: string;
  #sequence = 0;
  #previousHash = "GENESIS";
  #queue: Promise<void> = Promise.resolve();

  constructor(directory: string, sessionId: string = randomUUID()) {
    this.sessionId = sessionId;
    this.filePath = auditFilePath(directory, sessionId);
  }

  async append(eventType: string, payload: Record<string, unknown>): Promise<AuditEvent> {
    let created: AuditEvent | undefined;
    this.#queue = this.#queue.then(async () => {
      const base = unsignedEvent({
        sequence: ++this.#sequence,
        eventId: randomUUID(),
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
        eventType,
        payload: redactAuditPayload(payload) as Record<string, unknown>,
        previousHash: this.#previousHash
      });
      created = auditEventSchema.parse({ ...base, eventHash: sha256(base) });
      await mkdir(path.dirname(this.filePath), { recursive: true });
      await appendFile(this.filePath, `${canonicalJson(created)}\n`, { encoding: "utf8", mode: 0o600 });
      this.#previousHash = created.eventHash;
    });
    await this.#queue;
    if (!created) throw new Error("Audit event was not created");
    return created;
  }

  async close(): Promise<void> { await this.#queue; }
}

export type AuditVerification = { valid: boolean; eventCount: number; errors: string[] };

export async function readAuditEvents(filePath: string): Promise<AuditEvent[]> {
  const verification = await verifyAuditFile(filePath);
  if (!verification.valid) throw new Error(`Audit verification failed: ${verification.errors.join("; ")}`);
  return (await readFile(filePath, "utf8")).split(/\r?\n/).filter(Boolean).map((line) => auditEventSchema.parse(JSON.parse(line)));
}

export async function verifyAuditFile(filePath: string): Promise<AuditVerification> {
  const lines = (await readFile(filePath, "utf8")).split(/\r?\n/).filter((line) => line.trim().length > 0);
  const errors: string[] = [];
  let previousHash = "GENESIS";
  for (const [index, line] of lines.entries()) {
    try {
      const event = auditEventSchema.parse(JSON.parse(line));
      if (event.sequence !== index + 1) errors.push(`line ${index + 1}: expected sequence ${index + 1}, found ${event.sequence}`);
      if (event.previousHash !== previousHash) errors.push(`line ${index + 1}: previous hash link is invalid`);
      const { eventHash, ...unsigned } = event;
      if (eventHash !== sha256(unsigned)) errors.push(`line ${index + 1}: event hash is invalid`);
      previousHash = eventHash;
    } catch (error) {
      errors.push(`line ${index + 1}: ${error instanceof Error ? error.message : "invalid JSON event"}`);
    }
  }
  return { valid: errors.length === 0, eventCount: lines.length, errors };
}
