import { open, stat } from "node:fs/promises";
import { runtimeEventSchema, type RuntimeEvent } from "@toolbastion/shared";
import {
  RUNTIME_LOG_MAX_BYTES,
  RUNTIME_LOG_STALE_MS,
  invalidRuntimeLog,
  loadRuntimeSession,
  summarizeRuntimeEvent,
  type RuntimeLoadResult,
  type RuntimeEventSummary
} from "./runtime-events.js";

export type RuntimeTailerUpdate =
  | { type: "event"; event: RuntimeEventSummary }
  | { type: "state"; state: RuntimeLoadResult };

/**
 * One bounded file tailer feeds every SSE client.  It reads a full log only on
 * startup, rotation, truncation, or recovery from an invalid state; steady
 * state reads only bytes appended since the prior poll.
 */
export class RuntimeEventTailer {
  readonly #filePath: string;
  readonly #fallbackTargetName: string;
  readonly #runtimeMode: string;
  readonly #retainFiles: number;
  readonly #listeners = new Set<(update: RuntimeTailerUpdate) => void>();
  #state: RuntimeLoadResult | undefined;
  #offset = 0;
  #remainder = "";
  #timer: NodeJS.Timeout | undefined;
  #polling: Promise<void> | undefined;

  constructor(filePath: string, fallbackTargetName: string, runtimeMode: string, retainFiles: number) {
    this.#filePath = filePath;
    this.#fallbackTargetName = fallbackTargetName;
    this.#runtimeMode = runtimeMode;
    this.#retainFiles = retainFiles;
  }

  async snapshot(): Promise<RuntimeLoadResult> {
    await this.#ensureStarted();
    await this.#poll();
    return this.#state!;
  }

  subscribe(listener: (update: RuntimeTailerUpdate) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  close(): void {
    if (this.#timer !== undefined) clearInterval(this.#timer);
    this.#timer = undefined;
    this.#listeners.clear();
  }

  async #ensureStarted(): Promise<void> {
    if (this.#state !== undefined) return;
    await this.#reload();
    this.#timer = setInterval(() => { void this.#poll(); }, 500);
    this.#timer.unref();
  }

  async #reload(): Promise<void> {
    const next = await loadRuntimeSession(this.#filePath, this.#fallbackTargetName, this.#runtimeMode, this.#retainFiles);
    try {
      const metadata = await stat(this.#filePath);
      this.#offset = metadata.isFile() ? metadata.size : 0;
    } catch {
      this.#offset = 0;
    }
    this.#remainder = "";
    this.#setState(next);
  }

  async #poll(): Promise<void> {
    if (this.#polling !== undefined) return this.#polling;
    this.#polling = this.#pollOnce().finally(() => { this.#polling = undefined; });
    return this.#polling;
  }

  async #pollOnce(): Promise<void> {
    const active = this.#state;
    if (active === undefined) return;
    if (active.sourceState !== "LIVE_HEALTHY" && active.sourceState !== "LIVE_PARTIAL") {
      await this.#reload();
      return;
    }
    let metadata: Awaited<ReturnType<typeof stat>>;
    try {
      metadata = await stat(this.#filePath);
    } catch {
      await this.#reload();
      return;
    }
    if (!metadata.isFile() || metadata.size > RUNTIME_LOG_MAX_BYTES || metadata.size < this.#offset) {
      await this.#reload();
      return;
    }
    if (Date.now() - metadata.mtimeMs > RUNTIME_LOG_STALE_MS) {
      this.#setState({ sourceState: "LIVE_STALE", reasonCode: "runtime_log_stale" });
      return;
    }
    if (metadata.size === this.#offset) return;
    const added = await this.#readAppended(metadata.size);
    if (added === undefined) {
      await this.#reload();
      return;
    }
    for (const line of added) {
      let event: RuntimeEvent;
      try {
        event = runtimeEventSchema.parse(JSON.parse(line));
      } catch {
        this.#setState(invalidRuntimeLog("runtime_log_malformed"));
        return;
      }
      if (event.sessionId !== active.session.sessionId) {
        this.#setState(invalidRuntimeLog("runtime_log_mixed_sessions"));
        return;
      }
      if (event.eventType === "target_closed") {
        this.#setState({ sourceState: "LIVE_CLOSED", reasonCode: "runtime_session_closed" });
        return;
      }
      if (event.eventType !== "heartbeat") {
        const summary = summarizeRuntimeEvent(event);
        active.session.events.push(summary);
        this.#publish({ type: "event", event: summary });
      }
    }
  }

  async #readAppended(end: number): Promise<string[] | undefined> {
    const byteCount = end - this.#offset;
    if (byteCount <= 0 || byteCount > RUNTIME_LOG_MAX_BYTES) return undefined;
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(this.#filePath, "r");
      let position = this.#offset;
      let remaining = byteCount;
      let content = "";
      while (remaining > 0) {
        const buffer = Buffer.allocUnsafe(Math.min(remaining, 64 * 1024));
        const result = await handle.read(buffer, 0, buffer.length, position);
        if (result.bytesRead === 0) return undefined;
        position += result.bytesRead;
        remaining -= result.bytesRead;
        content += buffer.subarray(0, result.bytesRead).toString("utf8");
      }
      this.#offset = end;
      const fragments = `${this.#remainder}${content}`.split(/\r?\n/);
      this.#remainder = fragments.pop() ?? "";
      if (Buffer.byteLength(this.#remainder, "utf8") > 1_048_576) return undefined;
      return fragments.filter(Boolean);
    } catch {
      return undefined;
    } finally {
      await handle?.close();
    }
  }

  #setState(next: RuntimeLoadResult): void {
    const previous = this.#state;
    this.#state = next;
    if (previous?.sourceState !== next.sourceState || previous.reasonCode !== next.reasonCode) this.#publish({ type: "state", state: next });
  }

  #publish(update: RuntimeTailerUpdate): void {
    for (const listener of this.#listeners) listener(update);
  }
}
