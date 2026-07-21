import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import Fastify from "fastify";
import { parse } from "yaml";
import { ZodError, z } from "zod";
import { redactAuditPayload, resolveAuditReadFile, verifyAndReadAuditFile } from "@toolbastion/audit";
import { readTrustBaseline } from "@toolbastion/policy";
import { generateSessionReport, renderMarkdownReport } from "@toolbastion/reports";
import { formatZodIssues, TOOLBASTION_VERSION, toolbastionConfigSchema } from "@toolbastion/shared";
import { loadRuntimeSession, type RuntimeSourceState } from "./runtime-events.js";
import { RuntimeEventTailer } from "./runtime-event-tailer.js";

const eventSchema = z.object({
  eventId: z.string(),
  sessionId: z.string(),
  callId: z.string().optional(),
  timestamp: z.string(),
  eventType: z.string(),
  riskLevel: z.string(),
  toolName: z.string().optional(),
  decision: z.enum(["ALLOW", "ASK_USER", "BLOCK", "REDACT", "QUARANTINE"]).optional(),
  summary: z.string(),
  latencyMs: z.number().nonnegative().default(0),
  judgeTokens: z.number().int().nonnegative().default(0),
  cacheHit: z.boolean().default(false),
  authorizationDecision: z.string().optional(),
  executionState: z.string().optional(),
  outputDecision: z.string().optional(),
  decisionSource: z.string().default("deterministic"),
  evidenceState: z.string().default("AVAILABLE"),
  reasonCodes: z.array(z.string()).default([])
});
const sessionSchema = z.object({
  sessionId: z.string(),
  label: z.enum(["OFFLINE FIXTURE REPLAY", "LIVE LOCAL SESSION"]),
  targetName: z.string(),
  startedAt: z.string(),
  mode: z.string(),
  events: z.array(eventSchema)
});
type SnapshotSession = z.infer<typeof sessionSchema>;
type EvidenceSelection = { session: SnapshotSession; sourceState: RuntimeSourceState; reasonCode: string };

const attackScenarioSchema = z.object({ id: z.string(), title: z.string(), category: z.string(), expected: z.string(), actual: z.string(), summary: z.string() });

export type ApiOptions = {
  rootDir: string;
  configPath?: string;
  snapshotPath?: string;
  dashboardRoot?: string;
  eventLogPath?: string;
  allowRemote?: boolean;
  accessToken?: string;
  rateLimitPerMinute?: number;
  sseMaxBytes?: number;
  sseWriteTimeoutMs?: number;
};

const LOCAL_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);
const ACCESS_TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,256}$/;

function requireValidAccessToken(value: string): string {
  if (!ACCESS_TOKEN_PATTERN.test(value)) throw new Error("TOOLBASTION_API_TOKEN must be a 32-256 character base64url secret");
  return value;
}

function authorized(authorization: string | undefined, accessToken: string): boolean {
  if (authorization === undefined || !authorization.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(authorization.slice("Bearer ".length), "utf8");
  const expected = Buffer.from(accessToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function loadSession(filePath: string): Promise<SnapshotSession> {
  return sessionSchema.parse(JSON.parse(await readFile(filePath, "utf8")));
}

function metrics(session: SnapshotSession) {
  type Lifecycle = { terminal?: z.infer<typeof eventSchema>; authorization?: z.infer<typeof eventSchema>; cacheHit: boolean };
  const calls = new Map<string, Lifecycle>();
  for (const event of session.events) {
    if (!event.callId) continue;
    const lifecycle = calls.get(event.callId) ?? { cacheHit: false };
    lifecycle.cacheHit ||= event.cacheHit;
    if (event.eventType === "authorization_completed") lifecycle.authorization = event;
    if (event.eventType === "call_completed" || event.eventType === "call_blocked") lifecycle.terminal = event;
    calls.set(event.callId, lifecycle);
  }
  // Recorded v1 fixtures predate call identifiers. They remain visibly recorded
  // and retain their historical metrics; live runtime evidence always follows
  // the lifecycle branch below.
  if (calls.size === 0) {
    const decisions = session.events.filter((event) => event.decision !== undefined);
    const countLegacy = (decision: string) => decisions.filter((event) => event.decision === decision).length;
    return {
      totalToolCalls: decisions.length,
      allows: countLegacy("ALLOW"),
      blocks: countLegacy("BLOCK"),
      askUser: countLegacy("ASK_USER"),
      quarantines: countLegacy("QUARANTINE"),
      deterministicResolutionRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.judgeTokens === 0).length / decisions.length,
      judgeEscalationRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.judgeTokens > 0).length / decisions.length,
      judgeTokens: session.events.reduce((sum, event) => sum + event.judgeTokens, 0),
      cacheHitRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.cacheHit).length / decisions.length
    };
  }
  const completed = [...calls.values()].filter((call) => call.terminal !== undefined);
  const decision = (call: Lifecycle): "ALLOW" | "ASK_USER" | "BLOCK" | "QUARANTINE" => {
    if (call.terminal?.eventType === "call_blocked") return call.authorization?.authorizationDecision === "ASK_USER" || call.terminal.authorizationDecision === "ASK_USER" ? "ASK_USER" : "BLOCK";
    if (call.terminal?.outputDecision === "QUARANTINE") return "QUARANTINE";
    return "ALLOW";
  };
  const count = (value: ReturnType<typeof decision>) => completed.filter((call) => decision(call) === value).length;
  return {
    totalToolCalls: completed.length,
    allows: count("ALLOW"),
    blocks: count("BLOCK"),
    askUser: count("ASK_USER"),
    quarantines: count("QUARANTINE"),
    deterministicResolutionRate: completed.length === 0 ? 0 : completed.filter((call) => call.authorization?.decisionSource !== "semantic_judge").length / completed.length,
    judgeEscalationRate: completed.length === 0 ? 0 : completed.filter((call) => call.authorization?.decisionSource === "semantic_judge").length / completed.length,
    judgeTokens: completed.reduce((sum, call) => sum + (call.authorization?.judgeTokens ?? 0), 0),
    cacheHitRate: completed.length === 0 ? 0 : completed.filter((call) => call.cacheHit).length / completed.length
  };
}

export async function createApi(options: ApiOptions) {
  const app = Fastify({ logger: false, bodyLimit: 256 * 1024 });
  const accessToken = options.accessToken === undefined ? undefined : requireValidAccessToken(options.accessToken);
  const rateLimitPerMinute = options.rateLimitPerMinute ?? 120;
  if (!Number.isInteger(rateLimitPerMinute) || rateLimitPerMinute < 1 || rateLimitPerMinute > 10_000) throw new Error("rateLimitPerMinute must be an integer between 1 and 10000");
  const sseMaxBytes = options.sseMaxBytes ?? 1_048_576;
  const sseWriteTimeoutMs = options.sseWriteTimeoutMs ?? 5_000;
  if (!Number.isInteger(sseMaxBytes) || sseMaxBytes < 1_024 || sseMaxBytes > 16 * 1024 * 1024) throw new Error("sseMaxBytes is outside the supported range");
  if (!Number.isInteger(sseWriteTimeoutMs) || sseWriteTimeoutMs < 100 || sseWriteTimeoutMs > 60_000) throw new Error("sseWriteTimeoutMs is outside the supported range");
  const rateBuckets = new Map<string, { startedAt: number; count: number }>();
  let sseClients = 0;
  app.addHook("onRequest", async (request, reply) => {
    const now = Date.now();
    const key = request.ip;
    const prior = rateBuckets.get(key);
    const bucket = prior === undefined || now - prior.startedAt >= 60_000 ? { startedAt: now, count: 1 } : { ...prior, count: prior.count + 1 };
    rateBuckets.set(key, bucket);
    if (rateBuckets.size > 10_000) for (const [candidate, value] of rateBuckets) if (now - value.startedAt >= 60_000) rateBuckets.delete(candidate);
    if (bucket.count > rateLimitPerMinute) return reply.code(429).send({ error: "rate_limit_exceeded" });
  });
  if (accessToken !== undefined) {
    app.addHook("onRequest", async (request, reply) => {
      const route = request.url.split("?", 1)[0] ?? "";
      if (!route.startsWith("/api/") || route === "/api/health") return;
      if (!authorized(request.headers.authorization, accessToken)) return reply.code(401).send({ error: "authentication_required" });
    });
  }
  app.addHook("onSend", async (_request, reply, payload) => {
    reply.header("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:");
    reply.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    return payload;
  });
  await app.register(cors, {
    origin: (origin, callback) => callback(null, !origin || origin === "http://127.0.0.1:5173" || origin === "http://localhost:5173"),
    methods: ["GET", "POST"],
    allowedHeaders: ["Authorization", "Content-Type"]
  });
  const snapshotPath = options.snapshotPath ?? path.join(options.rootDir, "fixtures", "dashboard-snapshot", "session.json");
  const snapshotRoot = path.join(options.rootDir, "apps", "dashboard", "public", "snapshot");
  const session = await loadSession(snapshotPath);
  const attackScenarios = z.array(attackScenarioSchema).parse(JSON.parse(await readFile(path.join(options.rootDir, "fixtures", "dashboard-snapshot", "scenarios.json"), "utf8")));
  const runtimeConfig = options.configPath
    ? toolbastionConfigSchema.parse(parse(await readFile(options.configPath, "utf8")))
    : undefined;
  const eventLogPath = options.eventLogPath ?? (runtimeConfig ? path.join(runtimeConfig.project_root, ".toolbastion", "runtime-events.jsonl") : undefined);
  const runtimeTailer = eventLogPath === undefined
    ? undefined
    : new RuntimeEventTailer(eventLogPath, runtimeConfig?.target.name ?? session.targetName, runtimeConfig?.mode ?? "unknown", runtimeConfig?.runtime_events.retain_files ?? 0);

  const currentSession = async (): Promise<EvidenceSelection> => {
    if (!eventLogPath) return { session, sourceState: "RECORDED_SNAPSHOT", reasonCode: "recorded_snapshot_selected" };
    const runtime = runtimeTailer === undefined
      ? await loadRuntimeSession(eventLogPath, runtimeConfig?.target.name ?? session.targetName, runtimeConfig?.mode ?? "unknown")
      : await runtimeTailer.snapshot();
    if (runtime.sourceState === "LIVE_HEALTHY" || runtime.sourceState === "LIVE_PARTIAL") {
      return { session: sessionSchema.parse(runtime.session), sourceState: runtime.sourceState, reasonCode: runtime.reasonCode };
    }
    // A verified fixture may still be browsed, but its source is never relabeled as active runtime evidence.
    return { session, sourceState: runtime.sourceState, reasonCode: runtime.reasonCode };
  };

  app.get("/api/health", () => ({ status: "ok" }));
  app.get("/api/version", () => ({ version: TOOLBASTION_VERSION }));
  app.get("/api/config/status", async () => {
    if (!options.configPath) return { configured: false, openaiConfigured: Boolean(process.env.OPENAI_API_KEY), mode: "offline" };
    const config = toolbastionConfigSchema.parse(parse(await readFile(options.configPath, "utf8")));
    return { configured: true, openaiConfigured: Boolean(process.env.OPENAI_API_KEY), mode: config.judge.mode, runtimeMode: config.mode };
  });
  app.get("/api/evidence/status", async () => {
    const active = await currentSession();
    return { sourceState: active.sourceState, reasonCode: active.reasonCode, sessionId: active.session.sessionId };
  });
  app.get("/api/sessions", async () => {
    const active = await currentSession();
    return [{ ...active.session, events: undefined, eventCount: active.session.events.length, metrics: metrics(active.session), sourceState: active.sourceState, reasonCode: active.reasonCode }];
  });
  app.get("/api/sessions/:sessionId", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    return sessionId === active.session.sessionId ? { ...active.session, metrics: metrics(active.session), sourceState: active.sourceState, reasonCode: active.reasonCode } : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/sessions/:sessionId/events", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    return sessionId === active.session.sessionId ? { events: active.session.events, sourceState: active.sourceState, reasonCode: active.reasonCode } : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/sessions/:sessionId/metrics", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    return sessionId === active.session.sessionId ? { ...metrics(active.session), sourceState: active.sourceState, reasonCode: active.reasonCode } : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/sessions/:sessionId/report", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    if (sessionId !== active.session.sessionId) return reply.code(404).send({ error: "session_not_found" });
    const query = z.object({ format: z.enum(["json", "markdown"]).default("markdown") }).parse(request.query);
    const extension = query.format === "json" ? "json" : "md";
    let content: string;
    if ((active.sourceState === "LIVE_HEALTHY" || active.sourceState === "LIVE_PARTIAL") && runtimeConfig) {
      let report: Awaited<ReturnType<typeof generateSessionReport>>;
      try {
        report = await generateSessionReport(await resolveAuditReadFile(runtimeConfig.project_root, runtimeConfig.audit.directory, sessionId));
      } catch {
        return reply.code(409).send({ error: "audit_unavailable" });
      }
      content = query.format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderMarkdownReport(report);
    } else {
      content = await readFile(path.join(snapshotRoot, `report.${extension}`), "utf8");
    }
    return reply.header("Content-Type", query.format === "json" ? "application/json; charset=utf-8" : "text/markdown; charset=utf-8").header("Content-Disposition", `attachment; filename="toolbastion-${sessionId}.${extension}"`).send(content);
  });
  app.get("/api/sessions/:sessionId/audit", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    if (sessionId !== active.session.sessionId) return reply.code(404).send({ error: "session_not_found" });
    let file: string;
    if ((active.sourceState === "LIVE_HEALTHY" || active.sourceState === "LIVE_PARTIAL") && runtimeConfig) {
      try {
        file = await resolveAuditReadFile(runtimeConfig.project_root, runtimeConfig.audit.directory, sessionId);
      } catch {
        return reply.code(409).send({ error: "audit_unavailable" });
      }
    } else {
      file = path.join(snapshotRoot, "audit.jsonl");
    }
    const snapshot = await verifyAndReadAuditFile(file, undefined, active.session.sessionId);
    if (!snapshot.verification.valid) return reply.code(409).send({ error: "audit_verification_failed", issues: snapshot.verification.errors });
    const content = snapshot.content;
    return reply.header("Content-Type", "application/x-ndjson; charset=utf-8").header("Content-Disposition", `attachment; filename="toolbastion-${sessionId}-redacted.jsonl"`).send(content);
  });
  app.get("/api/evaluation", async (_request, reply) => reply.header("Content-Type", "application/json; charset=utf-8").header("Content-Disposition", "attachment; filename=toolbastion-evaluation-summary.json").send(await readFile(path.join(snapshotRoot, "evaluation-summary.json"), "utf8")));
  app.get("/api/trust", async (_request, reply) => {
    const trustRoot = runtimeConfig?.project_root ?? options.rootDir;
    try { return await readTrustBaseline(path.join(trustRoot, ".toolbastion", "toolbastion.lock.json")); }
    catch { return reply.code(404).send({ error: "trust_baseline_unavailable" }); }
  });
  app.get("/api/policy", async (_request, reply) => {
    if (!options.configPath) return reply.code(404).send({ error: "policy_unavailable" });
    const yaml = await readFile(options.configPath, "utf8");
    const config = toolbastionConfigSchema.parse(parse(yaml));
    return { yaml: redactAuditPayload(yaml), valid: true, mode: config.mode };
  });
  app.post("/api/policy/validate", (request, reply) => {
    const body = z.object({ yaml: z.string().max(200_000) }).parse(request.body);
    try { toolbastionConfigSchema.parse(parse(body.yaml)); return { valid: true, issues: [] }; }
    catch (error) { if (error instanceof ZodError) return reply.code(400).send({ valid: false, issues: formatZodIssues(error) }); throw error; }
  });
  app.get("/api/demo/scenarios", () => attackScenarios.map((scenario) => ({ id: scenario.id, title: scenario.title, category: scenario.category, expected: scenario.expected, summary: scenario.summary })));
  app.post("/api/demo/run", (request, reply) => {
    const validated = z.object({ scenarioId: z.string().regex(/^[a-z0-9-]{1,80}$/) }).safeParse(request.body);
    if (!validated.success) return reply.code(400).send({ error: "invalid_request", issues: formatZodIssues(validated.error) });
    const scenario = attackScenarios.find((item) => item.id === validated.data.scenarioId);
    if (!scenario) return reply.code(404).send({ error: "scenario_not_found" });
    return { mode: "OFFLINE FIXTURE REPLAY", sessionId: session.sessionId, scenarioId: scenario.id, expected: scenario.expected, actual: scenario.actual, matched: scenario.expected === scenario.actual, summary: scenario.summary };
  });
  app.get("/api/events", async (_request, reply) => {
    if (sseClients >= 16) return reply.code(429).send({ error: "too_many_event_streams" });
    const active = await currentSession();
    sseClients += 1;
    let closed = false;
    let pendingDrainTimer: ReturnType<typeof setTimeout> | undefined;
    let bytesWritten = 0;
    const writeChunk = (chunk: string): boolean => {
      if (closed) return false;
      const size = Buffer.byteLength(chunk, "utf8");
      if (bytesWritten + size > sseMaxBytes) {
        reply.raw.end();
        close();
        return false;
      }
      bytesWritten += size;
      const writable = reply.raw.write(chunk);
      if (!writable && pendingDrainTimer === undefined) {
        pendingDrainTimer = setTimeout(() => { pendingDrainTimer = undefined; if (!closed) { reply.raw.end(); close(); } }, sseWriteTimeoutMs);
      }
      return true;
    };
    const close = () => {
      if (!closed) {
        closed = true;
        if (pendingDrainTimer !== undefined) clearTimeout(pendingDrainTimer);
        sseClients -= 1;
      }
    };
    reply.hijack();
    reply.raw.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
    reply.raw.once("drain", () => { if (pendingDrainTimer !== undefined) { clearTimeout(pendingDrainTimer); pendingDrainTimer = undefined; } });
    for (const event of active.session.events) if (!writeChunk(`data: ${JSON.stringify(event)}\n\n`)) return;
    if ((active.sourceState !== "LIVE_HEALTHY" && active.sourceState !== "LIVE_PARTIAL") || runtimeTailer === undefined) {
      reply.raw.end();
      close();
      return;
    }
    const sent = new Set(active.session.events.map((event) => event.eventId));
    const heartbeat = setInterval(() => { writeChunk(": keep-alive\n\n"); }, 15_000);
    heartbeat.unref();
    const unsubscribe = runtimeTailer.subscribe((update) => {
      if (update.type === "event") {
        if (sent.has(update.event.eventId)) return;
        sent.add(update.event.eventId);
        writeChunk(`data: ${JSON.stringify(update.event)}\n\n`);
        return;
      }
      if (update.state.sourceState !== "LIVE_HEALTHY" && update.state.sourceState !== "LIVE_PARTIAL") reply.raw.end();
    });
    reply.raw.once("close", () => { clearInterval(heartbeat); unsubscribe(); close(); });
  });

  app.addHook("onClose", () => { runtimeTailer?.close(); });

  if (options.dashboardRoot) {
    await app.register(fastifyStatic, { root: options.dashboardRoot, prefix: "/", index: ["index.html"] });
  }

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof ZodError) void reply.code(400).send({ error: "invalid_request", issues: formatZodIssues(error) });
    else void reply.code(500).send({ error: "internal_error" });
  });
  return app;
}

export async function startApi(options: ApiOptions, port = 4782, host = process.env.TOOLBASTION_API_HOST ?? "127.0.0.1"): Promise<void> {
  const normalizedHost = host.toLowerCase();
  const remote = !LOCAL_HOSTS.has(normalizedHost);
  if (!options.allowRemote && remote) {
    throw new Error("Refusing to bind the dashboard API outside localhost without explicit --expose acknowledgement");
  }
  const accessToken = options.accessToken ?? (remote ? process.env.TOOLBASTION_API_TOKEN : undefined);
  if (remote && accessToken === undefined) throw new Error("Refusing to bind the dashboard API outside localhost without TOOLBASTION_API_TOKEN");
  const app = await createApi({ ...options, ...(accessToken === undefined ? {} : { accessToken }) });
  await app.listen({ host, port });
}
