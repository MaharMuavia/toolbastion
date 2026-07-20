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
import { loadRuntimeSession } from "./runtime-events.js";

const eventSchema = z.object({
  eventId: z.string(),
  sessionId: z.string(),
  timestamp: z.string(),
  eventType: z.string(),
  riskLevel: z.string(),
  toolName: z.string().optional(),
  decision: z.string().optional(),
  summary: z.string(),
  latencyMs: z.number().nonnegative().default(0),
  judgeTokens: z.number().int().nonnegative().default(0),
  cacheHit: z.boolean().default(false)
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

const attackScenarioSchema = z.object({ id: z.string(), title: z.string(), category: z.string(), expected: z.string(), actual: z.string(), summary: z.string() });

export type ApiOptions = {
  rootDir: string;
  configPath?: string;
  snapshotPath?: string;
  dashboardRoot?: string;
  eventLogPath?: string;
  allowRemote?: boolean;
  accessToken?: string;
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
  const decisions = session.events.filter((event) => event.decision);
  const count = (decision: string) => decisions.filter((event) => event.decision === decision).length;
  return {
    totalToolCalls: decisions.length,
    allows: count("ALLOW"),
    blocks: count("BLOCK"),
    askUser: count("ASK_USER"),
    quarantines: count("QUARANTINE"),
    deterministicResolutionRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.judgeTokens === 0).length / decisions.length,
    judgeEscalationRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.judgeTokens > 0).length / decisions.length,
    judgeTokens: session.events.reduce((sum, event) => sum + event.judgeTokens, 0),
    cacheHitRate: decisions.length === 0 ? 0 : decisions.filter((event) => event.cacheHit).length / decisions.length
  };
}

export async function createApi(options: ApiOptions) {
  const app = Fastify({ logger: false, bodyLimit: 256 * 1024 });
  const accessToken = options.accessToken === undefined ? undefined : requireValidAccessToken(options.accessToken);
  let sseClients = 0;
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

  const currentSession = async (): Promise<SnapshotSession> => {
    if (eventLogPath) {
      try {
        return sessionSchema.parse(await loadRuntimeSession(eventLogPath, runtimeConfig?.target.name ?? session.targetName, runtimeConfig?.mode ?? "unknown"));
      } catch { /* A missing, incomplete, or invalid live log falls back to the verified fixture. */ }
    }
    return session;
  };

  app.get("/api/health", () => ({ status: "ok" }));
  app.get("/api/version", () => ({ version: TOOLBASTION_VERSION }));
  app.get("/api/config/status", async () => {
    if (!options.configPath) return { configured: false, openaiConfigured: Boolean(process.env.OPENAI_API_KEY), mode: "offline" };
    const config = toolbastionConfigSchema.parse(parse(await readFile(options.configPath, "utf8")));
    return { configured: true, openaiConfigured: Boolean(process.env.OPENAI_API_KEY), mode: config.judge.mode, runtimeMode: config.mode };
  });
  app.get("/api/sessions", async () => {
    const active = await currentSession();
    return [{ ...active, events: undefined, eventCount: active.events.length, metrics: metrics(active) }];
  });
  app.get("/api/sessions/:sessionId", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    return sessionId === active.sessionId ? { ...active, metrics: metrics(active) } : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/sessions/:sessionId/events", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    return sessionId === active.sessionId ? active.events : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/sessions/:sessionId/metrics", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    return sessionId === active.sessionId ? metrics(active) : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/sessions/:sessionId/report", async (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    const active = await currentSession();
    if (sessionId !== active.sessionId) return reply.code(404).send({ error: "session_not_found" });
    const query = z.object({ format: z.enum(["json", "markdown"]).default("markdown") }).parse(request.query);
    const extension = query.format === "json" ? "json" : "md";
    let content: string;
    if (active.label === "LIVE LOCAL SESSION" && runtimeConfig) {
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
    if (sessionId !== active.sessionId) return reply.code(404).send({ error: "session_not_found" });
    let file: string;
    if (active.label === "LIVE LOCAL SESSION" && runtimeConfig) {
      try {
        file = await resolveAuditReadFile(runtimeConfig.project_root, runtimeConfig.audit.directory, sessionId);
      } catch {
        return reply.code(409).send({ error: "audit_unavailable" });
      }
    } else {
      file = path.join(snapshotRoot, "audit.jsonl");
    }
    const snapshot = await verifyAndReadAuditFile(file);
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
    const close = () => {
      if (!closed) {
        closed = true;
        sseClients -= 1;
      }
    };
    reply.hijack();
    reply.raw.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
    for (const event of active.events) reply.raw.write(`data: ${JSON.stringify(event)}\n\n`);
    if (active.label === "OFFLINE FIXTURE REPLAY") {
      reply.raw.end();
      close();
      return;
    }
    let sent = active.events.length;
    const timer = setInterval(() => {
      void currentSession().then((next) => {
        if (next.sessionId !== active.sessionId) {
          reply.raw.end();
          close();
          return;
        }
        for (const event of next.events.slice(sent)) reply.raw.write(`data: ${JSON.stringify(event)}\n\n`);
        sent = next.events.length;
      }).catch(() => undefined);
    }, 500);
    reply.raw.once("close", () => { clearInterval(timer); close(); });
  });

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
