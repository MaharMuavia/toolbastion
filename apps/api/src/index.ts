import { readFile } from "node:fs/promises";
import path from "node:path";
import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import Fastify from "fastify";
import { parse } from "yaml";
import { ZodError, z } from "zod";
import { readTrustBaseline } from "@mcp-warden/policy";
import { formatZodIssues, wardenConfigSchema } from "@mcp-warden/shared";

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
  label: z.literal("OFFLINE FIXTURE REPLAY"),
  targetName: z.string(),
  startedAt: z.string(),
  mode: z.string(),
  events: z.array(eventSchema)
});
type SnapshotSession = z.infer<typeof sessionSchema>;

export type ApiOptions = {
  rootDir: string;
  configPath?: string;
  snapshotPath?: string;
  dashboardRoot?: string;
};

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
  await app.register(cors, {
    origin: (origin, callback) => callback(null, !origin || origin === "http://127.0.0.1:5173" || origin === "http://localhost:5173"),
    methods: ["GET", "POST"]
  });
  const snapshotPath = options.snapshotPath ?? path.join(options.rootDir, "fixtures", "dashboard-snapshot", "session.json");
  const session = await loadSession(snapshotPath);

  app.get("/api/health", () => ({ status: "ok" }));
  app.get("/api/version", () => ({ version: "0.1.0" }));
  app.get("/api/config/status", async () => {
    if (!options.configPath) return { configured: false, openaiConfigured: Boolean(process.env.OPENAI_API_KEY), mode: "offline" };
    const config = wardenConfigSchema.parse(parse(await readFile(options.configPath, "utf8")));
    return { configured: true, openaiConfigured: Boolean(process.env.OPENAI_API_KEY), mode: config.judge.mode, runtimeMode: config.mode };
  });
  app.get("/api/sessions", () => [{ ...session, events: undefined, eventCount: session.events.length, metrics: metrics(session) }]);
  app.get("/api/sessions/:sessionId", (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    return sessionId === session.sessionId ? { ...session, metrics: metrics(session) } : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/sessions/:sessionId/events", (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    return sessionId === session.sessionId ? session.events : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/sessions/:sessionId/metrics", (request, reply) => {
    const { sessionId } = request.params as { sessionId: string };
    return sessionId === session.sessionId ? metrics(session) : reply.code(404).send({ error: "session_not_found" });
  });
  app.get("/api/trust", async (_request, reply) => {
    try { return await readTrustBaseline(path.join(options.rootDir, ".warden", "warden.lock.json")); }
    catch { return reply.code(404).send({ error: "trust_baseline_unavailable" }); }
  });
  app.get("/api/policy", async (_request, reply) => {
    if (!options.configPath) return reply.code(404).send({ error: "policy_unavailable" });
    const yaml = await readFile(options.configPath, "utf8");
    const config = wardenConfigSchema.parse(parse(yaml));
    return { yaml, valid: true, mode: config.mode };
  });
  app.post("/api/policy/validate", (request, reply) => {
    const body = z.object({ yaml: z.string().max(200_000) }).parse(request.body);
    try { wardenConfigSchema.parse(parse(body.yaml)); return { valid: true, issues: [] }; }
    catch (error) { if (error instanceof ZodError) return reply.code(400).send({ valid: false, issues: formatZodIssues(error) }); throw error; }
  });
  app.post("/api/demo/run", (request, reply) => {
    const validated = z.object({ scenarioId: z.string().regex(/^[a-z0-9-]{1,80}$/) }).safeParse(request.body);
    if (!validated.success) return reply.code(400).send({ error: "invalid_request", issues: formatZodIssues(validated.error) });
    return { mode: "OFFLINE FIXTURE REPLAY", sessionId: session.sessionId, events: session.events };
  });
  app.get("/api/events", (_request, reply) => {
    reply.hijack();
    reply.raw.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
    for (const event of session.events) reply.raw.write(`data: ${JSON.stringify(event)}\n\n`);
    reply.raw.end();
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

export async function startApi(options: ApiOptions, port = 4782): Promise<void> {
  const app = await createApi(options);
  await app.listen({ host: "127.0.0.1", port });
}
