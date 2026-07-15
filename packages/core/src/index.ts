import { randomUUID } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { AuditLog, redactAuditPayload } from "@toolbastion/audit";
import { createJudgeProvider, type JudgeProvider } from "@toolbastion/judge";
import { inspectToolResult } from "@toolbastion/output-firewall";
import { ExactCallCache, applyRuntimeMode, diffTrustBaseline, evaluateDeterministic, readTrustBaseline, type TrustDiff } from "@toolbastion/policy";
import { sha256, targetServerConfigSchema, type DeterministicResult, type JudgeVerdict, type RequestDecision, type TargetServerConfig, type ToolBastionConfig } from "@toolbastion/shared";

export type LifecycleEvent = {
  eventId: string;
  timestamp: string;
  eventType: "session_started" | "target_connecting" | "target_connected" | "tools_listed" | "tools_changed" | "trust_verified" | "policy_evaluated" | "approval_requested" | "approval_resolved" | "call_blocked" | "tool_forwarded" | "output_inspected" | "audit_failed" | "target_closed";
  payload: Record<string, unknown>;
};

type EventSink = (event: LifecycleEvent) => void;

export type JudgeContext = { status: "available" | "unavailable"; summary?: string; reason: string };

export async function loadJudgeContext(config: ToolBastionConfig): Promise<JudgeContext> {
  const configured = config.judge.context_file;
  if (!configured) return { status: "unavailable", reason: "context_file_not_configured" };
  const root = await realpath(path.resolve(config.project_root)).catch(() => path.resolve(config.project_root));
  const candidate = path.resolve(root, configured);
  const resolved = await realpath(candidate).catch(() => candidate);
  const normalizeCase = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
  const relative = path.relative(normalizeCase(root), normalizeCase(resolved));
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    return { status: "unavailable", reason: "context_file_outside_project_root" };
  }
  try {
    const metadata = await stat(resolved);
    if (!metadata.isFile()) return { status: "unavailable", reason: "context_path_is_not_a_file" };
    if (metadata.size > config.judge.context_max_bytes) return { status: "unavailable", reason: "context_file_too_large" };
    const raw = await readFile(resolved, "utf8");
    const redacted = redactAuditPayload(raw);
    const summary = typeof redacted === "string" ? redacted.trim() : "";
    return summary.length > 0
      ? { status: "available", summary, reason: "context_file_loaded" }
      : { status: "unavailable", reason: "context_file_empty" };
  } catch {
    return { status: "unavailable", reason: "context_file_unreadable" };
  }
}

export function buildTargetEnvironment(envAllowlist: string[], environment: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const allowed = getDefaultEnvironment();
  for (const requestedName of envAllowlist) {
    const actualName = process.platform === "win32"
      ? Object.keys(environment).find((name) => name.toLowerCase() === requestedName.toLowerCase())
      : requestedName;
    if (!actualName) continue;
    const value = environment[actualName];
    if (value !== undefined && !value.startsWith("()")) allowed[actualName] = value;
  }
  return allowed;
}

export class ToolBastionTargetClient {
  readonly #config: TargetServerConfig;
  readonly #client: Client;
  readonly #transport: StdioClientTransport;
  readonly #emit: EventSink;
  readonly #onToolsChanged: () => Promise<void>;
  #connected = false;

  constructor(config: TargetServerConfig, emit: EventSink = () => undefined, onToolsChanged: () => Promise<void> = () => Promise.resolve()) {
    this.#config = targetServerConfigSchema.parse({ ...config, env_allowlist: config.envAllowlist });
    this.#emit = emit;
    this.#onToolsChanged = onToolsChanged;
    this.#client = new Client({ name: "toolbastion", version: "0.1.0" }, { capabilities: {} });
    this.#client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
      this.#event("tools_changed", { targetName: this.#config.name });
      await this.#onToolsChanged();
    });
    const options: ConstructorParameters<typeof StdioClientTransport>[0] = {
      command: this.#config.command,
      args: this.#config.args,
      env: buildTargetEnvironment(this.#config.envAllowlist),
      stderr: "pipe"
    };
    if (this.#config.cwd !== undefined) options.cwd = this.#config.cwd;
    this.#transport = new StdioClientTransport(options);
  }

  async connect(): Promise<void> {
    if (this.#connected) return;
    this.#event("target_connecting", { targetName: this.#config.name });
    await this.#client.connect(this.#transport);
    this.#connected = true;
    this.#event("target_connected", { targetName: this.#config.name });
  }

  async listTools() {
    this.#assertConnected();
    const result = await this.#client.listTools();
    this.#event("tools_listed", { count: result.tools.length });
    return result;
  }

  async callTool(name: string, args: Record<string, unknown>) {
    this.#assertConnected();
    const result = await this.#client.callTool({ name, arguments: args });
    this.#event("tool_forwarded", { toolName: name });
    return result;
  }

  async close(): Promise<void> {
    await this.#transport.close();
    this.#connected = false;
    this.#event("target_closed", { targetName: this.#config.name });
  }

  #assertConnected(): void { if (!this.#connected) throw new Error("Target MCP client is not connected"); }
  #event(eventType: LifecycleEvent["eventType"], payload: Record<string, unknown>): void {
    this.#emit({ eventId: randomUUID(), timestamp: new Date().toISOString(), eventType, payload });
  }
}

type CachedDecision = { result: DeterministicResult; decision: RequestDecision; judge?: JudgeVerdict };

export class ToolBastionProxy {
  readonly #config: ToolBastionConfig;
  readonly #target: ToolBastionTargetClient;
  readonly #server: Server;
  readonly #emit: EventSink;
  readonly #cache = new ExactCallCache<CachedDecision>();
  readonly #judge: JudgeProvider;
  readonly #audit: AuditLog;
  readonly #recentEvents: string[] = [];
  #tools: Awaited<ReturnType<ToolBastionTargetClient["listTools"]>>["tools"] = [];
  #untrustedTools = new Set<string>();

  constructor(config: ToolBastionConfig, emit: EventSink = () => undefined) {
    this.#config = config;
    this.#emit = emit;
    this.#target = new ToolBastionTargetClient(config.target, emit, async () => this.#refreshTools(true));
    this.#judge = createJudgeProvider(config);
    this.#audit = new AuditLog(path.resolve(config.project_root, config.audit.directory));
    this.#server = new Server({ name: "toolbastion", version: "0.1.0" }, { capabilities: { tools: { listChanged: true } } });
    this.#server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: this.#visibleTools() }));
    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => this.#handleCall(request.params.name, request.params.arguments ?? {}));
  }

  async runStdio(): Promise<void> {
    this.#emitEvent("session_started", { sessionId: this.#audit.sessionId });
    await this.#initializeTarget();
    await this.#server.connect(new StdioServerTransport());
  }

  async close(): Promise<void> { await Promise.allSettled([this.#server.close(), this.#target.close(), this.#audit.close()]); }

  async #initializeTarget(): Promise<void> {
    await this.#target.connect();
    await this.#refreshTools(false);
  }

  async #refreshTools(notifyDownstream: boolean): Promise<void> {
    this.#tools = (await this.#target.listTools()).tools;
    const baselinePath = path.resolve(this.#config.project_root, ".toolbastion", "toolbastion.lock.json");
    let diff: TrustDiff;
    try {
      diff = diffTrustBaseline(await readTrustBaseline(baselinePath), this.#tools);
    } catch (error) {
      diff = { added: this.#tools.map((tool) => tool.name), removed: [], schemaChanged: [], descriptionChanged: [], poisoned: [], unchanged: [] };
      this.#emitEvent("trust_verified", { approved: false, error: error instanceof Error ? error.message : "baseline unavailable", diff });
    }
    this.#untrustedTools = new Set([...diff.added, ...diff.schemaChanged, ...diff.descriptionChanged, ...diff.poisoned]);
    this.#emitEvent("trust_verified", { approved: this.#untrustedTools.size === 0, diff });
    this.#cache.clear();
    if (notifyDownstream) await this.#server.sendToolListChanged();
  }

  #visibleTools() {
    return this.#config.mode === "enforce" ? this.#tools.filter((tool) => !this.#untrustedTools.has(tool.name)) : this.#tools;
  }

  async #handleCall(toolName: string, args: Record<string, unknown>) {
    const callId = randomUUID();
    if (!await this.#appendAudit("tool_call_received", { callId, toolName, args })) {
      if (this.#config.mode === "enforce") return this.#auditUnavailable(toolName);
    }
    if (this.#config.mode === "enforce" && this.#untrustedTools.has(toolName)) {
      return this.#blocked(toolName, "tool_trust_not_approved", ["Tool metadata is new or changed from the approved baseline"], {
        callId,
        args,
        deterministicEvidence: [{ category: "tool_trust_not_approved", severity: "critical" }]
      });
    }
    const tool = this.#tools.find((candidate) => candidate.name === toolName);
    const schemaHash = sha256(tool?.inputSchema ?? {});
    const policyHash = sha256(this.#config);
    const context = this.#config.judge.enabled ? await loadJudgeContext(this.#config) : { status: "unavailable" as const, reason: "judge_disabled" };
    const fingerprint = this.#cache.fingerprint({ targetName: this.#config.target.name, toolName, schemaHash, policyHash, args, mode: this.#config.mode, contextHash: sha256(context) });
    let cached = this.#config.cache.enabled ? this.#cache.get(fingerprint) : undefined;
    if (!cached) {
      const result = await evaluateDeterministic(toolName, args, this.#config);
      let decision = applyRuntimeMode(result, this.#config.mode);
      let judge: JudgeVerdict | undefined;
      if (result.resolution === "AMBIGUOUS" && this.#config.judge.enabled) {
        judge = await this.#judge.evaluateRequest({
          toolName,
          untrustedDescription: tool?.description ?? "",
          schemaSummary: tool?.inputSchema ?? {},
          args,
          policySummary: { paths: this.#config.paths, network: this.#config.network, toolRule: this.#config.tools.rules[toolName] ?? this.#config.tools.default },
          deterministicEvidence: result.evidence,
          recentEvents: this.#recentEvents,
          baseRisk: this.#config.tools.rules[toolName]?.base_risk ?? "medium",
          runtimeMode: this.#config.mode,
          ...(context.summary === undefined ? {} : { contextSummary: context.summary })
        });
        decision = this.#config.mode === "shadow" ? "ALLOW" : judge.decision;
      }
      cached = judge ? { result, decision, judge } : { result, decision };
      if (this.#config.cache.enabled) this.#cache.set(fingerprint, cached, this.#config.cache.ttl_seconds);
    }
    this.#emitEvent("policy_evaluated", { toolName, argsHash: sha256(args), decision: cached.decision, deterministic: cached.result, judge: cached.judge, contextStatus: context.status, contextReason: context.reason, cacheHits: this.#cache.hits, cacheMisses: this.#cache.misses });
    if (!await this.#appendAudit("policy_decision", { callId, toolName, argsHash: sha256(args), decision: cached.decision, deterministic: cached.result, judge: cached.judge, contextStatus: context.status, contextReason: context.reason })) {
      if (this.#config.mode === "enforce") return this.#auditUnavailable(toolName);
    }
    const blockedContext = { callId, args, deterministicEvidence: cached.result.evidence, ...(cached.judge === undefined ? {} : { judgeVerdict: cached.judge }) };
    if (cached.decision === "BLOCK") return this.#blocked(toolName, "deterministic_block", cached.result.reasonCodes, blockedContext);
    if (cached.decision === "ASK_USER") {
      const approval = await this.#requestUserApproval(toolName, callId, cached.result.reasonCodes);
      if (approval !== "approved") {
        return this.#blocked(toolName, approval === "declined" ? "user_approval_declined" : "user_approval_required", cached.result.reasonCodes, blockedContext);
      }
    }
    const result = await this.#target.callTool(toolName, args);
    if (!this.#config.outputs.inspect) return result;
    const inspection = inspectToolResult(result, this.#config);
    this.#emitEvent("output_inspected", { toolName, decision: inspection.decision, riskLevel: inspection.riskLevel, evidence: inspection.evidence, redactions: inspection.redactions.length, quarantineId: inspection.quarantineId });
    if (!await this.#appendAudit("output_inspected", { toolName, decision: inspection.decision, riskLevel: inspection.riskLevel, evidence: inspection.evidence, redactions: inspection.redactions, quarantineId: inspection.quarantineId })) {
      if (this.#config.mode === "enforce") return this.#auditUnavailable(toolName);
    }
    if (inspection.decision === "QUARANTINE") {
      return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ decision: "QUARANTINE", reason: "unsafe_tool_output", evidence: inspection.evidence.map((item) => item.category), quarantineId: inspection.quarantineId }) }] };
    }
    return inspection.sanitizedResult as typeof result;
  }

  async #requestUserApproval(toolName: string, callId: string, reasonCodes: string[]): Promise<"approved" | "declined" | "unavailable"> {
    const capabilities = this.#server.getClientCapabilities();
    if (!capabilities?.elicitation?.form) return "unavailable";
    const safeToolName = toolName.replace(/[^A-Za-z0-9_.-]/g, "?").slice(0, 100);
    this.#emitEvent("approval_requested", { toolName: safeToolName, callId, reasonCodes });
    try {
      const response = await this.#server.elicitInput({
        mode: "form",
        message: `ToolBastion requires approval before running ${safeToolName}. Deterministic hard denies cannot be approved.`,
        requestedSchema: {
          type: "object",
          properties: {
            decision: {
              type: "string",
              title: "Decision",
              description: "Approve only this exact tool call, or deny it.",
              enum: ["approve_once", "deny"],
              enumNames: ["Approve once", "Deny"],
              default: "deny"
            }
          },
          required: ["decision"]
        }
      });
      const approved = response.action === "accept" && response.content?.decision === "approve_once";
      const resolution = approved ? "approved" : "declined";
      this.#emitEvent("approval_resolved", { toolName: safeToolName, callId, resolution });
      await this.#appendAudit("user_approval", { callId, toolName: safeToolName, resolution, reasonCodes });
      return resolution;
    } catch {
      this.#emitEvent("approval_resolved", { toolName: safeToolName, callId, resolution: "unavailable" });
      await this.#appendAudit("user_approval", { callId, toolName: safeToolName, resolution: "unavailable", reasonCodes });
      return "unavailable";
    }
  }

  #blocked(toolName: string, reason: string, evidence: string[], context?: { callId: string; args: Record<string, unknown>; deterministicEvidence: unknown; judgeVerdict?: JudgeVerdict }) {
    const eventId = randomUUID();
    this.#emitEvent("call_blocked", { toolName, reason, evidence, eventId });
    void this.#appendAudit("call_blocked", { toolName, reason, evidence, eventId, ...context });
    return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ decision: reason === "user_approval_required" ? "ASK_USER" : "BLOCK", reason, evidence, eventId }) }] };
  }

  #auditUnavailable(toolName: string) {
    const eventId = randomUUID();
    this.#emitEvent("call_blocked", { toolName, reason: "audit_unavailable", evidence: ["Tamper-evident audit write failed"], eventId });
    return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ decision: "BLOCK", reason: "audit_unavailable", evidence: ["Tamper-evident audit write failed"], eventId }) }] };
  }

  async #appendAudit(eventType: string, payload: Record<string, unknown>): Promise<boolean> {
    try {
      await this.#audit.append(eventType, payload);
      return true;
    } catch (error) {
      this.#emitEvent("audit_failed", { eventType, error: error instanceof Error ? error.message : "audit write failed" });
      return false;
    }
  }

  #emitEvent(eventType: LifecycleEvent["eventType"], payload: Record<string, unknown>): void {
    this.#recentEvents.push(eventType);
    if (this.#recentEvents.length > 20) this.#recentEvents.shift();
    this.#emit({ eventId: randomUUID(), timestamp: new Date().toISOString(), eventType, payload });
  }
}
