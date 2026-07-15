import { randomUUID } from "node:crypto";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { AuditLog } from "@mcp-warden/audit";
import { createJudgeProvider, type JudgeProvider } from "@mcp-warden/judge";
import { inspectToolResult } from "@mcp-warden/output-firewall";
import { ExactCallCache, applyRuntimeMode, diffTrustBaseline, evaluateDeterministic, readTrustBaseline, type TrustDiff } from "@mcp-warden/policy";
import { sha256, targetServerConfigSchema, type DeterministicResult, type JudgeVerdict, type RequestDecision, type TargetServerConfig, type WardenConfig } from "@mcp-warden/shared";

export type LifecycleEvent = {
  eventId: string;
  timestamp: string;
  eventType: "target_connecting" | "target_connected" | "tools_listed" | "trust_verified" | "policy_evaluated" | "call_blocked" | "tool_forwarded" | "output_inspected" | "audit_failed" | "target_closed";
  payload: Record<string, unknown>;
};

type EventSink = (event: LifecycleEvent) => void;

export class WardenTargetClient {
  readonly #config: TargetServerConfig;
  readonly #client: Client;
  readonly #transport: StdioClientTransport;
  readonly #emit: EventSink;
  #connected = false;

  constructor(config: TargetServerConfig, emit: EventSink = () => undefined) {
    this.#config = targetServerConfigSchema.parse({ ...config, env_allowlist: config.envAllowlist });
    this.#emit = emit;
    this.#client = new Client({ name: "mcp-warden", version: "0.1.0" }, { capabilities: {} });
    const options: ConstructorParameters<typeof StdioClientTransport>[0] = { command: this.#config.command, args: this.#config.args, stderr: "pipe" };
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

export class WardenProxy {
  readonly #config: WardenConfig;
  readonly #target: WardenTargetClient;
  readonly #server: Server;
  readonly #emit: EventSink;
  readonly #cache = new ExactCallCache<CachedDecision>();
  readonly #judge: JudgeProvider;
  readonly #audit: AuditLog;
  readonly #recentEvents: string[] = [];
  #tools: Awaited<ReturnType<WardenTargetClient["listTools"]>>["tools"] = [];
  #untrustedTools = new Set<string>();

  constructor(config: WardenConfig, emit: EventSink = () => undefined) {
    this.#config = config;
    this.#emit = emit;
    this.#target = new WardenTargetClient(config.target, emit);
    this.#judge = createJudgeProvider(config);
    this.#audit = new AuditLog(path.resolve(config.project_root, config.audit.directory));
    this.#server = new Server({ name: "mcp-warden", version: "0.1.0" }, { capabilities: { tools: {} } });
    this.#server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: this.#visibleTools() }));
    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => this.#handleCall(request.params.name, request.params.arguments ?? {}));
  }

  async runStdio(): Promise<void> {
    await this.#initializeTarget();
    await this.#server.connect(new StdioServerTransport());
  }

  async close(): Promise<void> { await Promise.allSettled([this.#server.close(), this.#target.close(), this.#audit.close()]); }

  async #initializeTarget(): Promise<void> {
    await this.#target.connect();
    this.#tools = (await this.#target.listTools()).tools;
    const baselinePath = path.resolve(this.#config.project_root, ".warden", "warden.lock.json");
    let diff: TrustDiff;
    try {
      diff = diffTrustBaseline(await readTrustBaseline(baselinePath), this.#tools);
    } catch (error) {
      diff = { added: this.#tools.map((tool) => tool.name), removed: [], schemaChanged: [], descriptionChanged: [], poisoned: [], unchanged: [] };
      this.#emitEvent("trust_verified", { approved: false, error: error instanceof Error ? error.message : "baseline unavailable", diff });
    }
    this.#untrustedTools = new Set([...diff.added, ...diff.schemaChanged, ...diff.descriptionChanged, ...diff.poisoned]);
    this.#emitEvent("trust_verified", { approved: this.#untrustedTools.size === 0, diff });
  }

  #visibleTools() {
    return this.#config.mode === "enforce" ? this.#tools.filter((tool) => !this.#untrustedTools.has(tool.name)) : this.#tools;
  }

  async #handleCall(toolName: string, args: Record<string, unknown>) {
    if (!await this.#appendAudit("tool_call_received", { toolName, args })) {
      if (this.#config.mode === "enforce") return this.#auditUnavailable(toolName);
    }
    if (this.#config.mode === "enforce" && this.#untrustedTools.has(toolName)) {
      return this.#blocked(toolName, "tool_trust_not_approved", ["Tool metadata is new or changed from the approved baseline"]);
    }
    const tool = this.#tools.find((candidate) => candidate.name === toolName);
    const schemaHash = sha256(tool?.inputSchema ?? {});
    const policyHash = sha256(this.#config);
    const fingerprint = this.#cache.fingerprint({ targetName: this.#config.target.name, toolName, schemaHash, policyHash, args, mode: this.#config.mode });
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
          runtimeMode: this.#config.mode
        });
        decision = this.#config.mode === "shadow" ? "ALLOW" : judge.decision;
      }
      cached = judge ? { result, decision, judge } : { result, decision };
      if (this.#config.cache.enabled) this.#cache.set(fingerprint, cached, this.#config.cache.ttl_seconds);
    }
    this.#emitEvent("policy_evaluated", { toolName, argsHash: sha256(args), decision: cached.decision, deterministic: cached.result, judge: cached.judge, cacheHits: this.#cache.hits, cacheMisses: this.#cache.misses });
    if (!await this.#appendAudit("policy_decision", { toolName, argsHash: sha256(args), decision: cached.decision, deterministic: cached.result, judge: cached.judge })) {
      if (this.#config.mode === "enforce") return this.#auditUnavailable(toolName);
    }
    if (cached.decision !== "ALLOW") return this.#blocked(toolName, cached.decision === "BLOCK" ? "deterministic_block" : "user_approval_required", cached.result.reasonCodes);
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

  #blocked(toolName: string, reason: string, evidence: string[]) {
    const eventId = randomUUID();
    this.#emitEvent("call_blocked", { toolName, reason, evidence, eventId });
    void this.#appendAudit("call_blocked", { toolName, reason, evidence, eventId });
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
