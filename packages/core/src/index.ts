import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, realpath, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { Ajv2020, type AnySchemaObject, type ValidateFunction } from "ajv/dist/2020.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { AuditLog, redactAuditPayload } from "@toolbastion/audit";
import { createJudgeProvider, unavailableJudgeVerdict, type JudgeProvider } from "@toolbastion/judge";
import { inspectToolResult } from "@toolbastion/output-firewall";
import { ExactCallCache, applyRuntimeMode, diffTrustBaseline, evaluateDeterministic, readTrustBaseline, type TrustDiff } from "@toolbastion/policy";
import { sha256, targetServerConfigSchema, TOOLBASTION_VERSION, type DeterministicResult, type JudgeVerdict, type RequestDecision, type TargetServerConfig, type TargetServerConfigInput, type ToolBastionConfig } from "@toolbastion/shared";

export type LifecycleEvent = {
  eventId: string;
  timestamp: string;
  eventType: "session_started" | "target_connecting" | "target_connected" | "tools_listed" | "tools_changed" | "trust_verified" | "policy_evaluated" | "call_blocked" | "tool_forwarded" | "target_call_failed" | "output_inspected" | "audit_failed" | "target_closed";
  payload: Record<string, unknown>;
};

type EventSink = (event: LifecycleEvent) => void;

export type ValueBounds = { maxBytes: number; maxDepth: number; maxNodes: number };
type ToolInputValidator = ValidateFunction<Record<string, unknown>>;
type ToolInputValidation = { valid: true } | { valid: false; reason: "input_schema_invalid" | "input_schema_unavailable" };
type AddFormats = (ajv: Ajv2020) => unknown;

const require = createRequire(import.meta.url);
const addFormats = require("ajv-formats") as AddFormats;

export function findValueBoundsViolation(value: unknown, bounds: ValueBounds): string | undefined {
  let bytes = 0;
  let nodes = 0;
  const pending: Array<{ current: unknown; depth: number }> = [{ current: value, depth: 0 }];
  while (pending.length > 0) {
    const { current, depth } = pending.pop()!;
    nodes += 1;
    if (nodes > bounds.maxNodes) return "value_node_limit_exceeded";
    if (depth > bounds.maxDepth) return "value_depth_limit_exceeded";
    if (typeof current === "string") {
      bytes += Buffer.byteLength(current, "utf8");
    } else if (typeof current === "number" || typeof current === "boolean" || current === null) {
      bytes += Buffer.byteLength(String(current), "utf8");
    } else if (Array.isArray(current)) {
      for (const item of current) pending.push({ current: item, depth: depth + 1 });
    } else if (typeof current === "object") {
      for (const [key, item] of Object.entries(current as Record<string, unknown>)) {
        bytes += Buffer.byteLength(key, "utf8");
        pending.push({ current: item, depth: depth + 1 });
      }
    } else {
      return "unsupported_argument_value";
    }
    if (bytes > bounds.maxBytes) return "value_byte_limit_exceeded";
  }
  return undefined;
}

function compileToolInputValidator(inputSchema: Record<string, unknown>): ToolInputValidator {
  if (inputSchema.type !== "object") throw new Error("Tool input schema must have an object root");
  const ajv = new Ajv2020({
    strict: true,
    validateSchema: true,
    validateFormats: true,
    allErrors: false,
    coerceTypes: false,
    useDefaults: false,
    removeAdditional: false,
    ownProperties: true
  });
  addFormats(ajv);
  return ajv.compile<Record<string, unknown>>(inputSchema as AnySchemaObject);
}

function resolveWithinProject(projectRoot: string, configuredPath: string, label: string): string {
  const root = path.resolve(projectRoot);
  const candidate = path.resolve(root, configuredPath);
  const normalizeCase = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
  const relative = path.relative(normalizeCase(root), normalizeCase(candidate));
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error(`${label} must stay inside project_root`);
  return candidate;
}

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

function allowedTargetEnvironmentEntries(envAllowlist: string[], environment: NodeJS.ProcessEnv): Record<string, string> {
  const allowed: Record<string, string> = {};
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

export function buildTargetEnvironment(envAllowlist: string[], environment: NodeJS.ProcessEnv = process.env): Record<string, string> {
  return { ...getDefaultEnvironment(), ...allowedTargetEnvironmentEntries(envAllowlist, environment) };
}

export function buildIsolatedTargetEnvironment(envAllowlist: string[], environment: NodeJS.ProcessEnv = process.env): Record<string, string> {
  return allowedTargetEnvironmentEntries(envAllowlist, environment);
}

const DOCKER_RUNTIME_ROOT = "/workspace";
const DOCKER_WORKSPACE = `${DOCKER_RUNTIME_ROOT}/project`;

type DockerIsolation = Extract<TargetServerConfig["isolation"], { provider: "docker" }>;
type TargetClientConfig = TargetServerConfig | TargetServerConfigInput | (Omit<TargetServerConfigInput, "env_allowlist"> & { envAllowlist?: string[] });

function dockerWorkdir(projectRoot: string, configuredCwd: string | undefined): string {
  const root = path.resolve(projectRoot);
  const cwd = resolveWithinProject(root, configuredCwd ?? ".", "target.cwd");
  const relative = path.relative(root, cwd);
  return relative.length === 0 ? DOCKER_WORKSPACE : path.posix.join(DOCKER_WORKSPACE, relative.split(path.sep).join("/"));
}

export function buildDockerTargetCommand(config: TargetServerConfig, projectRoot: string, environment: Record<string, string>): { command: "docker"; args: string[] } {
  if (config.isolation.provider !== "docker") throw new Error("Docker target command requested without Docker isolation");
  const isolation: DockerIsolation = config.isolation;
  const source = path.resolve(projectRoot);
  if (source.includes(",")) throw new Error("Docker target isolation does not support a project_root containing a comma");
  const environmentArgs = Object.entries(environment)
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([name, value]) => ["--env", `${name}=${value}`]);
  return {
    command: "docker",
    args: [
      "run", "--rm", "--pull=never", "--init", "-i",
      "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
      "--user", isolation.user,
      "--pids-limit", String(isolation.pids_limit), "--memory", `${isolation.memory_mb}m`, "--cpus", String(isolation.cpus),
      "--tmpfs", `/tmp:rw,noexec,nosuid,nodev,size=${isolation.tmpfs_size_mb}m`,
      "--tmpfs", `${DOCKER_WORKSPACE}/node_modules:rw,noexec,nosuid,nodev,size=16m`,
      "--mount", `type=bind,src=${source},dst=${DOCKER_WORKSPACE},readonly`,
      "--workdir", dockerWorkdir(source, config.cwd),
      ...environmentArgs,
      isolation.image,
      config.command,
      ...config.args
    ]
  };
}

async function assertDockerImageAvailable(image: string): Promise<void> {
  const output = await new Promise<string>((resolve, reject) => {
    const child = spawn("docker", ["image", "inspect", "--format", "{{json .RepoDigests}}\n{{.Id}}", image], {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("Docker image inspection timed out"));
    }, 10_000);
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      if (Buffer.byteLength(stdout, "utf8") > 65_536) child.kill();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
      if (Buffer.byteLength(stderr, "utf8") > 4_096) child.kill();
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(new Error(`Docker is unavailable: ${error.message}`));
    });
    child.once("close", (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        const diagnostic = stderr.trim().replaceAll(/\s+/g, " ").slice(0, 512);
        reject(new Error(`Docker image inspection failed${diagnostic.length === 0 ? "" : `: ${diagnostic}`}`));
        return;
      }
      resolve(stdout);
    });
  });
  const [rawRepoDigests = "", imageId = ""] = output.trimEnd().split(/\r?\n/, 2);
  if (image.startsWith("sha256:")) {
    if (imageId !== image) throw new Error("Docker image ID does not match the configured immutable digest");
    return;
  }
  let repoDigests: unknown;
  try {
    repoDigests = JSON.parse(rawRepoDigests);
  } catch {
    throw new Error("Docker image inspection returned an invalid digest record");
  }
  if (!Array.isArray(repoDigests) || !repoDigests.includes(image)) {
    throw new Error("Docker image is not available under the configured immutable digest");
  }
}

export class ToolBastionTargetClient {
  readonly #config: TargetServerConfig;
  readonly #client: Client;
  readonly #transport: StdioClientTransport;
  readonly #emit: EventSink;
  readonly #onToolsChanged: () => Promise<void>;
  readonly #timeoutMs: number;
  readonly #projectRoot: string;
  readonly #targetEnvironment: Record<string, string>;
  readonly #isolatedTargetEnvironment: Record<string, string>;
  #connected = false;
  #preflighted = false;

  constructor(config: TargetClientConfig, emit: EventSink = () => undefined, onToolsChanged: () => Promise<void> = () => Promise.resolve(), timeoutMs = 30_000, projectRoot = process.cwd()) {
    const parsedInput = "envAllowlist" in config
      ? (() => {
        const { envAllowlist, ...target } = config;
        return { ...target, env_allowlist: envAllowlist };
      })()
      : config;
    this.#config = targetServerConfigSchema.parse(parsedInput);
    this.#emit = emit;
    this.#onToolsChanged = onToolsChanged;
    this.#timeoutMs = timeoutMs;
    this.#projectRoot = path.resolve(projectRoot);
    this.#targetEnvironment = buildTargetEnvironment(this.#config.envAllowlist);
    this.#isolatedTargetEnvironment = buildIsolatedTargetEnvironment(this.#config.envAllowlist);
    this.#client = new Client({ name: "toolbastion", version: TOOLBASTION_VERSION }, { capabilities: {} });
    this.#client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
      this.#event("tools_changed", { targetName: this.#config.name });
      await this.#onToolsChanged();
    });
    const launch = this.#config.isolation.provider === "docker"
      ? buildDockerTargetCommand(this.#config, this.#projectRoot, this.#isolatedTargetEnvironment)
      : { command: this.#config.command, args: this.#config.args };
    const options: ConstructorParameters<typeof StdioClientTransport>[0] = {
      command: launch.command,
      args: launch.args,
      env: this.#targetEnvironment,
      stderr: "pipe"
    };
    if (this.#config.isolation.provider !== "docker" && this.#config.cwd !== undefined) options.cwd = this.#config.cwd;
    this.#transport = new StdioClientTransport(options);
    this.#transport.stderr?.on("data", () => undefined);
  }

  async connect(): Promise<void> {
    if (this.#connected) return;
    await this.preflight();
    this.#event("target_connecting", { targetName: this.#config.name, isolationProvider: this.#config.isolation.provider });
    await this.#client.connect(this.#transport);
    this.#connected = true;
    this.#event("target_connected", { targetName: this.#config.name });
  }

  async preflight(): Promise<void> {
    if (this.#preflighted || this.#config.isolation.provider !== "docker") return;
    await assertDockerImageAvailable(this.#config.isolation.image);
    this.#preflighted = true;
  }

  async listTools() {
    this.#assertConnected();
    const result = await this.#client.listTools(undefined, { timeout: this.#timeoutMs });
    this.#event("tools_listed", { count: result.tools.length });
    return result;
  }

  async callTool(name: string, args: Record<string, unknown>) {
    this.#assertConnected();
    const result = await this.#client.callTool({ name, arguments: args }, undefined, { timeout: this.#timeoutMs });
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

type SafeJudgeVerdict = Pick<JudgeVerdict, "decision" | "riskLevel" | "latencyMs" | "inputTokens" | "outputTokens" | "cached" | "offlineReplay"> & {
  subchecks: Array<Pick<JudgeVerdict["subchecks"][number], "checkName" | "verdict" | "riskLevel">>;
};

function summarizeJudgeVerdict(judge: JudgeVerdict | undefined): SafeJudgeVerdict | undefined {
  if (!judge) return undefined;
  return {
    decision: judge.decision,
    riskLevel: judge.riskLevel,
    latencyMs: judge.latencyMs,
    ...(judge.inputTokens === undefined ? {} : { inputTokens: judge.inputTokens }),
    ...(judge.outputTokens === undefined ? {} : { outputTokens: judge.outputTokens }),
    cached: judge.cached,
    offlineReplay: judge.offlineReplay,
    subchecks: judge.subchecks.map((subcheck) => ({
      checkName: subcheck.checkName,
      verdict: subcheck.verdict,
      riskLevel: subcheck.riskLevel
    }))
  };
}

export class ToolBastionProxy {
  readonly #config: ToolBastionConfig;
  readonly #target: ToolBastionTargetClient;
  readonly #server: Server;
  readonly #emit: EventSink;
  readonly #cache = new ExactCallCache<CachedDecision>();
  readonly #inputValidators = new Map<string, ToolInputValidator>();
  readonly #judge: JudgeProvider;
  readonly #audit: AuditLog;
  readonly #recentEvents: string[] = [];
  #tools: Awaited<ReturnType<ToolBastionTargetClient["listTools"]>>["tools"] = [];
  #untrustedTools = new Set<string>();
  #inflightCalls = 0;

  constructor(config: ToolBastionConfig, emit: EventSink = () => undefined) {
    this.#config = config;
    this.#emit = emit;
    this.#target = new ToolBastionTargetClient(config.target, emit, async () => this.#refreshTools(true), config.limits.tool_timeout_ms, config.project_root);
    this.#judge = createJudgeProvider(config);
    this.#audit = new AuditLog(
      resolveWithinProject(config.project_root, config.audit.directory, "audit.directory"),
      undefined,
      { retainRawContent: config.audit.retain_raw_content }
    );
    this.#server = new Server({ name: "toolbastion", version: TOOLBASTION_VERSION }, { capabilities: { tools: { listChanged: true } } });
    this.#server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: this.#visibleTools() }));
    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => this.#handleCall(request.params.name, request.params.arguments ?? {}));
  }

  async runStdio(): Promise<void> {
    await this.#target.preflight();
    if (!await this.#appendAudit("session_started", { sessionId: this.#audit.sessionId })) {
      if (this.#config.mode === "enforce") throw new Error("Audit initialization failed; enforce mode cannot start without an audit session");
    }
    this.#emitEvent("session_started", { sessionId: this.#audit.sessionId });
    await this.#initializeTarget();
    await this.#server.connect(new StdioServerTransport());
  }

  async close(): Promise<void> {
    const outcomes = await Promise.allSettled([this.#server.close(), this.#target.close(), this.#audit.close()]);
    const failure = outcomes.find((outcome): outcome is PromiseRejectedResult => outcome.status === "rejected");
    if (failure) throw failure.reason;
  }

  async #initializeTarget(): Promise<void> {
    await this.#target.connect();
    await this.#refreshTools(false);
  }

  async #refreshTools(notifyDownstream: boolean): Promise<void> {
    this.#tools = (await this.#target.listTools()).tools;
    const baselinePath = path.resolve(this.#config.project_root, ".toolbastion", "toolbastion.lock.json");
    let diff: TrustDiff;
    try {
      diff = diffTrustBaseline(await readTrustBaseline(baselinePath), this.#tools, this.#config.target.name);
    } catch (error) {
      diff = { added: this.#tools.map((tool) => tool.name), removed: [], schemaChanged: [], descriptionChanged: [], poisoned: [], unchanged: [] };
      this.#emitEvent("trust_verified", { approved: false, error: error instanceof Error ? error.message : "baseline unavailable", diff });
    }
    const oversizedMetadata = this.#tools
      .filter((tool) => findValueBoundsViolation({ description: tool.description ?? "", inputSchema: tool.inputSchema }, { maxBytes: this.#config.limits.max_tool_metadata_bytes, maxDepth: 32, maxNodes: 10_000 }) !== undefined)
      .map((tool) => tool.name);
    this.#untrustedTools = new Set([...diff.added, ...diff.schemaChanged, ...diff.descriptionChanged, ...diff.poisoned, ...oversizedMetadata]);
    this.#emitEvent("trust_verified", { approved: this.#untrustedTools.size === 0, diff, oversizedMetadata });
    this.#cache.clear();
    this.#inputValidators.clear();
    if (notifyDownstream) await this.#server.sendToolListChanged();
  }

  #visibleTools() {
    return this.#config.mode === "shadow" ? this.#tools : this.#tools.filter((tool) => !this.#untrustedTools.has(tool.name));
  }

  async #handleCall(toolName: string, args: Record<string, unknown>) {
    if (this.#inflightCalls >= this.#config.limits.max_inflight_calls) {
      return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ decision: "BLOCK", reason: "too_many_inflight_calls" }) }] };
    }
    this.#inflightCalls += 1;
    try {
      return await this.#handleCallInner(toolName, args);
    } finally {
      this.#inflightCalls -= 1;
    }
  }

  async #handleCallInner(toolName: string, args: Record<string, unknown>) {
    const callId = randomUUID();
    const boundsViolation = findValueBoundsViolation(args, {
      maxBytes: this.#config.limits.max_argument_bytes,
      maxDepth: this.#config.limits.max_argument_depth,
      maxNodes: this.#config.limits.max_argument_nodes
    });
    if (boundsViolation) {
      if (!await this.#appendAudit("tool_call_received", { callId, toolName, argumentBoundsViolation: boundsViolation })) {
        if (this.#config.mode === "enforce") return this.#auditUnavailable(toolName);
      }
      return this.#blocked(toolName, "argument_bounds_exceeded", [boundsViolation], {
        callId,
        deterministicEvidence: [{ category: boundsViolation, severity: "high" }]
      });
    }
    const argsHash = sha256(args);
    if (!await this.#appendAudit("tool_call_received", { callId, toolName, argsHash })) {
      if (this.#config.mode === "enforce") return this.#auditUnavailable(toolName);
    }
    const tool = this.#tools.find((candidate) => candidate.name === toolName);
    if (this.#config.mode !== "shadow" && !tool) {
      return this.#blocked(toolName, "tool_not_listed", ["Tool is not in the current target inventory"], {
        callId,
        argsHash,
        deterministicEvidence: [{ category: "tool_not_listed", severity: "critical" }]
      });
    }
    if (this.#config.mode !== "shadow" && this.#untrustedTools.has(toolName)) {
      return this.#blocked(toolName, "tool_trust_not_approved", ["Tool metadata is new or changed from the approved baseline"], {
        callId,
        argsHash,
        deterministicEvidence: [{ category: "tool_trust_not_approved", severity: "critical" }]
      });
    }
    const schemaHash = sha256(tool?.inputSchema ?? {});
    if (tool && !this.#untrustedTools.has(toolName)) {
      const inputValidation = this.#validateToolInput(schemaHash, tool.inputSchema, args);
      if (!inputValidation.valid) {
        await this.#appendAudit("input_schema_validation_failed", { callId, toolName, argsHash, schemaHash, reason: inputValidation.reason });
        if (this.#config.mode !== "shadow") {
          const message = inputValidation.reason === "input_schema_invalid"
            ? "Arguments do not match the target's approved input schema"
            : "The target's approved input schema could not be validated";
          return this.#blocked(toolName, inputValidation.reason, [message], {
            callId,
            argsHash,
            deterministicEvidence: [{ category: inputValidation.reason, severity: "critical" }]
          });
        }
      }
    }
    const policyHash = sha256(this.#config);
    const context = this.#config.judge.enabled ? await loadJudgeContext(this.#config) : { status: "unavailable" as const, reason: "judge_disabled" };
    const fingerprint = this.#cache.fingerprint({ targetName: this.#config.target.name, toolName, schemaHash, policyHash, args, mode: this.#config.mode, contextHash: sha256(context) });
    let cached = this.#config.cache.enabled ? this.#cache.get(fingerprint) : undefined;
    if (!cached) {
      const result = await evaluateDeterministic(toolName, args, this.#config);
      let decision = applyRuntimeMode(result, this.#config.mode);
      let judge: JudgeVerdict | undefined;
      if (result.resolution === "AMBIGUOUS" && this.#config.judge.enabled) {
        const judgeRequest = {
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
        };
        const resolvedJudge = await (async () => {
          try {
            return await this.#judge.evaluateRequest(judgeRequest);
          } catch (error) {
            return unavailableJudgeVerdict(judgeRequest, error instanceof Error ? error.message : "Judge provider failed");
          }
        })();
        judge = resolvedJudge;
        decision = this.#config.mode === "shadow" ? "ALLOW" : resolvedJudge.decision;
      }
      cached = judge ? { result, decision, judge } : { result, decision };
      if (this.#config.cache.enabled) this.#cache.set(fingerprint, cached, this.#config.cache.ttl_seconds);
    }
    const safeJudge = summarizeJudgeVerdict(cached.judge);
    this.#emitEvent("policy_evaluated", { toolName, argsHash, decision: cached.decision, deterministic: cached.result, judge: safeJudge, contextStatus: context.status, contextReason: context.reason, cacheHits: this.#cache.hits, cacheMisses: this.#cache.misses });
    if (!await this.#appendAudit("policy_decision", { callId, toolName, argsHash, decision: cached.decision, deterministic: cached.result, judge: safeJudge, contextStatus: context.status, contextReason: context.reason })) {
      if (this.#config.mode === "enforce") return this.#auditUnavailable(toolName);
    }
    const blockedContext = { callId, argsHash, deterministicEvidence: cached.result.evidence, ...(safeJudge === undefined ? {} : { judgeVerdict: safeJudge }) };
    if (cached.decision === "BLOCK") return this.#blocked(toolName, "deterministic_block", cached.result.reasonCodes, blockedContext);
    if (cached.decision === "ASK_USER") {
      return this.#blocked(toolName, "operator_approval_required", cached.result.reasonCodes, blockedContext);
    }
    let result: Awaited<ReturnType<ToolBastionTargetClient["callTool"]>>;
    try {
      result = await this.#target.callTool(toolName, args);
    } catch (error) {
      const reason = error instanceof Error ? error.name : "target_call_failed";
      this.#emitEvent("target_call_failed", { toolName, reason });
      await this.#appendAudit("target_call_failed", { callId, toolName, reason });
      return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ decision: "BLOCK", reason: "target_call_failed" }) }] };
    }
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

  #validateToolInput(schemaHash: string, inputSchema: Record<string, unknown>, args: Record<string, unknown>): ToolInputValidation {
    let validator = this.#inputValidators.get(schemaHash);
    if (!validator) {
      try {
        validator = compileToolInputValidator(inputSchema);
        this.#inputValidators.set(schemaHash, validator);
      } catch {
        return { valid: false, reason: "input_schema_unavailable" };
      }
    }
    try {
      return validator(args) ? { valid: true } : { valid: false, reason: "input_schema_invalid" };
    } catch {
      return { valid: false, reason: "input_schema_unavailable" };
    }
  }

  async #blocked(toolName: string, reason: string, evidence: string[], context?: { callId: string; argsHash?: string; deterministicEvidence: unknown; judgeVerdict?: SafeJudgeVerdict }) {
    const eventId = randomUUID();
    this.#emitEvent("call_blocked", { toolName, reason, evidence, eventId });
    await this.#appendAudit("call_blocked", { toolName, reason, evidence, eventId, ...context });
    return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ decision: reason === "operator_approval_required" ? "ASK_USER" : "BLOCK", reason, evidence, eventId }) }] };
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
