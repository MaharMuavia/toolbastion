import { createHash, createPrivateKey, randomUUID } from "node:crypto";
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
import { AuditLog, redactAuditPayload, signReceipt, writeReceiptFile } from "@toolbastion/audit";
import { createJudgeProvider, unavailableJudgeVerdict, type JudgeProvider } from "@toolbastion/judge";
import { inspectToolResult } from "@toolbastion/output-firewall";
import { ExactCallCache, applyRuntimeMode, diffTrustBaseline, evaluateDeterministic, readTrustBaseline, type TrustDiff } from "@toolbastion/policy";
import { bastionReceiptSchema, canonicalJson, sanitizeRuntimeEvent, sha256, targetArtifactIdentitySchema, targetServerConfigSchema, TOOLBASTION_VERSION, type AuthorizationDecision, type DeterministicResult, type ExecutionState, type JudgeVerdict, type OutputDecision, type RequestDecision, type RuntimeEvent, type RuntimeEventType, type TargetArtifactIdentity, type TargetServerConfig, type TargetServerConfigInput, type ToolBastionConfig } from "@toolbastion/shared";

export type LifecycleEvent = {
  eventId: string;
  timestamp: string;
  eventType: RuntimeEventType;
  payload: Record<string, unknown>;
};

type EventSink = (event: LifecycleEvent) => void;
type RuntimeEventSink = (event: RuntimeEvent) => void;

export type ValueBounds = { maxBytes: number; maxDepth: number; maxNodes: number };
export type Clock = { now(): Date };
const systemClock: Clock = { now: () => new Date() };
/** Immutable per-call timing captured before any policy, audit, or target work. */
export class ReceiptTiming {
  readonly startedAt: string;
  #completedAt: string | undefined;
  readonly #clock: Clock;

  constructor(clock: Clock) {
    this.#clock = clock;
    this.startedAt = clock.now().toISOString();
  }

  complete(): string {
    if (this.#completedAt !== undefined) return this.#completedAt;
    const completedAt = this.#clock.now().toISOString();
    if (Date.parse(completedAt) < Date.parse(this.startedAt)) throw new Error("Receipt clock moved backwards before finalization");
    this.#completedAt = completedAt;
    return completedAt;
  }
}
type AcceptedCall = { callId: string; toolName: string; argsHash: string; policyHash: string; startedAt: string; timing: ReceiptTiming };
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

export function buildDockerTargetCommand(config: TargetServerConfig, projectRoot: string, environment: Record<string, string>, containerName?: string): { command: "docker"; args: string[] } {
  if (config.isolation.provider !== "docker") throw new Error("Docker target command requested without Docker isolation");
  const isolation: DockerIsolation = config.isolation;
  const source = path.resolve(projectRoot);
  if (source.includes(",")) throw new Error("Docker target isolation does not support a project_root containing a comma");
  const environmentArgs = Object.keys(environment)
    .sort((left, right) => left.localeCompare(right))
    .flatMap((name) => ["--env", name]);
  const writableMounts = isolation.writable_paths.flatMap((relativePath) => {
    const normalized = relativePath.replaceAll("\\", "/").replace(/^\.\//, "");
    const sourcePath = path.resolve(source, relativePath);
    const destinationPath = path.posix.join(DOCKER_WORKSPACE, normalized);
    return ["--mount", `type=bind,src=${sourcePath},dst=${destinationPath},rw`];
  });
  return {
    command: "docker",
    args: [
      "run", "--rm", "--pull=never", "--init", "-i",
      ...(containerName === undefined ? [] : ["--name", containerName]),
      "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
      "--user", isolation.user,
      "--pids-limit", String(isolation.pids_limit), "--memory", `${isolation.memory_mb}m`, "--cpus", String(isolation.cpus),
      "--tmpfs", `/tmp:rw,noexec,nosuid,nodev,size=${isolation.tmpfs_size_mb}m`,
      "--tmpfs", `${DOCKER_WORKSPACE}/node_modules:rw,noexec,nosuid,nodev,size=16m`,
      "--mount", `type=bind,src=${source},dst=${DOCKER_WORKSPACE},readonly`,
      ...writableMounts,
      "--workdir", dockerWorkdir(source, config.cwd),
      ...environmentArgs,
      isolation.image,
      config.command,
      ...config.args
    ]
  };
}

async function assertWritableMountsWithinProject(config: TargetServerConfig, projectRoot: string): Promise<void> {
  if (config.isolation.provider !== "docker") return;
  const root = await realpath(path.resolve(projectRoot));
  const normalizeCase = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
  for (const relativePath of config.isolation.writable_paths) {
    const candidate = path.resolve(root, relativePath);
    const canonical = await realpath(candidate).catch(() => { throw new Error(`Writable containment path does not exist: ${relativePath}`); });
    const relative = path.relative(normalizeCase(root), normalizeCase(canonical));
    if (relative === "" || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      throw new Error(`Writable containment path resolves outside project_root: ${relativePath}`);
    }
    const metadata = await stat(canonical);
    if (!metadata.isDirectory()) throw new Error(`Writable containment path is not a directory: ${relativePath}`);
  }
}

async function inspectDockerImage(image: string): Promise<{ repoDigests: string[]; imageId: string }> {
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
    return { repoDigests: [], imageId };
  }
  let repoDigests: unknown;
  try {
    repoDigests = JSON.parse(rawRepoDigests);
  } catch {
    throw new Error("Docker image inspection returned an invalid digest record");
  }
  if (!Array.isArray(repoDigests) || !repoDigests.every((value): value is string => typeof value === "string")) {
    throw new Error("Docker image inspection returned an invalid digest record");
  }
  if (!repoDigests.includes(image)) {
    throw new Error("Docker image is not available under the configured immutable digest");
  }
  return { repoDigests, imageId };
}

async function assertDockerImageAvailable(image: string): Promise<void> {
  await inspectDockerImage(image);
}

function sha256Bytes(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

async function resolveExecutablePath(command: string): Promise<string> {
  const candidates: string[] = [];
  if (path.isAbsolute(command) || command.includes(path.sep) || command.includes("/")) candidates.push(path.resolve(command));
  else {
    if (command.toLowerCase() === "node") candidates.push(process.execPath);
    for (const directory of (process.env.PATH ?? "").split(path.delimiter).filter((value) => value.length > 0)) {
      candidates.push(path.join(directory, command));
      if (process.platform === "win32") for (const extension of [".exe", ".cmd", ".bat"]) candidates.push(path.join(directory, `${command}${extension}`));
    }
  }
  for (const candidate of candidates) {
    try {
      const metadata = await stat(candidate);
      if (metadata.isFile()) return await realpath(candidate);
    } catch { /* try the next PATH candidate */ }
  }
  throw new Error(`Target executable could not be resolved for artifact hashing: ${command}`);
}

async function resolveTargetInputFiles(config: TargetServerConfig, projectRoot: string): Promise<string[]> {
  const files = new Set<string>();
  for (const argument of config.args) {
    if (argument.startsWith("-") || /^[a-z][a-z0-9+.-]*:\/\//i.test(argument)) continue;
    const candidate = path.resolve(config.cwd === undefined ? projectRoot : path.resolve(projectRoot, config.cwd), argument);
    try {
      const metadata = await stat(candidate);
      if (metadata.isFile()) files.add(await realpath(candidate));
    } catch { /* non-path arguments are not artifact files */ }
  }
  return [...files].sort((left, right) => left.localeCompare(right));
}

export async function resolveTargetArtifactIdentity(configInput: TargetServerConfigInput | TargetServerConfig, projectRoot: string): Promise<TargetArtifactIdentity> {
  const config = targetServerConfigSchema.parse("envAllowlist" in configInput
    ? (() => {
      const { envAllowlist, ...target } = configInput;
      return { ...target, env_allowlist: envAllowlist };
    })()
    : configInput);
  if (config.isolation.provider === "docker") {
    const inspected = await inspectDockerImage(config.isolation.image);
    const digest = config.isolation.image.startsWith("sha256:")
      ? config.isolation.image
      : config.isolation.image.slice(config.isolation.image.indexOf("@") + 1);
    return targetArtifactIdentitySchema.parse({ kind: "docker", reference: config.isolation.image, digest, imageId: inspected.imageId });
  }
  const executablePath = await resolveExecutablePath(config.command);
  const executableHash = sha256Bytes(await readFile(executablePath));
  const inputFiles = await resolveTargetInputFiles(config, path.resolve(projectRoot));
  const inputHashes = await Promise.all(inputFiles.map(async (filePath) => ({ path: filePath, hash: sha256Bytes(await readFile(filePath)) })));
  return targetArtifactIdentitySchema.parse({
    kind: "executable",
    executablePath,
    executableHash,
    buildHash: sha256(canonicalJson(inputHashes))
  });
}

export class ToolBastionTargetClient {
  readonly #config: TargetServerConfig;
  #client: Client;
  #transport: StdioClientTransport;
  readonly #emit: EventSink;
  readonly #onToolsChanged: () => Promise<void>;
  readonly #timeoutMs: number;
  readonly #projectRoot: string;
  readonly #targetEnvironment: Record<string, string>;
  readonly #isolatedTargetEnvironment: Record<string, string>;
  readonly #dockerContainerName: string | undefined;
  #dockerContainerId: string | undefined;
  #connected = false;
  #preflighted = false;
  #recovery: Promise<void> | undefined;

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
    this.#dockerContainerName = this.#config.isolation.provider === "docker" ? `toolbastion-${randomUUID()}` : undefined;
    this.#client = this.#createClient();
    const launch = this.#config.isolation.provider === "docker"
      ? buildDockerTargetCommand(this.#config, this.#projectRoot, this.#isolatedTargetEnvironment, this.#dockerContainerName)
      : { command: this.#config.command, args: this.#config.args };
    const options: ConstructorParameters<typeof StdioClientTransport>[0] = {
      command: launch.command,
      args: launch.args,
      env: this.#targetEnvironment,
      stderr: "pipe"
    };
    if (this.#config.isolation.provider !== "docker" && this.#config.cwd !== undefined) options.cwd = this.#config.cwd;
    this.#transport = this.#createTransport(options);
  }

  async connect(): Promise<void> {
    if (this.#connected) return;
    await this.preflight();
    this.#event("target_connecting", { targetName: this.#config.name, isolationProvider: this.#config.isolation.provider });
    await this.#client.connect(this.#transport);
    this.#connected = true;
    if (this.#dockerContainerName !== undefined) await this.#captureDockerContainer();
    this.#event("target_connected", { targetName: this.#config.name, ...(this.#dockerContainerId === undefined ? {} : { containerId: this.#dockerContainerId }) });
  }

  async preflight(): Promise<void> {
    if (this.#preflighted || this.#config.isolation.provider !== "docker") return;
    await assertDockerImageAvailable(this.#config.isolation.image);
    await assertWritableMountsWithinProject(this.#config, this.#projectRoot);
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
    if (this.#recovery) throw new Error("Target recovery is in progress; fail closed");
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const request = this.#client.callTool({ name, arguments: args });
      const deadline = new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new TargetCallTimeoutError()), this.#timeoutMs);
      });
      return await Promise.race([request, deadline]);
    } catch (error) {
      if (error instanceof TargetCallTimeoutError || this.#isTimeout(error)) {
        try {
          await this.#recoverAfterTimeout();
        } catch {
          throw new TargetCallTimeoutError(false);
        }
        throw new TargetCallTimeoutError(true);
      }
      throw error;
    } finally {
      if (timeout !== undefined) clearTimeout(timeout);
    }
  }

  async close(): Promise<void> {
    await this.#transport.close();
    this.#connected = false;
    this.#event("target_closed", { targetName: this.#config.name });
  }

  #assertConnected(): void { if (!this.#connected) throw new Error("Target MCP client is not connected"); }
  #createClient(): Client {
    const client = new Client({ name: "toolbastion", version: TOOLBASTION_VERSION }, { capabilities: {} });
    client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
      this.#event("tools_changed", { targetName: this.#config.name });
      await this.#onToolsChanged();
    });
    return client;
  }

  #createTransport(options: ConstructorParameters<typeof StdioClientTransport>[0]): StdioClientTransport {
    const transport = new StdioClientTransport(options);
    transport.stderr?.on("data", () => undefined);
    return transport;
  }

  #isTimeout(error: unknown): boolean {
    const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    return /timeout|timed out|deadline/i.test(message);
  }

  async #recoverAfterTimeout(): Promise<void> {
    if (this.#recovery) return this.#recovery;
    this.#recovery = (async () => {
      const pid = this.#transport.pid;
      this.#connected = false;
      this.#event("target_termination_started", { targetName: this.#config.name, ...(pid === null ? {} : { pid }) });
      const terminated = this.#dockerContainerName === undefined
        ? await terminateProcessTree(pid)
        : await terminateDockerContainer(this.#dockerContainerName, this.#dockerContainerId);
      await this.#transport.close().catch(() => undefined);
      if (!terminated) throw new Error("Target termination could not be confirmed; proxy remains fail closed");
      this.#event("target_terminated", { targetName: this.#config.name, ...(pid === null ? {} : { pid }) });
      this.#event("target_restart_started", { targetName: this.#config.name });
      this.#client = this.#createClient();
      const launch = this.#config.isolation.provider === "docker"
        ? buildDockerTargetCommand(this.#config, this.#projectRoot, this.#isolatedTargetEnvironment, this.#dockerContainerName)
        : { command: this.#config.command, args: this.#config.args };
      const options: ConstructorParameters<typeof StdioClientTransport>[0] = { command: launch.command, args: launch.args, env: this.#targetEnvironment, stderr: "pipe" };
      if (this.#config.isolation.provider !== "docker" && this.#config.cwd !== undefined) options.cwd = this.#config.cwd;
      this.#transport = this.#createTransport(options);
      await this.connect();
      await this.#onToolsChanged();
      this.#event("target_restarted", { targetName: this.#config.name });
    })();
    try {
      await this.#recovery;
    } finally {
      this.#recovery = undefined;
    }
  }
  #event(eventType: LifecycleEvent["eventType"], payload: Record<string, unknown>): void {
    this.#emit({ eventId: randomUUID(), timestamp: new Date().toISOString(), eventType, payload });
  }

  async #captureDockerContainer(): Promise<void> {
    if (this.#dockerContainerName === undefined) return;
    const inspected = await runBoundedCommand("docker", ["container", "inspect", "--format", "{{.Id}}", this.#dockerContainerName], 5_000, 4_096);
    const containerId = inspected.stdout.trim();
    if (inspected.code !== 0 || !/^[a-f0-9]{64}$/i.test(containerId)) throw new Error("Docker target container identity could not be captured");
    this.#dockerContainerId = containerId.toLowerCase();
  }
}

export class TargetCallTimeoutError extends Error {
  readonly confirmedTermination: boolean;
  constructor(confirmedTermination = true) {
    super("Target call timed out and recovery completed");
    this.name = "TargetCallTimeoutError";
    this.confirmedTermination = confirmedTermination;
  }
}

type BoundedCommandResult = { code: number | null; stdout: string; stderr: string };

async function runBoundedCommand(command: string, args: string[], timeoutMs: number, maxOutputBytes: number): Promise<BoundedCommandResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ code, stdout, stderr });
    };
    const timeout = setTimeout(() => { child.kill(); finish(null); }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      if (Buffer.byteLength(stdout, "utf8") > maxOutputBytes) child.kill();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
      if (Buffer.byteLength(stderr, "utf8") > maxOutputBytes) child.kill();
    });
    child.once("error", () => finish(null));
    child.once("close", (code) => finish(code));
  });
}

async function descendantPids(pid: number): Promise<number[] | undefined> {
  const processTable = process.platform === "win32"
    ? await runBoundedCommand("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId),$($_.ParentProcessId)\" }"], 5_000, 1_048_576)
    : await runBoundedCommand("ps", ["-eo", "pid=,ppid="], 5_000, 1_048_576);
  if (processTable.code !== 0) return undefined;
  const children = new Map<number, number[]>();
  for (const line of processTable.stdout.split(/\r?\n/)) {
    const values = process.platform === "win32" ? line.trim().split(",") : line.trim().split(/\s+/);
    const childPid = Number(values[0]);
    const parentPid = Number(values[1]);
    if (!Number.isInteger(childPid) || !Number.isInteger(parentPid)) continue;
    const known = children.get(parentPid) ?? [];
    known.push(childPid);
    children.set(parentPid, known);
  }
  const result: number[] = [];
  const pending = [pid];
  while (pending.length > 0) {
    const current = pending.shift()!;
    if (result.includes(current)) continue;
    result.push(current);
    pending.push(...(children.get(current) ?? []));
  }
  return result;
}

function processExited(pid: number): boolean {
  try { process.kill(pid, 0); return false; }
  catch { return true; }
}

async function waitForProcessExit(pids: number[], timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pids.every(processExited)) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return pids.every(processExited);
}

async function terminateProcessTree(pid: number | null): Promise<boolean> {
  if (pid === null) return false;
  const pids = await descendantPids(pid) ?? [pid];
  if (process.platform === "win32") {
    const taskkill = await runBoundedCommand("taskkill", ["/pid", String(pid), "/t", "/f"], 10_000, 8_192);
    if (taskkill.code !== 0 && !processExited(pid)) {
      // Some managed Windows endpoints deny taskkill even for a child owned by
      // the current user. Stop-Process reaches the same kernel termination
      // primitive and is a bounded fallback; we still require exit confirmation.
      const stopped = await runBoundedCommand(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", `Stop-Process -Id ${pid} -Force -ErrorAction Stop`],
        10_000,
        8_192
      );
      if (stopped.code !== 0 && !processExited(pid)) return false;
    }
    return waitForProcessExit(pids, 2_000);
  }
  for (const childPid of [...pids].reverse()) {
    try { process.kill(childPid, "SIGTERM"); } catch { /* Process already exited. */ }
  }
  if (await waitForProcessExit(pids, 750)) return true;
  for (const childPid of [...pids].reverse()) {
    try { process.kill(childPid, "SIGKILL"); } catch { /* Process already exited. */ }
  }
  return waitForProcessExit(pids, 1_500);
}

async function terminateDockerContainer(name: string, expectedId: string | undefined): Promise<boolean> {
  if (expectedId === undefined) return false;
  const inspected = await runBoundedCommand("docker", ["container", "inspect", "--format", "{{.Id}}", name], 5_000, 4_096);
  if (inspected.code !== 0 || inspected.stdout.trim().toLowerCase() !== expectedId) return false;
  const removed = await runBoundedCommand("docker", ["container", "rm", "--force", name], 10_000, 8_192);
  if (removed.code !== 0) return false;
  const verification = await runBoundedCommand("docker", ["container", "inspect", name], 5_000, 4_096);
  return verification.code !== 0;
}

type CachedDecision = { result: DeterministicResult; decision: RequestDecision; judge?: JudgeVerdict };

type SafeJudgeVerdict = Pick<JudgeVerdict, "decision" | "riskLevel" | "latencyMs" | "inputTokens" | "outputTokens" | "cached" | "offlineReplay"> & {
  model: string;
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
    model: judge.model,
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
  readonly #emit: RuntimeEventSink;
  readonly #cache = new ExactCallCache<CachedDecision>();
  readonly #inputValidators = new Map<string, ToolInputValidator>();
  readonly #judge: JudgeProvider;
  readonly #audit: AuditLog;
  readonly #clock: Clock;
  readonly #recentEvents: string[] = [];
  readonly #receiptCallIds = new Set<string>();
  readonly #receiptFinalizations = new Map<string, Promise<void>>();
  readonly #acceptedCalls = new Map<string, AcceptedCall>();
  #tools: Awaited<ReturnType<ToolBastionTargetClient["listTools"]>>["tools"] = [];
  #untrustedTools = new Set<string>();
  #inflightCalls = 0;
  #auditFailed = false;

  constructor(config: ToolBastionConfig, emit: RuntimeEventSink = () => undefined, options: { audit?: AuditLog; clock?: Clock } = {}) {
    this.#config = config;
    this.#emit = emit;
    this.#clock = options.clock ?? systemClock;
    this.#target = new ToolBastionTargetClient(config.target, (event) => this.#emitEvent(event.eventType, event.payload), async () => this.#refreshTools(true), config.limits.tool_timeout_ms, config.project_root);
    this.#judge = createJudgeProvider(config);
    this.#audit = options.audit ?? new AuditLog(
      resolveWithinProject(config.project_root, config.audit.directory, "audit.directory"),
      undefined,
      { retainRawContent: config.audit.retain_raw_content }
    );
    this.#server = new Server({ name: "toolbastion", version: TOOLBASTION_VERSION }, { capabilities: { tools: { listChanged: true } } });
    this.#server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: this.#visibleTools() }));
    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => this.#handleCall(request.params.name, request.params.arguments ?? {}));
  }

  async runStdio(): Promise<void> {
    if (this.#config.receipts.signingRequired) {
      const privateKeyPem = process.env.TOOLBASTION_RECEIPT_PRIVATE_KEY;
      if (!privateKeyPem) throw new Error("Receipt signing is required but TOOLBASTION_RECEIPT_PRIVATE_KEY is unavailable");
      const privateKey = createPrivateKey(privateKeyPem);
      if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Receipt signing requires an Ed25519 private key");
    }
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
      const artifactIdentity = await resolveTargetArtifactIdentity(this.#config.target, this.#config.project_root);
      diff = diffTrustBaseline(await readTrustBaseline(baselinePath), this.#tools, this.#config.capabilities.tools, this.#config.target.name, artifactIdentity);
    } catch (error) {
      diff = { added: this.#tools.map((tool) => tool.name), removed: [], schemaChanged: [], descriptionChanged: [], capabilityChanged: [], poisoned: [], unchanged: [], artifactChanged: true };
      this.#emitEvent("trust_verified", { approved: false, error: error instanceof Error ? error.message : "baseline unavailable", diff });
    }
    const oversizedMetadata = this.#tools
      .filter((tool) => findValueBoundsViolation({ description: tool.description ?? "", inputSchema: tool.inputSchema }, { maxBytes: this.#config.limits.max_tool_metadata_bytes, maxDepth: 32, maxNodes: 10_000 }) !== undefined)
      .map((tool) => tool.name);
    this.#untrustedTools = new Set([
      ...(diff.artifactChanged ? this.#tools.map((tool) => tool.name) : []),
      ...diff.added, ...diff.schemaChanged, ...diff.descriptionChanged, ...diff.capabilityChanged, ...diff.poisoned, ...oversizedMetadata
    ]);
    this.#emitEvent("trust_verified", { approved: this.#untrustedTools.size === 0, diff, oversizedMetadata });
    this.#cache.clear();
    this.#inputValidators.clear();
    if (notifyDownstream) await this.#server.sendToolListChanged();
  }

  #visibleTools() {
    return this.#config.mode === "shadow" ? this.#tools : this.#tools.filter((tool) => !this.#untrustedTools.has(tool.name));
  }

  async #handleCall(toolName: string, args: Record<string, unknown>) {
    const accepted = this.#acceptCall(toolName, args);
    if (this.#config.mode === "enforce" && this.#auditFailed) return this.#preDispatchAuditUnavailable(toolName, {}, accepted);
    if (this.#inflightCalls >= this.#config.limits.max_inflight_calls) {
      return this.#blocked(toolName, "too_many_inflight_calls", ["The target call queue is full"], {
        ...accepted,
        deterministicEvidence: [{ category: "too_many_inflight_calls", severity: "high" }]
      });
    }
    this.#inflightCalls += 1;
    try {
      return await this.#handleCallInner(toolName, args, accepted);
    } finally {
      this.#inflightCalls -= 1;
    }
  }

  async #handleCallInner(toolName: string, args: Record<string, unknown>, accepted: AcceptedCall) {
    const { callId, argsHash, policyHash } = accepted;
    const boundsViolation = findValueBoundsViolation(args, {
      maxBytes: this.#config.limits.max_argument_bytes,
      maxDepth: this.#config.limits.max_argument_depth,
      maxNodes: this.#config.limits.max_argument_nodes
    });
    if (boundsViolation) {
      const lifecycle = this.#callLifecycle({ callId, toolName, argsHash, policyHash, authorizationDecision: "BLOCK_BEFORE_EXECUTION", executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED" });
      this.#emitEvent("tool_call_received", { ...lifecycle, argumentBoundsViolation: boundsViolation });
      if (!await this.#appendAudit("tool_call_received", { ...lifecycle, argumentBoundsViolation: boundsViolation })) {
        if (this.#config.mode === "enforce") return this.#preDispatchAuditUnavailable(toolName, lifecycle);
      }
      return this.#blocked(toolName, "argument_bounds_exceeded", [boundsViolation], {
        callId,
        deterministicEvidence: [{ category: boundsViolation, severity: "high" }]
      });
    }
    const receivedLifecycle = this.#receivedLifecycle(callId, toolName, argsHash, policyHash);
    this.#emitEvent("tool_call_received", receivedLifecycle);
    if (!await this.#appendAudit("tool_call_received", receivedLifecycle)) {
      if (this.#config.mode === "enforce") return this.#preDispatchAuditUnavailable(toolName, receivedLifecycle);
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
    const context = this.#config.judge.enabled ? await loadJudgeContext(this.#config) : { status: "unavailable" as const, reason: "judge_disabled" };
    const fingerprint = this.#cache.fingerprint({ targetName: this.#config.target.name, toolName, schemaHash, policyHash, args, mode: this.#config.mode, contextHash: sha256(context) });
    let cached = this.#config.cache.enabled ? this.#cache.get(fingerprint) : undefined;
    const cacheHit = cached !== undefined;
    if (!cached) {
      const result = await evaluateDeterministic(toolName, args, this.#config);
      let decision = applyRuntimeMode(result, this.#config.mode);
      let judge: JudgeVerdict | undefined;
      if (result.resolution === "AMBIGUOUS" && this.#config.judge.enabled) {
        const toolMetadataIntegrity: "verified" | "untrusted" | "unavailable" = tool === undefined ? "unavailable" : this.#untrustedTools.has(toolName) ? "untrusted" : "verified";
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
          toolMetadataIntegrity,
          targetEgress: this.#config.network.target_egress,
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
    this.#emitEvent("policy_evaluated", { toolName, argsHash, deterministic: cached.result, judge: safeJudge, cacheHit, reasonCodes: cached.result.reasonCodes });
    const authorizationDecision: AuthorizationDecision = cached.decision === "ALLOW" ? "ALLOW" : cached.decision === "ASK_USER" ? "ASK_USER" : "BLOCK_BEFORE_EXECUTION";
    const authorizationLifecycle = this.#callLifecycle({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision, executionState: "NOT_DISPATCHED", outputDecision: "NOT_INSPECTED" });
    this.#emitEvent("authorization_completed", { ...authorizationLifecycle, deterministic: cached.result, judge: safeJudge, cacheHit, reasonCodes: cached.result.reasonCodes });
    if (!await this.#appendAudit("authorization_completed", { ...authorizationLifecycle, deterministic: cached.result, judge: safeJudge, contextStatus: context.status, contextReason: context.reason })) {
      if (this.#config.mode === "enforce") return this.#preDispatchAuditUnavailable(toolName, authorizationLifecycle);
    }
    const blockedContext = { callId, argsHash, schemaHash, policyHash, deterministicEvidence: cached.result.evidence, ...(safeJudge === undefined ? {} : { judgeVerdict: safeJudge }) };
    if (cached.decision === "BLOCK") return this.#blocked(toolName, "deterministic_block", cached.result.reasonCodes, blockedContext);
    if (cached.decision === "ASK_USER") {
      return this.#blocked(toolName, "operator_approval_required", cached.result.reasonCodes, blockedContext);
    }
    let result: Awaited<ReturnType<ToolBastionTargetClient["callTool"]>>;
    const dispatchLifecycle = this.#callLifecycle({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision: "ALLOW", executionState: "DISPATCHED", outputDecision: "NOT_INSPECTED" });
    this.#emitEvent("tool_dispatch_started", dispatchLifecycle);
    if (!await this.#appendAudit("tool_dispatch_started", dispatchLifecycle) && this.#config.mode === "enforce") return this.#preDispatchAuditUnavailable(toolName, dispatchLifecycle);
    try {
      result = await this.#target.callTool(toolName, args);
    } catch (error) {
      const timedOut = error instanceof TargetCallTimeoutError;
      const executionState: ExecutionState = timedOut ? error.confirmedTermination ? "TIMED_OUT" : "UNKNOWN" : "FAILED";
      const lifecycle = this.#callLifecycle({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision: "ALLOW", executionState, outputDecision: "NOT_INSPECTED" });
      const reason = timedOut ? executionState === "UNKNOWN" ? "target_outcome_unknown" : "target_call_timed_out" : error instanceof Error ? error.name : "target_call_failed";
      this.#emitEvent(timedOut ? "tool_dispatch_timed_out" : "tool_dispatch_failed", { ...lifecycle, reason });
      if (!await this.#appendAudit(timedOut ? "tool_dispatch_timed_out" : "tool_dispatch_failed", { ...lifecycle, reason }) && this.#config.mode === "enforce") return this.#postDispatchUnavailable(toolName, lifecycle);
      this.#emitEvent("call_completed", { ...lifecycle, reason });
      if (!await this.#appendAudit("call_completed", { ...lifecycle, reason }) && this.#config.mode === "enforce") return this.#postDispatchUnavailable(toolName, lifecycle);
      await this.#writeFinalReceipt({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision: "ALLOW", executionState, outputDecision: "NOT_INSPECTED", judge: safeJudge });
      return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ authorizationDecision: "ALLOW", executionState, outputDecision: "NOT_INSPECTED", reason }) }] };
    }
    const completedLifecycle = this.#callLifecycle({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "NOT_INSPECTED" });
    this.#emitEvent("tool_dispatch_completed", completedLifecycle);
    if (!await this.#appendAudit("tool_dispatch_completed", completedLifecycle) && this.#config.mode === "enforce") return this.#postDispatchUnavailable(toolName, completedLifecycle);
    if (!this.#config.outputs.inspect) {
      this.#emitEvent("call_completed", completedLifecycle);
      if (!await this.#appendAudit("call_completed", completedLifecycle) && this.#config.mode === "enforce") return this.#postDispatchUnavailable(toolName, completedLifecycle);
      await this.#writeFinalReceipt({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "NOT_INSPECTED", judge: safeJudge });
      return result;
    }
    const inspection = inspectToolResult(result, this.#config);
    const outputLifecycle = this.#callLifecycle({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: inspection.decision });
    this.#emitEvent("output_inspected", { ...outputLifecycle, riskLevel: inspection.riskLevel, evidence: inspection.evidence, redactions: inspection.redactions.length, quarantineId: inspection.quarantineId });
    if (!await this.#appendAudit("output_inspected", { ...outputLifecycle, riskLevel: inspection.riskLevel, evidence: inspection.evidence, redactions: inspection.redactions, quarantineId: inspection.quarantineId })) {
      if (this.#config.mode === "enforce") return this.#postDispatchUnavailable(toolName, outputLifecycle);
    }
    if (inspection.decision === "QUARANTINE") {
      this.#emitEvent("call_completed", outputLifecycle);
      if (!await this.#appendAudit("call_completed", outputLifecycle) && this.#config.mode === "enforce") return this.#postDispatchUnavailable(toolName, outputLifecycle);
      await this.#writeFinalReceipt({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: "QUARANTINE", judge: safeJudge });
      return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ decision: "QUARANTINE", reason: "unsafe_tool_output", evidence: inspection.evidence.map((item) => item.category), quarantineId: inspection.quarantineId }) }] };
    }
    this.#emitEvent("call_completed", outputLifecycle);
    if (!await this.#appendAudit("call_completed", outputLifecycle) && this.#config.mode === "enforce") return this.#postDispatchUnavailable(toolName, outputLifecycle);
    await this.#writeFinalReceipt({ callId, toolName, argsHash, schemaHash, policyHash, authorizationDecision: "ALLOW", executionState: "COMPLETED", outputDecision: inspection.decision, judge: safeJudge });
    return inspection.sanitizedResult as typeof result;
  }

  #callLifecycle(input: {
    callId: string;
    toolName: string;
    argsHash?: string;
    schemaHash?: string;
    policyHash?: string;
    authorizationDecision: AuthorizationDecision;
    executionState: ExecutionState;
    outputDecision: OutputDecision;
  }): Record<string, unknown> {
    return {
      sessionId: this.#audit.sessionId,
      callId: input.callId,
      toolName: input.toolName,
      ...(input.argsHash === undefined ? {} : { argsHash: input.argsHash }),
      ...(input.schemaHash === undefined ? {} : { schemaHash: input.schemaHash }),
      ...(input.policyHash === undefined ? {} : { policyHash: input.policyHash }),
      authorizationDecision: input.authorizationDecision,
      executionState: input.executionState,
      outputDecision: input.outputDecision
    };
  }

  #receivedLifecycle(callId: string, toolName: string, argsHash: string, policyHash: string): Record<string, unknown> {
    return {
      sessionId: this.#audit.sessionId,
      callId,
      toolName,
      argsHash,
      policyHash,
      executionState: "NOT_DISPATCHED",
      outputDecision: "NOT_INSPECTED"
    };
  }

  #acceptCall(toolName: string, args: Record<string, unknown>): AcceptedCall {
    const accepted: AcceptedCall = {
      callId: randomUUID(),
      toolName,
      argsHash: sha256(args),
      policyHash: sha256(this.#config),
      timing: new ReceiptTiming(this.#clock),
      startedAt: ""
    };
    accepted.startedAt = accepted.timing.startedAt;
    this.#acceptedCalls.set(accepted.callId, accepted);
    return accepted;
  }

  async #writeFinalReceipt(input: { callId: string; toolName: string; argsHash?: string; schemaHash?: string; policyHash?: string; authorizationDecision: AuthorizationDecision; executionState: ExecutionState; outputDecision: OutputDecision; judge: SafeJudgeVerdict | undefined }): Promise<void> {
    if (this.#receiptCallIds.has(input.callId)) return;
    const pending = this.#receiptFinalizations.get(input.callId);
    if (pending !== undefined) return pending;
    const operation = (async () => {
      if (!this.#config.receipts.enabled) return;
      const accepted = this.#acceptedCalls.get(input.callId);
      if (!accepted) throw new Error("Receipt finalization was attempted for a call that was not accepted");
      const unsigned = {
        version: 1 as const,
        sessionId: this.#audit.sessionId,
        callId: input.callId,
        toolName: input.toolName,
        toolManifestHash: sha256(this.#tools.map((tool) => ({ name: tool.name, description: tool.description ?? "", inputSchema: tool.inputSchema }))),
        schemaHash: input.schemaHash ?? sha256({}),
        policyHash: input.policyHash ?? accepted.policyHash,
        argsHash: input.argsHash ?? accepted.argsHash,
        authorizationDecision: input.authorizationDecision,
        executionState: input.executionState,
        outputDecision: input.outputDecision,
        ...(input.judge === undefined ? {} : { judge: { requestedModel: this.#config.judge.model, responseModel: input.judge.model, offlineReplay: input.judge.offlineReplay, subchecks: input.judge.subchecks, inputTokens: input.judge.inputTokens ?? 0, outputTokens: input.judge.outputTokens ?? 0, latencyMs: input.judge.latencyMs } }),
        startedAt: accepted.startedAt,
        completedAt: accepted.timing.complete()
      };
      const receipt = process.env.TOOLBASTION_RECEIPT_PRIVATE_KEY
        ? signReceipt(unsigned)
        : bastionReceiptSchema.parse({ ...unsigned, signatureStatus: "unsigned" });
      await writeReceiptFile(this.#config.project_root, this.#config.receipts.directory, receipt);
    })();
    this.#receiptFinalizations.set(input.callId, operation);
    try {
      await operation;
      this.#receiptCallIds.add(input.callId);
      this.#acceptedCalls.delete(input.callId);
    } finally {
      if (this.#receiptFinalizations.get(input.callId) === operation) this.#receiptFinalizations.delete(input.callId);
    }
  }

  async #preDispatchAuditUnavailable(toolName: string, lifecycle: Record<string, unknown> = {}, accepted?: AcceptedCall) {
    const authorizationDecision = lifecycle.authorizationDecision === "ALLOW" || lifecycle.authorizationDecision === "ASK_USER" || lifecycle.authorizationDecision === "BLOCK_BEFORE_EXECUTION"
      ? lifecycle.authorizationDecision
      : "BLOCK_BEFORE_EXECUTION";
    const response = {
      ...(accepted === undefined ? {} : { callId: accepted.callId, argsHash: accepted.argsHash, policyHash: accepted.policyHash }),
      ...lifecycle,
      toolName,
      authorizationDecision,
      executionState: "NOT_DISPATCHED",
      evidenceState: "UNAVAILABLE",
      outputDecision: "NOT_RELEASED",
      reason: "audit_unavailable_before_execution"
    };
    this.#emitEvent("audit_failed", response);
    const callId = typeof response.callId === "string" ? response.callId : undefined;
    if (callId !== undefined) {
      await this.#writeFinalReceipt({
        callId,
        toolName,
        authorizationDecision,
        executionState: "NOT_DISPATCHED",
        outputDecision: "NOT_INSPECTED",
        judge: undefined
      });
    }
    return { isError: true, content: [{ type: "text" as const, text: JSON.stringify(response) }] };
  }

  async #postDispatchUnavailable(toolName: string, lifecycle: Record<string, unknown>) {
    const authorizationDecision = lifecycle.authorizationDecision === "ALLOW" || lifecycle.authorizationDecision === "ASK_USER" || lifecycle.authorizationDecision === "BLOCK_BEFORE_EXECUTION"
      ? lifecycle.authorizationDecision
      : "ALLOW";
    const executionState = lifecycle.executionState === "COMPLETED" || lifecycle.executionState === "FAILED" || lifecycle.executionState === "TIMED_OUT" || lifecycle.executionState === "UNKNOWN"
      ? lifecycle.executionState
      : "UNKNOWN";
    const response = {
      ...lifecycle,
      toolName,
      authorizationDecision,
      executionState,
      evidenceState: "UNAVAILABLE",
      outputDecision: "NOT_RELEASED",
      reason: "audit_unavailable_after_execution"
    };
    this.#emitEvent("call_completed", response);
    const callId = typeof lifecycle.callId === "string" ? lifecycle.callId : undefined;
    if (callId !== undefined) {
      await this.#writeFinalReceipt({
        callId,
        toolName,
        authorizationDecision,
        executionState,
        outputDecision: "NOT_RELEASED",
        judge: undefined
      });
    }
    return { isError: true, content: [{ type: "text" as const, text: JSON.stringify(response) }] };
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

  async #blocked(toolName: string, reason: string, evidence: string[], context?: { callId: string; argsHash?: string; schemaHash?: string; policyHash?: string; deterministicEvidence: unknown; judgeVerdict?: SafeJudgeVerdict }) {
    const eventId = randomUUID();
    const lifecycle = context === undefined ? {} : this.#callLifecycle({
      callId: context.callId,
      toolName,
      ...(context.argsHash === undefined ? {} : { argsHash: context.argsHash }),
      ...(context.schemaHash === undefined ? {} : { schemaHash: context.schemaHash }),
      ...(context.policyHash === undefined ? {} : { policyHash: context.policyHash }),
      authorizationDecision: reason === "operator_approval_required" ? "ASK_USER" : "BLOCK_BEFORE_EXECUTION",
      executionState: "NOT_DISPATCHED",
      outputDecision: "NOT_INSPECTED"
    });
    this.#emitEvent("call_blocked", { ...lifecycle, toolName, reason, evidence, eventId });
    if (!await this.#appendAudit("call_blocked", { ...lifecycle, toolName, reason, evidence, eventId, ...context }) && this.#config.mode === "enforce") {
      return this.#preDispatchAuditUnavailable(toolName, lifecycle);
    }
    if (context !== undefined) {
      await this.#writeFinalReceipt({
        callId: context.callId,
        toolName,
        ...(context.argsHash === undefined ? {} : { argsHash: context.argsHash }),
        ...(context.schemaHash === undefined ? {} : { schemaHash: context.schemaHash }),
        ...(context.policyHash === undefined ? {} : { policyHash: context.policyHash }),
        authorizationDecision: reason === "operator_approval_required" ? "ASK_USER" : "BLOCK_BEFORE_EXECUTION",
        executionState: "NOT_DISPATCHED",
        outputDecision: "NOT_INSPECTED",
        judge: context.judgeVerdict
      });
    }
    return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ decision: reason === "operator_approval_required" ? "ASK_USER" : "BLOCK", reason, evidence, eventId }) }] };
  }

  async #appendAudit(eventType: string, payload: Record<string, unknown>): Promise<boolean> {
    try {
      await this.#audit.append(eventType, payload);
      return true;
    } catch {
      this.#auditFailed = true;
      this.#emitEvent("audit_failed", { eventType, reason: "audit_write_failed", reasonCodes: ["audit_write_failed"], evidenceState: "UNAVAILABLE" });
      return false;
    }
  }

  #emitEvent(eventType: RuntimeEventType, payload: Record<string, unknown>): void {
    this.#recentEvents.push(eventType);
    if (this.#recentEvents.length > 20) this.#recentEvents.shift();
    this.#emit(sanitizeRuntimeEvent({
      eventId: randomUUID(),
      sessionId: this.#audit.sessionId,
      timestamp: new Date().toISOString(),
      eventType,
      payload,
      ...(payload.judge === undefined ? {} : { judgeRequestedModel: this.#config.judge.model })
    }));
  }
}
