import { mkdir, readFile, writeFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import path from "node:path";
import { inspectArguments, highestRisk } from "@toolbastion/detectors";
import {
  canonicalJson,
  capabilityContractSchema,
  deterministicResultSchema,
  sha256,
  targetArtifactIdentitySchema,
  TOOLBASTION_VERSION,
  type CapabilityContract,
  type DetectionEvidence,
  type DeterministicResult,
  type RequestDecision,
  type RuntimeMode,
  type TargetArtifactIdentity,
  type ToolBastionConfig
} from "@toolbastion/shared";
import { z } from "zod";

function scopedResources(value: unknown, key = ""): string[] {
  if (typeof value === "string") return /(?:path|file|directory|folder|cwd|destination|url|uri|endpoint|host|hostname|address)$/i.test(key) ? [value] : [];
  if (Array.isArray(value)) return value.flatMap((item) => scopedResources(item, key));
  if (value !== null && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([childKey, child]) => scopedResources(child, childKey));
  }
  return [];
}

type FilesystemIntent = { access: boolean; write: boolean; destructive: boolean };

function looksLikeFilesystemValue(value: string): boolean {
  const normalized = value.trim().replaceAll("\\", "/");
  return normalized.startsWith("/")
    || /^[a-z]:\//i.test(normalized)
    || normalized.startsWith("../")
    || normalized.startsWith("./")
    || normalized.startsWith("file://")
    || /%2e|%2f|%5c/i.test(normalized)
    || /(?:^|[/])(?:\.env|\.ssh|\.aws|\.azure|id_rsa|credentials(?:\.json)?)(?:[/]|$)/i.test(normalized)
    || /(?:readFile|writeFile|appendFile|unlink|rename|mkdir|rmdir|readdir|open)\s*\(/i.test(value);
}

function filesystemIntent(toolName: string, value: unknown, key = ""): FilesystemIntent {
  const tool = toolName.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();
  const normalizedKey = key.toLowerCase();
  const text = typeof value === "string" ? value : "";
  const accessKey = /(?:path|file|directory|folder|cwd|destination|source|filename|pathname|mount|workspace)/.test(normalizedKey);
  const writeKey = /(?:write|save|append|create|update|edit|output|new[_-]?path|target[_-]?path|rename|move|delete|remove|unlink|mkdir|rmdir|truncate|chmod)/.test(normalizedKey);
  const writeTool = /(?:write|save|create|update|edit|delete|remove|unlink|rename|move|mkdir|rmdir|truncate|chmod|touch|append)/.test(tool);
  const commandTool = /(?:command|shell|exec|run|script)/.test(tool);
  const destructive = /(?:delete|remove|unlink|rename|move|rmdir|truncate|chmod|rm\s+-rf|rmdir\s+\/s|remove-item\s+.*-recurse|format\s+[a-z]:)/i.test(`${tool} ${normalizedKey} ${text}`);
  const write = writeKey || writeTool || /(?:>|>>|\b(?:cp|mv|rm|rmdir|del|remove-item|mkdir|touch|chmod)\b|(?:writeFile|appendFile|unlink|rename|mkdir)\s*\()/i.test(text);
  const access = accessKey || writeKey || writeTool || looksLikeFilesystemValue(text) || (commandTool && text.length > 0);
  return { access, write, destructive };
}

function collectFilesystemIntent(toolName: string, value: unknown, key = ""): FilesystemIntent {
  const current = filesystemIntent(toolName, value, key);
  if (Array.isArray(value)) return value.reduce<FilesystemIntent>((intent, child, index) => mergeFilesystemIntent(intent, collectFilesystemIntent(toolName, child, `${key}.${index}`)), current);
  if (value !== null && typeof value === "object") return Object.entries(value as Record<string, unknown>).reduce<FilesystemIntent>((intent, [childKey, child]) => mergeFilesystemIntent(intent, collectFilesystemIntent(toolName, child, childKey)), current);
  return current;
}

function mergeFilesystemIntent(left: FilesystemIntent, right: FilesystemIntent): FilesystemIntent {
  return { access: left.access || right.access, write: left.write || right.write, destructive: left.destructive || right.destructive };
}

function filesystemPathValues(value: unknown, key = ""): Array<{ value: string; key: string }> {
  if (typeof value === "string") {
    return /(?:path|file|directory|folder|cwd|destination|source|filename|pathname|mount|workspace)/i.test(key) ? [{ value, key }] : [];
  }
  if (Array.isArray(value)) return value.flatMap((child) => filesystemPathValues(child, key));
  if (value !== null && typeof value === "object") return Object.entries(value as Record<string, unknown>).flatMap(([childKey, child]) => filesystemPathValues(child, childKey));
  return [];
}

function insideDirectory(root: string, candidate: string): boolean {
  const normalizeCase = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
  const relative = path.relative(normalizeCase(root), normalizeCase(candidate));
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

async function writableScopeFindings(args: Record<string, unknown>, config: ToolBastionConfig): Promise<DetectionEvidence[]> {
  const contract = config.capabilities.tools;
  const paths = config.target.isolation.provider === "docker" ? config.target.isolation.writable_paths : [];
  if (paths.length === 0 || !Object.values(contract).some((value) => value.filesystem === "write")) return [];
  const root = await realpath(path.resolve(config.project_root)).catch(() => path.resolve(config.project_root));
  const scopes = await Promise.all(paths.map(async (scope) => ({ scope, canonical: await realpath(path.resolve(root, scope)).catch(() => path.resolve(root, scope)) })));
  const findings: DetectionEvidence[] = [];
  for (const { value, key } of filesystemPathValues(args)) {
    let decoded = value;
    for (let index = 0; index < 2; index += 1) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch { break; }
    }
    const candidate = path.resolve(root, decoded.replaceAll("\\", "/").split("/").join(path.sep));
    const parent = await realpath(path.dirname(candidate)).catch(() => path.dirname(candidate));
    const canonicalCandidate = path.join(parent, path.basename(candidate));
    if (!scopes.some(({ canonical }) => insideDirectory(canonical, canonicalCandidate))) {
      findings.push({ detector: "capability", category: "filesystem_write_outside_scope", severity: "critical", message: "Write target is outside every declared writable containment path", fieldPath: `args.${key}`, redactedValue: "[REDACTED]" });
    }
  }
  return findings;
}

function capabilityFindings(toolName: string, config: ToolBastionConfig) {
  const contract = config.capabilities.tools[toolName];
  if (!contract) {
    return [{ detector: "capability", category: "missing_capability_contract", severity: "critical" as const, message: "Tool has no operator-approved capability contract" }];
  }
  if (config.mode !== "enforce") return [];
  if (contract.network === "allowlist") {
    return [{ detector: "capability", category: "network_allowlist_unsupported", severity: "critical" as const, message: "Enforce mode does not provide an authenticated allowlisted egress proxy" }];
  }
  const requiresContainment = contract.network === "deny" || contract.command_exec || contract.subprocess || contract.destructive;
  if (requiresContainment && config.target.isolation.provider !== "docker") {
    return [{ detector: "capability", category: "capability_containment_required", severity: "critical" as const, message: "Declared network, command, subprocess, or destructive capability requires Docker containment in enforce mode" }];
  }
  return [];
}

export async function evaluateDeterministic(toolName: string, args: Record<string, unknown>, config: ToolBastionConfig): Promise<DeterministicResult> {
  const findings = await inspectArguments(toolName, args, config);
  findings.push(...capabilityFindings(toolName, config));
  const contract = config.capabilities.tools[toolName];
  if (contract !== undefined && config.mode === "enforce") {
    const intent = collectFilesystemIntent(toolName, args);
    if (intent.access && contract.filesystem === "none") {
      findings.push({ detector: "capability", category: "filesystem_access_not_declared", severity: "critical", message: "Tool arguments request filesystem access but the approved contract is filesystem:none" });
    }
    if (intent.write && contract.filesystem !== "write") {
      findings.push({ detector: "capability", category: "filesystem_write_not_declared", severity: "critical", message: "Tool arguments request filesystem writes but the approved contract is not write-capable" });
    }
    if (intent.destructive && (!contract.destructive || contract.filesystem !== "write")) {
      findings.push({ detector: "capability", category: "filesystem_destructive_not_declared", severity: "critical", message: "Destructive filesystem operation requires both filesystem:write and destructive:true" });
    }
    if (contract.filesystem === "write" && (config.target.isolation.provider !== "docker" || config.target.isolation.writable_paths.length === 0)) {
      findings.push({ detector: "capability", category: "filesystem_write_containment_required", severity: "critical", message: "filesystem:write requires a narrowly scoped Docker writable mount" });
    }
    if (contract.filesystem === "write") findings.push(...await writableScopeFindings(args, config));
  }
  const rule = config.tools.rules[toolName];
  const action = rule?.action ?? config.tools.default;
  if (action === "block") {
    findings.push({ detector: "policy", category: "tool_blocked_by_policy", severity: "critical", message: "Tool is explicitly blocked by policy" });
  }
  if (action === "allow_when_in_scope") {
    const resources = scopedResources(args);
    if (resources.length === 0) {
      findings.push({ detector: "policy", category: "scope_required", severity: "high", message: "allow_when_in_scope requires an identifiable project path resource" });
    }
  }
  const riskLevel = highestRisk(findings);
  const hardDeny = findings.some((item) => item.severity === "high" || item.severity === "critical");
  const unresolved = !hardDeny && action === "judge";
  return deterministicResultSchema.parse({
    resolution: hardDeny ? "HARD_DENY" : unresolved ? "AMBIGUOUS" : "SAFE",
    riskLevel: hardDeny ? riskLevel : unresolved ? (rule?.base_risk ?? "medium") : riskLevel,
    evidence: findings,
    reasonCodes: findings.map((item) => item.category).concat(unresolved ? ["semantic_judgment_required"] : [])
  });
}

export function applyRuntimeMode(result: DeterministicResult, mode: RuntimeMode): RequestDecision {
  if (mode === "shadow") return "ALLOW";
  if (result.resolution === "HARD_DENY") return "BLOCK";
  if (result.resolution === "AMBIGUOUS") return mode === "interactive" ? "ASK_USER" : "BLOCK";
  return "ALLOW";
}

type CacheEntry<T> = { value: T; expiresAt: number };

export class ExactCallCache<T> {
  readonly #entries = new Map<string, CacheEntry<T>>();
  hits = 0;
  misses = 0;

  fingerprint(input: { targetName: string; toolName: string; schemaHash: string; policyHash: string; args: Record<string, unknown>; mode: RuntimeMode; contextHash?: string }): string {
    return sha256(input);
  }

  get(key: string): T | undefined {
    const entry = this.#entries.get(key);
    if (!entry || entry.expiresAt <= Date.now()) {
      this.#entries.delete(key);
      this.misses += 1;
      return undefined;
    }
    this.hits += 1;
    return entry.value;
  }

  set(key: string, value: T, ttlSeconds: number): void {
    this.#entries.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  clear(): void { this.#entries.clear(); }
}

const baselineToolSchema = z.object({
  name: z.string(),
  description: z.string(),
  inputSchema: z.record(z.string(), z.unknown()),
  schemaHash: z.string(),
  descriptionHash: z.string(),
  riskClassification: z.string(),
  capabilities: capabilityContractSchema
});

export const trustBaselineSchema = z.object({
  version: z.literal(3),
  targetName: z.string(),
  toolbastionVersion: z.string(),
  artifactIdentity: targetArtifactIdentitySchema,
  createdAt: z.string(),
  tools: z.array(baselineToolSchema),
  baselineHash: z.string()
});
export type TrustBaseline = z.infer<typeof trustBaselineSchema>;

export type ListedTool = { name: string; description?: string | undefined; inputSchema: Record<string, unknown> };
export type CapabilityDeclarations = Record<string, CapabilityContract>;

function assertUniqueToolNames(tools: Array<{ name: string }>, label: string): void {
  const names = new Set<string>();
  for (const tool of tools) {
    if (names.has(tool.name)) throw new Error(`${label} contains duplicate tool name: ${tool.name}`);
    names.add(tool.name);
  }
}

function metadataPoisoned(description: string): boolean {
  return /ignore (?:all |any )?(?:previous|prior|system)|(?:read|send|upload).*(?:credential|\.env|secret)|contact external|bypass.*(?:policy|rule)/i.test(description);
}

function requiredCapabilities(toolName: string, capabilities: CapabilityDeclarations): CapabilityContract {
  const contract = capabilities[toolName];
  if (!contract) throw new Error(`Tool ${toolName} is missing a capability contract; use trust migrate or trust approve after declaring capabilities.tools.${toolName}`);
  return capabilityContractSchema.parse(contract);
}

function fallbackArtifactIdentity(targetName: string, tools: ListedTool[]): TargetArtifactIdentity {
  const buildHash = sha256(tools.map((tool) => ({ name: tool.name, description: tool.description ?? "", inputSchema: tool.inputSchema })));
  return {
    kind: "executable",
    executablePath: `unbound:${targetName}`,
    executableHash: sha256({ targetName }),
    buildHash
  };
}

export function createTrustBaseline(targetName: string, tools: ListedTool[], capabilities: CapabilityDeclarations, artifactIdentityOrNow?: TargetArtifactIdentity | Date, maybeNow = new Date()): TrustBaseline {
  assertUniqueToolNames(tools, "Current tool inventory");
  const artifactIdentity = artifactIdentityOrNow instanceof Date || artifactIdentityOrNow === undefined
    ? fallbackArtifactIdentity(targetName, tools)
    : artifactIdentityOrNow;
  const now = artifactIdentityOrNow instanceof Date ? artifactIdentityOrNow : maybeNow;
  const normalizedTools = tools.map((tool) => {
    const description = tool.description ?? "";
    return {
      name: tool.name,
      description,
      inputSchema: JSON.parse(canonicalJson(tool.inputSchema)) as Record<string, unknown>,
      schemaHash: sha256(tool.inputSchema),
      descriptionHash: sha256(description),
      riskClassification: metadataPoisoned(description) ? "critical" : "unclassified",
      capabilities: requiredCapabilities(tool.name, capabilities)
    };
  }).sort((left, right) => left.name.localeCompare(right.name));
  const unsigned = { version: 3 as const, targetName, toolbastionVersion: TOOLBASTION_VERSION, artifactIdentity, createdAt: now.toISOString(), tools: normalizedTools };
  return { ...unsigned, baselineHash: sha256(unsigned) };
}

export function verifyTrustBaseline(input: unknown): TrustBaseline {
  if (z.object({ version: z.literal(1) }).passthrough().safeParse(input).success) {
    throw new Error("Trust baseline v1 does not contain capability contracts; run trust migrate --yes after reviewing declared capabilities");
  }
  if (z.object({ version: z.literal(2) }).passthrough().safeParse(input).success) {
    throw new Error("Trust baseline v2 is missing target artifact identity; run trust migrate --yes after reviewing the target artifact");
  }
  const baseline = trustBaselineSchema.parse(input);
  assertUniqueToolNames(baseline.tools, "Trust baseline");
  const { baselineHash, ...unsigned } = baseline;
  if (sha256(unsigned) !== baselineHash) throw new Error("Trust baseline hash is invalid; the file may have been edited");
  return baseline;
}

export type TrustDiff = {
  added: string[];
  removed: string[];
  schemaChanged: string[];
  descriptionChanged: string[];
  capabilityChanged: string[];
  artifactChanged: boolean;
  poisoned: string[];
  unchanged: string[];
};

export function diffTrustBaseline(baseline: TrustBaseline, tools: ListedTool[], capabilities: CapabilityDeclarations, expectedTargetName?: string, artifactIdentity?: TargetArtifactIdentity): TrustDiff {
  verifyTrustBaseline(baseline);
  if (expectedTargetName !== undefined && baseline.targetName !== expectedTargetName) {
    throw new Error(`Trust baseline target does not match configured target: ${baseline.targetName}`);
  }
  assertUniqueToolNames(tools, "Current tool inventory");
  const current = new Map(createTrustBaseline(baseline.targetName, tools, capabilities).tools.map((tool) => [tool.name, tool]));
  const approved = new Map(baseline.tools.map((tool) => [tool.name, tool]));
  const result: TrustDiff = {
    added: [], removed: [], schemaChanged: [], descriptionChanged: [], capabilityChanged: [], poisoned: [], unchanged: [],
    artifactChanged: artifactIdentity === undefined ? false : canonicalJson(artifactIdentity) !== canonicalJson(baseline.artifactIdentity)
  };
  for (const [name, tool] of current) {
    const prior = approved.get(name);
    if (!prior) result.added.push(name);
    else if (tool.schemaHash !== prior.schemaHash) result.schemaChanged.push(name);
    else if (tool.descriptionHash !== prior.descriptionHash) result.descriptionChanged.push(name);
    else if (canonicalJson(tool.capabilities) !== canonicalJson(prior.capabilities)) result.capabilityChanged.push(name);
    else result.unchanged.push(name);
    if (tool.riskClassification === "critical") result.poisoned.push(name);
  }
  for (const name of approved.keys()) if (!current.has(name)) result.removed.push(name);
  return result;
}

export async function writeTrustBaseline(filePath: string, baseline: TrustBaseline): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(baseline, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

export async function readTrustBaseline(filePath: string): Promise<TrustBaseline> {
  return verifyTrustBaseline(JSON.parse(await readFile(filePath, "utf8")));
}
