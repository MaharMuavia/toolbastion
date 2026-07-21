import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { inspectArguments, highestRisk } from "@toolbastion/detectors";
import {
  canonicalJson,
  capabilityContractSchema,
  deterministicResultSchema,
  sha256,
  TOOLBASTION_VERSION,
  type CapabilityContract,
  type DeterministicResult,
  type RequestDecision,
  type RuntimeMode,
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
  version: z.literal(2),
  targetName: z.string(),
  toolbastionVersion: z.string(),
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

export function createTrustBaseline(targetName: string, tools: ListedTool[], capabilities: CapabilityDeclarations, now = new Date()): TrustBaseline {
  assertUniqueToolNames(tools, "Current tool inventory");
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
  const unsigned = { version: 2 as const, targetName, toolbastionVersion: TOOLBASTION_VERSION, createdAt: now.toISOString(), tools: normalizedTools };
  return { ...unsigned, baselineHash: sha256(unsigned) };
}

export function verifyTrustBaseline(input: unknown): TrustBaseline {
  if (z.object({ version: z.literal(1) }).passthrough().safeParse(input).success) {
    throw new Error("Trust baseline v1 does not contain capability contracts; run trust migrate --yes after reviewing declared capabilities");
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
  poisoned: string[];
  unchanged: string[];
};

export function diffTrustBaseline(baseline: TrustBaseline, tools: ListedTool[], capabilities: CapabilityDeclarations, expectedTargetName?: string): TrustDiff {
  verifyTrustBaseline(baseline);
  if (expectedTargetName !== undefined && baseline.targetName !== expectedTargetName) {
    throw new Error(`Trust baseline target does not match configured target: ${baseline.targetName}`);
  }
  assertUniqueToolNames(tools, "Current tool inventory");
  const current = new Map(createTrustBaseline(baseline.targetName, tools, capabilities).tools.map((tool) => [tool.name, tool]));
  const approved = new Map(baseline.tools.map((tool) => [tool.name, tool]));
  const result: TrustDiff = { added: [], removed: [], schemaChanged: [], descriptionChanged: [], capabilityChanged: [], poisoned: [], unchanged: [] };
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
