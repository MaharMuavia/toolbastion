import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { inspectArguments, highestRisk } from "@mcp-warden/detectors";
import {
  canonicalJson,
  deterministicResultSchema,
  sha256,
  type DeterministicResult,
  type RequestDecision,
  type RuntimeMode,
  type WardenConfig
} from "@mcp-warden/shared";
import { z } from "zod";

export async function evaluateDeterministic(toolName: string, args: Record<string, unknown>, config: WardenConfig): Promise<DeterministicResult> {
  const findings = await inspectArguments(toolName, args, config);
  const rule = config.tools.rules[toolName];
  const action = rule?.action ?? config.tools.default;
  if (action === "block") {
    findings.push({ detector: "policy", category: "tool_blocked_by_policy", severity: "critical", message: "Tool is explicitly blocked by policy" });
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
  riskClassification: z.string()
});

export const trustBaselineSchema = z.object({
  version: z.literal(1),
  targetName: z.string(),
  wardenVersion: z.string(),
  createdAt: z.string(),
  tools: z.array(baselineToolSchema),
  baselineHash: z.string()
});
export type TrustBaseline = z.infer<typeof trustBaselineSchema>;

type ListedTool = { name: string; description?: string | undefined; inputSchema: Record<string, unknown> };

function metadataPoisoned(description: string): boolean {
  return /ignore (?:all |any )?(?:previous|prior|system)|(?:read|send|upload).*(?:credential|\.env|secret)|contact external|bypass.*(?:policy|rule)/i.test(description);
}

export function createTrustBaseline(targetName: string, tools: ListedTool[], now = new Date()): TrustBaseline {
  const normalizedTools = tools.map((tool) => {
    const description = tool.description ?? "";
    return {
      name: tool.name,
      description,
      inputSchema: JSON.parse(canonicalJson(tool.inputSchema)) as Record<string, unknown>,
      schemaHash: sha256(tool.inputSchema),
      descriptionHash: sha256(description),
      riskClassification: metadataPoisoned(description) ? "critical" : "unclassified"
    };
  }).sort((left, right) => left.name.localeCompare(right.name));
  const unsigned = { version: 1 as const, targetName, wardenVersion: "0.1.0", createdAt: now.toISOString(), tools: normalizedTools };
  return { ...unsigned, baselineHash: sha256(unsigned) };
}

export function verifyTrustBaseline(input: unknown): TrustBaseline {
  const baseline = trustBaselineSchema.parse(input);
  const { baselineHash, ...unsigned } = baseline;
  if (sha256(unsigned) !== baselineHash) throw new Error("Trust baseline hash is invalid; the file may have been edited");
  return baseline;
}

export type TrustDiff = {
  added: string[];
  removed: string[];
  schemaChanged: string[];
  descriptionChanged: string[];
  poisoned: string[];
  unchanged: string[];
};

export function diffTrustBaseline(baseline: TrustBaseline, tools: ListedTool[]): TrustDiff {
  verifyTrustBaseline(baseline);
  const current = new Map(createTrustBaseline(baseline.targetName, tools).tools.map((tool) => [tool.name, tool]));
  const approved = new Map(baseline.tools.map((tool) => [tool.name, tool]));
  const result: TrustDiff = { added: [], removed: [], schemaChanged: [], descriptionChanged: [], poisoned: [], unchanged: [] };
  for (const [name, tool] of current) {
    const prior = approved.get(name);
    if (!prior) result.added.push(name);
    else if (tool.schemaHash !== prior.schemaHash) result.schemaChanged.push(name);
    else if (tool.descriptionHash !== prior.descriptionHash) result.descriptionChanged.push(name);
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
