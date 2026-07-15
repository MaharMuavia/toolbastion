import { createHash } from "node:crypto";
import { z } from "zod";

export const runtimeModeSchema = z.enum(["shadow", "interactive", "enforce"]);
export type RuntimeMode = z.infer<typeof runtimeModeSchema>;
export const requestDecisionSchema = z.enum(["ALLOW", "ASK_USER", "BLOCK"]);
export type RequestDecision = z.infer<typeof requestDecisionSchema>;
export const outputDecisionSchema = z.enum(["PASS", "REDACT", "QUARANTINE"]);
export type OutputDecision = z.infer<typeof outputDecisionSchema>;
export const riskLevelSchema = z.enum(["none", "low", "medium", "high", "critical"]);
export type RiskLevel = z.infer<typeof riskLevelSchema>;

export const detectionEvidenceSchema = z.object({
  detector: z.string().min(1),
  category: z.string().min(1),
  severity: riskLevelSchema,
  message: z.string().min(1),
  fieldPath: z.string().optional(),
  redactedValue: z.string().optional()
});
export type DetectionEvidence = z.infer<typeof detectionEvidenceSchema>;

export const deterministicResultSchema = z.object({
  resolution: z.enum(["SAFE", "AMBIGUOUS", "HARD_DENY"]),
  riskLevel: riskLevelSchema,
  evidence: z.array(detectionEvidenceSchema),
  reasonCodes: z.array(z.string())
});
export type DeterministicResult = z.infer<typeof deterministicResultSchema>;

export const judgeSubcheckSchema = z.object({
  checkName: z.enum(["scope_safety", "exfiltration_risk", "tool_integrity", "output_injection"]),
  verdict: z.enum(["safe", "suspicious", "malicious", "unavailable"]),
  riskLevel: riskLevelSchema,
  reason: z.string().min(1),
  evidence: z.array(z.string())
});
export type JudgeSubcheck = z.infer<typeof judgeSubcheckSchema>;

export const judgeVerdictSchema = z.object({
  decision: requestDecisionSchema,
  riskLevel: riskLevelSchema,
  subchecks: z.array(judgeSubcheckSchema),
  reason: z.string().min(1),
  reasonCodes: z.array(z.string()),
  model: z.string().min(1),
  latencyMs: z.number().nonnegative(),
  inputTokens: z.number().int().nonnegative().optional(),
  outputTokens: z.number().int().nonnegative().optional(),
  cached: z.boolean(),
  offlineReplay: z.boolean()
});
export type JudgeVerdict = z.infer<typeof judgeVerdictSchema>;

export const toolResultInspectionSchema = z.object({
  decision: outputDecisionSchema,
  riskLevel: riskLevelSchema,
  evidence: z.array(detectionEvidenceSchema),
  redactions: z.array(z.object({ fieldPath: z.string(), reason: z.string() })),
  sanitizedResult: z.unknown(),
  quarantineId: z.string().optional()
});
export type ToolResultInspection = z.infer<typeof toolResultInspectionSchema>;

export const auditEventSchema = z.object({
  sequence: z.number().int().positive(),
  eventId: z.string(),
  sessionId: z.string(),
  timestamp: z.string(),
  eventType: z.string(),
  payload: z.record(z.string(), z.unknown()),
  previousHash: z.string(),
  eventHash: z.string()
});
export type AuditEvent = z.infer<typeof auditEventSchema>;

export const remediationOutputSchema = z.object({
  action: z.enum(["PATCH", "NO_CHANGE"]),
  unifiedDiff: z.string().nullable(),
  reasoning: z.string().min(1),
  expectedOutcome: z.enum(["allow_legitimate_call", "keep_attack_blocked"])
}).superRefine((value, context) => {
  if (value.action === "PATCH" && !value.unifiedDiff) context.addIssue({ code: "custom", path: ["unifiedDiff"], message: "PATCH requires a unified diff" });
  if (value.action === "NO_CHANGE" && value.unifiedDiff !== null) context.addIssue({ code: "custom", path: ["unifiedDiff"], message: "NO_CHANGE requires null" });
});
export type RemediationOutput = z.infer<typeof remediationOutputSchema>;

export const remediationProposalSchema = remediationOutputSchema.and(z.object({
  proposalId: z.string(),
  blockedEventId: z.string(),
  verified: z.boolean(),
  verificationResults: z.array(z.string()),
  createdAt: z.string(),
  status: z.enum(["pending", "applied", "rejected"]),
  appliedBy: z.string().optional(),
  appliedAt: z.string().optional()
}));
export type RemediationProposal = z.infer<typeof remediationProposalSchema>;

export const targetServerConfigSchema = z.object({
  name: z.string().trim().min(1),
  command: z.string().trim().min(1),
  args: z.array(z.string()).default([]),
  cwd: z.string().optional(),
  env_allowlist: z.array(z.string()).default([])
}).transform(({ env_allowlist, ...value }) => ({ ...value, envAllowlist: env_allowlist }));
export type TargetServerConfig = z.output<typeof targetServerConfigSchema>;

const pathPolicySchema = z.object({
  allow: z.array(z.string()).default(["./**"]),
  deny: z.array(z.string()).default([
    "**/.env", "**/.env.*", "**/.ssh/**", "**/.aws/**", "**/.azure/**",
    "**/*credentials*", "**/*secret*", "**/id_rsa", "**/id_ed25519"
  ])
}).prefault({});

const networkPolicySchema = z.object({
  default: z.enum(["allow", "deny"]).default("deny"),
  allow_domains: z.array(z.string().trim().min(1)).default([]),
  allow_subdomains: z.boolean().default(false),
  deny_private_ips: z.boolean().default(true),
  deny_loopback: z.boolean().default(true),
  deny_link_local: z.boolean().default(true),
  deny_metadata_endpoints: z.boolean().default(true),
  follow_redirects: z.boolean().default(false),
  allowed_ports: z.array(z.number().int().min(1).max(65535)).default([80, 443])
}).prefault({});

const toolRuleSchema = z.object({
  base_risk: riskLevelSchema.default("medium"),
  action: z.enum(["allow", "allow_when_in_scope", "judge", "block"]).default("judge")
});

const judgeSchema = z.object({
  enabled: z.boolean().default(true),
  mode: z.enum(["live", "offline"]).default("live"),
  model: z.string().default("gpt-5.6"),
  reasoning_effort: z.enum(["low", "medium", "high"]).default("medium"),
  timeout_ms: z.number().int().positive().max(120_000).default(20_000),
  max_calls_per_session: z.number().int().nonnegative().default(40),
  parallel_subchecks: z.boolean().default(true),
  fixture_file: z.string().default("./fixtures/recorded-judge-results/request-verdicts.json"),
  failure_policy: z.object({
    interactive: z.literal("ask_user").default("ask_user"),
    enforce: z.literal("block").default("block"),
    shadow: z.literal("allow_and_log").default("allow_and_log")
  }).prefault({})
}).prefault({});

export const wardenConfigSchema = z.object({
  version: z.literal(1),
  mode: runtimeModeSchema.default("interactive"),
  project_root: z.string().default("./"),
  target: targetServerConfigSchema,
  paths: pathPolicySchema,
  network: networkPolicySchema,
  tools: z.object({
    default: z.enum(["allow", "judge", "block"]).default("judge"),
    rules: z.record(z.string(), toolRuleSchema).default({})
  }).prefault({}),
  judge: judgeSchema,
  cache: z.object({
    enabled: z.boolean().default(true),
    ttl_seconds: z.number().int().positive().default(3600)
  }).prefault({}),
  outputs: z.object({
    inspect: z.boolean().default(true),
    redact_secrets: z.boolean().default(true),
    quarantine_prompt_injection: z.boolean().default(true),
    quarantine_untrusted_urls: z.boolean().default(true)
  }).prefault({}),
  audit: z.object({
    directory: z.string().default("./.warden/audit"),
    redact_arguments: z.boolean().default(true),
    hash_chain: z.boolean().default(true),
    retain_raw_content: z.literal(false).default(false)
  }).prefault({}),
  remediation: z.object({
    enabled: z.boolean().default(false),
    auto_apply: z.literal(false).default(false),
    run_regression_suite: z.boolean().default(true),
    directory: z.string().default("./.warden/remediation"),
    timeout_ms: z.number().int().positive().max(300_000).default(120_000)
  }).prefault({})
});
export type WardenConfig = z.output<typeof wardenConfigSchema>;

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, canonicalize(child)])
    );
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function formatZodIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => `${issue.path.length > 0 ? issue.path.join(".") : "<root>"}: ${issue.message}`);
}
