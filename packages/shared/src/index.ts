import { createHash } from "node:crypto";
import { isIP } from "node:net";
import path from "node:path";
import { z } from "zod";

export const TOOLBASTION_VERSION = "0.1.3";

export const runtimeModeSchema = z.enum(["shadow", "interactive", "enforce"]);
export type RuntimeMode = z.infer<typeof runtimeModeSchema>;
export const requestDecisionSchema = z.enum(["ALLOW", "ASK_USER", "BLOCK"]);
export type RequestDecision = z.infer<typeof requestDecisionSchema>;
export const authorizationDecisionSchema = z.enum(["ALLOW", "ASK_USER", "BLOCK_BEFORE_EXECUTION"]);
export type AuthorizationDecision = z.infer<typeof authorizationDecisionSchema>;
export const executionStateSchema = z.enum(["NOT_DISPATCHED", "DISPATCHED", "COMPLETED", "FAILED", "TIMED_OUT", "UNKNOWN"]);
export type ExecutionState = z.infer<typeof executionStateSchema>;
export const outputDecisionSchema = z.enum(["NOT_INSPECTED", "NOT_RELEASED", "PASS", "REDACT", "QUARANTINE"]);
export type OutputDecision = z.infer<typeof outputDecisionSchema>;
export const riskLevelSchema = z.enum(["none", "low", "medium", "high", "critical"]);
export type RiskLevel = z.infer<typeof riskLevelSchema>;

/**
 * The dashboard/runtime boundary is deliberately narrower than the audit
 * boundary.  It contains only displayable lifecycle metadata: never tool
 * arguments, policy text, target output, model reasoning, or credentials.
 */
export const runtimeEventTypeSchema = z.enum([
  "session_started", "target_connecting", "target_connected", "tools_listed", "tools_changed", "trust_verified",
  "policy_evaluated", "tool_call_received", "authorization_completed", "tool_dispatch_started", "tool_dispatch_completed",
  "tool_dispatch_failed", "tool_dispatch_timed_out", "target_termination_started", "target_terminated", "target_restart_started",
  "target_restarted", "output_inspected", "call_completed", "call_blocked", "audit_failed", "target_closed", "runtime_log_rotated", "heartbeat"
]);
export type RuntimeEventType = z.infer<typeof runtimeEventTypeSchema>;

export const runtimeDecisionSourceSchema = z.enum(["deterministic", "semantic_judge", "cache", "system_failure"]);
export type RuntimeDecisionSource = z.infer<typeof runtimeDecisionSourceSchema>;
export const evidenceStateSchema = z.enum(["AVAILABLE", "UNAVAILABLE", "NOT_REQUIRED"]);
export type EvidenceState = z.infer<typeof evidenceStateSchema>;

const runtimeReasonCodeSchema = z.string().trim().toLowerCase().regex(/^[a-z0-9][a-z0-9_:-]{0,119}$/);

export const runtimeEventSchema = z.object({
  schemaVersion: z.literal(1),
  eventId: z.string().min(1).max(128),
  sessionId: z.string().min(1).max(128),
  sessionStartedAt: z.string().datetime({ offset: true }).optional(),
  callId: z.string().min(1).max(128).optional(),
  timestamp: z.string().datetime({ offset: true }),
  eventType: runtimeEventTypeSchema,
  toolName: z.string().min(1).max(256).optional(),
  authorizationDecision: authorizationDecisionSchema.optional(),
  executionState: executionStateSchema.optional(),
  outputDecision: outputDecisionSchema.optional(),
  decisionSource: runtimeDecisionSourceSchema,
  riskLevel: riskLevelSchema,
  judgeRequestedModel: z.string().min(1).max(128).optional(),
  judgeResponseModel: z.string().min(1).max(128).optional(),
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  judgeLatencyMs: z.number().nonnegative(),
  cacheHit: z.boolean(),
  reasonCodes: z.array(runtimeReasonCodeSchema).max(64),
  evidenceState: evidenceStateSchema
}).strict();
export type RuntimeEvent = z.infer<typeof runtimeEventSchema>;

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function validString(value: unknown, maximum = 256): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= maximum ? value : undefined;
}

function safeToolName(value: unknown): string | undefined {
  const name = validString(value);
  return name !== undefined && /^[A-Za-z0-9_.-]+$/.test(name) ? name : undefined;
}

function validNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0;
}

function safeReasonCode(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase().replaceAll(/[^a-z0-9_:-]+/g, "_").replaceAll(/^_+|_+$/g, "").slice(0, 120);
  return runtimeReasonCodeSchema.safeParse(normalized).success ? normalized : undefined;
}

/** Constructs a schema-validated, allowlisted runtime event from local facts. */
export function sanitizeRuntimeEvent(input: {
  eventId: string;
  sessionId: string;
  timestamp: string;
  eventType: RuntimeEventType;
  payload?: Record<string, unknown>;
  judgeRequestedModel?: string;
}): RuntimeEvent {
  const payload = input.payload ?? {};
  const deterministic = record(payload.deterministic);
  const judge = record(payload.judge);
  const directRisk = riskLevelSchema.safeParse(payload.riskLevel);
  const deterministicRisk = riskLevelSchema.safeParse(deterministic.riskLevel);
  const judgeRisk = riskLevelSchema.safeParse(judge.riskLevel);
  const authorizationDecision = authorizationDecisionSchema.safeParse(payload.authorizationDecision);
  const executionState = executionStateSchema.safeParse(payload.executionState);
  const outputDecision = outputDecisionSchema.safeParse(payload.outputDecision);
  const evidenceState = evidenceStateSchema.safeParse(payload.evidenceState);
  const cacheHit = payload.cacheHit === true;
  const payloadCodes = Array.isArray(payload.reasonCodes) ? payload.reasonCodes : payload.reason === undefined ? [] : [payload.reason];
  const reasonCodes = [...new Set(payloadCodes.map(safeReasonCode).filter((value): value is string => value !== undefined))];
  const model = validString(judge.model, 128);
  const source = runtimeDecisionSourceSchema.safeParse(payload.decisionSource);
  const decisionSource: RuntimeDecisionSource = source.success
    ? source.data
    : cacheHit ? "cache"
      : model !== undefined || judge.offlineReplay === true ? "semantic_judge"
        : input.eventType === "audit_failed" ? "system_failure"
          : "deterministic";
  return runtimeEventSchema.parse({
    schemaVersion: 1,
    eventId: input.eventId,
    sessionId: input.sessionId,
    ...(typeof payload.sessionStartedAt === "string" && z.string().datetime({ offset: true }).safeParse(payload.sessionStartedAt).success ? { sessionStartedAt: payload.sessionStartedAt } : {}),
    ...(validString(payload.callId, 128) === undefined ? {} : { callId: validString(payload.callId, 128) }),
    timestamp: input.timestamp,
    eventType: input.eventType,
    ...(safeToolName(payload.toolName) === undefined ? {} : { toolName: safeToolName(payload.toolName) }),
    ...(authorizationDecision.success ? { authorizationDecision: authorizationDecision.data } : {}),
    ...(executionState.success ? { executionState: executionState.data } : {}),
    ...(outputDecision.success ? { outputDecision: outputDecision.data } : {}),
    decisionSource,
    riskLevel: directRisk.success ? directRisk.data : deterministicRisk.success ? deterministicRisk.data : judgeRisk.success ? judgeRisk.data : "none",
    ...(input.judgeRequestedModel === undefined ? {} : { judgeRequestedModel: input.judgeRequestedModel.slice(0, 128) }),
    ...(model === undefined ? {} : { judgeResponseModel: model }),
    inputTokens: validNumber(judge.inputTokens),
    outputTokens: validNumber(judge.outputTokens),
    judgeLatencyMs: validNumber(judge.latencyMs),
    cacheHit,
    reasonCodes,
    evidenceState: evidenceState.success ? evidenceState.data : input.eventType === "audit_failed" ? "UNAVAILABLE" : "AVAILABLE"
  });
}

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
  timestamp: z.string().datetime({ offset: true }),
  eventType: z.string(),
  payload: z.record(z.string(), z.unknown()),
  previousHash: z.string(),
  eventHash: z.string()
}).strict();
export type AuditEvent = z.infer<typeof auditEventSchema>;

export const bastionReceiptSchema = z.object({
  version: z.literal(1),
  sessionId: z.string().min(1),
  callId: z.string().min(1),
  toolName: z.string().min(1),
  toolManifestHash: z.string().regex(/^[a-f0-9]{64}$/),
  schemaHash: z.string().regex(/^[a-f0-9]{64}$/),
  policyHash: z.string().regex(/^[a-f0-9]{64}$/),
  argsHash: z.string().regex(/^[a-f0-9]{64}$/),
  authorizationDecision: authorizationDecisionSchema,
  executionState: executionStateSchema,
  outputDecision: outputDecisionSchema,
  judge: z.object({
    requestedModel: z.string().min(1),
    responseModel: z.string().min(1).optional(),
    offlineReplay: z.boolean(),
    subchecks: z.array(z.object({ checkName: z.string(), verdict: z.string(), riskLevel: riskLevelSchema }).strict()),
    inputTokens: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    latencyMs: z.number().nonnegative()
  }).strict().optional(),
  startedAt: z.string().datetime({ offset: true }),
  completedAt: z.string().datetime({ offset: true }).optional(),
  signatureStatus: z.enum(["signed", "unsigned"]),
  signature: z.object({
    algorithm: z.literal("ed25519"),
    keyId: z.string().regex(/^[a-f0-9]{64}$/),
    publicKey: z.string().min(1),
    value: z.string().min(1)
  }).strict().optional()
}).strict().superRefine((receipt, context) => {
  if (receipt.signatureStatus === "signed" && receipt.signature === undefined) context.addIssue({ code: "custom", path: ["signature"], message: "signed receipts require a signature" });
  if (receipt.signatureStatus === "unsigned" && receipt.signature !== undefined) context.addIssue({ code: "custom", path: ["signature"], message: "unsigned receipts cannot contain a signature" });
});
export type BastionReceipt = z.infer<typeof bastionReceiptSchema>;

const remediationReasoningSchema = z.string().trim().min(1).max(4_000);

export const remediationOutputSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("ADD_EXACT_REQUEST_HOST"),
    reasoning: remediationReasoningSchema,
    expectedOutcome: z.literal("allow_legitimate_call")
  }).strict(),
  z.object({
    action: z.literal("NO_CHANGE"),
    reasoning: remediationReasoningSchema,
    expectedOutcome: z.literal("keep_attack_blocked")
  }).strict()
]);
export type RemediationOutput = z.infer<typeof remediationOutputSchema>;

export const remediationOperationSchema = z.object({
  kind: z.literal("add_exact_network_domain"),
  domain: z.string().regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/)
}).strict();
export type RemediationOperation = z.infer<typeof remediationOperationSchema>;

const remediationProposalFields = {
  version: z.literal(2),
  proposalId: z.string(),
  blockedEventId: z.string(),
  toolName: z.string().min(1),
  decision: z.enum(["BLOCK", "ASK_USER"]),
  argsHash: z.string().regex(/^[a-f0-9]{64}$/),
  basePolicyHash: z.string().regex(/^[a-f0-9]{64}$/),
  proposalHash: z.string().regex(/^[a-f0-9]{64}$/),
  integrity: z.object({
    algorithm: z.literal("hmac-sha256"),
    keyId: z.literal("TOOLBASTION_REMEDIATION_HMAC_KEY"),
    signature: z.string().regex(/^[a-f0-9]{64}$/)
  }).strict(),
  verified: z.boolean(),
  verificationResults: z.array(z.string()),
  createdAt: z.string(),
  status: z.enum(["pending", "applied", "rejected"]),
  appliedBy: z.string().optional(),
  appliedAt: z.string().optional()
};

export const remediationProposalSchema = z.discriminatedUnion("action", [
  z.object({
    ...remediationProposalFields,
    action: z.literal("ADD_EXACT_REQUEST_HOST"),
    reasoning: remediationReasoningSchema,
    expectedOutcome: z.literal("allow_legitimate_call"),
    operation: remediationOperationSchema.nullable()
  }).strict(),
  z.object({
    ...remediationProposalFields,
    action: z.literal("NO_CHANGE"),
    reasoning: remediationReasoningSchema,
    expectedOutcome: z.literal("keep_attack_blocked"),
    operation: z.null()
  }).strict()
]);
export type RemediationProposal = z.infer<typeof remediationProposalSchema>;

const dockerImageReferenceSchema = z.string().trim()
  .regex(/^(?:sha256:[a-f0-9]{64}|[^\s@]+@sha256:[a-f0-9]{64})$/, "Docker isolation image must be pinned by immutable sha256 digest");

const targetIsolationSchema = z.discriminatedUnion("provider", [
  z.object({ provider: z.literal("none") }).strict(),
  z.object({
    provider: z.literal("docker"),
    image: dockerImageReferenceSchema,
    user: z.string().regex(/^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$/).default("1000:1000"),
    memory_mb: z.number().int().min(128).max(4_096).default(512),
    cpus: z.number().positive().max(4).default(1),
    pids_limit: z.number().int().min(32).max(1_024).default(256),
    tmpfs_size_mb: z.number().int().min(16).max(1_024).default(64)
  }).strict()
]).default({ provider: "none" });

export const targetServerConfigSchema = z.object({
  name: z.string().trim().min(1),
  command: z.string().trim().min(1),
  args: z.array(z.string()).default([]),
  cwd: z.string().optional(),
  env_allowlist: z.array(z.string()).default([]),
  isolation: targetIsolationSchema
}).strict().transform(({ env_allowlist, ...value }) => ({ ...value, envAllowlist: env_allowlist }));
export type TargetServerConfig = z.output<typeof targetServerConfigSchema>;
export type TargetServerConfigInput = z.input<typeof targetServerConfigSchema>;

const pathPolicySchema = z.object({
  allow: z.array(z.string()).default(["./**"]),
  deny: z.array(z.string()).default([
    "**/.env", "**/.env.*", "**/.ssh/**", "**/.aws/**", "**/.azure/**",
    "**/.npmrc", "**/.netrc", "**/.pypirc", "**/.envrc", "**/.git-credentials",
    "**/.docker/config.json", "**/.kube/config", "**/*credentials*", "**/*secret*",
    "**/id_rsa", "**/id_ed25519", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.tfstate"
  ])
}).strict().prefault({});

const networkDomainSchema = z.string().trim().toLowerCase()
  .regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/)
  .refine((domain) => isIP(domain) === 0, "network allow_domains must contain DNS names, not IP literals")
  .refine((domain) => !(
    domain === "localhost"
    || domain.endsWith(".localhost")
    || domain.endsWith(".local")
    || domain === "metadata.google.internal"
    || domain === "nip.io"
    || domain.endsWith(".nip.io")
    || domain === "sslip.io"
    || domain.endsWith(".sslip.io")
    || domain === "localtest.me"
    || domain.endsWith(".localtest.me")
  ), "network allow_domains contains a localhost, metadata, or resolver-magic hostname");

const networkPolicySchema = z.object({
  default: z.enum(["allow", "deny"]).default("deny"),
  allow_domains: z.array(networkDomainSchema).default([]),
  allow_subdomains: z.boolean().default(false),
  deny_private_ips: z.boolean().default(true),
  deny_loopback: z.boolean().default(true),
  deny_link_local: z.boolean().default(true),
  deny_metadata_endpoints: z.boolean().default(true),
  allowed_ports: z.array(z.number().int().min(1).max(65535)).default([80, 443]),
  target_egress: z.enum(["blocked", "isolated"]).default("blocked")
}).strict().prefault({});

const toolRuleSchema = z.object({
  base_risk: riskLevelSchema.default("medium"),
  action: z.enum(["allow", "allow_when_in_scope", "judge", "block"]).default("judge")
}).strict();

const judgeSchema = z.object({
  enabled: z.boolean().default(true),
  mode: z.enum(["live", "offline"]).default("live"),
  model: z.string().default("gpt-5.6"),
  reasoning_effort: z.enum(["low", "medium", "high"]).default("medium"),
  timeout_ms: z.number().int().positive().max(120_000).default(20_000),
  max_calls_per_session: z.number().int().nonnegative().default(40),
  parallel_subchecks: z.boolean().default(true),
  context_file: z.string().optional(),
  context_max_bytes: z.number().int().positive().max(65_536).default(8_192),
  fixture_file: z.string().default("./fixtures/recorded-judge-results/request-verdicts.json")
}).strict().prefault({});

const projectRelativeDirectorySchema = z.string().trim().min(1).refine((directory) => {
  if (path.isAbsolute(directory)) return false;
  return !directory.replaceAll("\\", "/").split("/").includes("..");
}, "directory must be a relative path inside project_root");

const limitSchema = z.object({
  max_argument_bytes: z.number().int().positive().max(1_048_576).default(65_536),
  max_argument_depth: z.number().int().min(1).max(128).default(32),
  max_argument_nodes: z.number().int().positive().max(100_000).default(10_000),
  max_output_bytes: z.number().int().positive().max(16_777_216).default(1_000_000),
  max_output_depth: z.number().int().min(1).max(128).default(32),
  max_output_nodes: z.number().int().positive().max(100_000).default(10_000),
  max_tool_metadata_bytes: z.number().int().positive().max(1_048_576).default(65_536),
  max_inflight_calls: z.number().int().positive().max(128).default(1),
  tool_timeout_ms: z.number().int().positive().max(120_000).default(30_000)
}).strict().prefault({});

const receiptSchema = z.object({
  enabled: z.boolean().default(true),
  directory: projectRelativeDirectorySchema.default("./.toolbastion/receipts"),
  signing_required: z.boolean().optional(),
  signingRequired: z.boolean().optional()
}).strict().prefault({}).superRefine((value, context) => {
  if (value.signing_required !== undefined && value.signingRequired !== undefined && value.signing_required !== value.signingRequired) {
    context.addIssue({ code: "custom", path: ["signing_required"], message: "signing_required conflicts with normalized signingRequired" });
  }
}).transform(({ signing_required, signingRequired, ...value }) => ({ ...value, signingRequired: signing_required ?? signingRequired ?? false }));

const runtimeEventsSchema = z.object({
  // The active log plus retained segments is capped at 64 MiB.  Rotation markers
  // preserve the session identity when a long-running local session crosses a segment boundary.
  max_bytes: z.number().int().min(65_536).max(16 * 1024 * 1024).default(8 * 1024 * 1024),
  retain_files: z.number().int().min(1).max(3).default(2)
}).strict().prefault({});

export const toolbastionConfigSchema = z.object({
  version: z.literal(1),
  mode: runtimeModeSchema.default("interactive"),
  project_root: z.string().default("./"),
  target: targetServerConfigSchema,
  paths: pathPolicySchema,
  network: networkPolicySchema,
  tools: z.object({
    default: z.enum(["allow", "judge", "block"]).default("judge"),
    rules: z.record(z.string(), toolRuleSchema).default({})
  }).strict().prefault({}),
  judge: judgeSchema,
  cache: z.object({
    enabled: z.boolean().default(true),
    ttl_seconds: z.number().int().positive().default(3600)
  }).strict().prefault({}),
  limits: limitSchema,
  outputs: z.object({
    inspect: z.boolean().default(true),
    redact_secrets: z.boolean().default(true),
    quarantine_prompt_injection: z.boolean().default(true),
    quarantine_untrusted_urls: z.boolean().default(true)
  }).strict().prefault({}),
  audit: z.object({
    directory: projectRelativeDirectorySchema.default("./.toolbastion/audit"),
    retain_raw_content: z.literal(false).default(false)
  }).strict().prefault({}),
  runtime_events: runtimeEventsSchema,
  receipts: receiptSchema,
  remediation: z.object({
    enabled: z.boolean().default(false),
    auto_apply: z.literal(false).default(false),
    run_regression_suite: z.boolean().default(true),
    directory: z.string().default("./.toolbastion/remediation"),
    timeout_ms: z.number().int().positive().max(300_000).default(120_000)
  }).strict().prefault({})
}).strict().superRefine((config, context) => {
  if (config.target.isolation.provider === "docker") {
    if (config.target.cwd !== undefined && (path.isAbsolute(config.target.cwd) || config.target.cwd.replaceAll("\\", "/").split("/").includes(".."))) {
      context.addIssue({ code: "custom", path: ["target", "cwd"], message: "Docker-isolated target cwd must be relative to project_root" });
    }
    if (path.isAbsolute(config.target.command)) {
      context.addIssue({ code: "custom", path: ["target", "command"], message: "Docker-isolated target command must be available inside the pinned image" });
    }
    config.target.args.forEach((argument, index) => {
      if (path.isAbsolute(argument)) {
        context.addIssue({ code: "custom", path: ["target", "args", index], message: "Docker-isolated target arguments must use container-relative paths" });
      }
    });
  }
  if (config.mode !== "enforce") return;
  if (config.limits.max_inflight_calls > 1) {
    context.addIssue({ code: "custom", path: ["limits", "max_inflight_calls"], message: "enforce mode currently supports one in-flight call per stdio target" });
  }
  if (config.network.default !== "deny") {
    context.addIssue({ code: "custom", path: ["network", "default"], message: "enforce mode requires a deny-by-default network policy" });
  }
  for (const key of ["deny_private_ips", "deny_loopback", "deny_link_local", "deny_metadata_endpoints"] as const) {
    if (!config.network[key]) context.addIssue({ code: "custom", path: ["network", key], message: "enforce mode requires this network protection" });
  }
  for (const key of ["inspect", "redact_secrets", "quarantine_prompt_injection", "quarantine_untrusted_urls"] as const) {
    if (!config.outputs[key]) context.addIssue({ code: "custom", path: ["outputs", key], message: "enforce mode requires this output protection" });
  }
  if (config.judge.enabled && config.judge.mode === "offline") {
    context.addIssue({ code: "custom", path: ["judge", "mode"], message: "offline judge replay is not permitted in enforce mode" });
  }
  if (config.network.target_egress === "isolated" && config.target.isolation.provider !== "docker") {
    context.addIssue({ code: "custom", path: ["network", "target_egress"], message: "isolated target egress requires Docker target isolation" });
  }
});
export type ToolBastionConfig = z.output<typeof toolbastionConfigSchema>;

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
