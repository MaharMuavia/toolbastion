import { randomUUID } from "node:crypto";
import { type DetectionEvidence, type RiskLevel, type ToolResultInspection, type ToolBastionConfig } from "@toolbastion/shared";

const SECRET_PATTERNS = [
  { category: "openai_key", expression: /sk-(?:proj-)?[A-Za-z0-9_-]{12,}/gi },
  { category: "github_token", expression: /gh[pousr]_[A-Za-z0-9_]{12,}/gi },
  { category: "aws_access_key", expression: /AKIA[A-Z0-9]{16}/g },
  { category: "authorization_header", expression: /(?:authorization\s*[:=]\s*)?Bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi },
  { category: "private_key", expression: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { category: "environment_secret", expression: /\b(?:OPENAI_API_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|CLIENT_SECRET)\s*=\s*[^\s"']+/gi }
] as const;
const INJECTION = /(?:ignore\s+(?:all\s+)?(?:previous|prior|system)|(?:call|invoke|execute|use)\s+(?:the\s+)?(?:tool|function)|do\s+not\s+(?:tell|show)\s+(?:the\s+)?user|system\s+message|developer\s+instruction)/i;
const URL_PATTERN = /https?:\/\/[^\s<>"')\]]+/gi;
const SENSITIVE_KEY = /(?:api[_-]?key|authorization|credential|password|passwd|secret|token|private[_-]?key|cookie)/i;

function riskRank(risk: RiskLevel): number { return ["none", "low", "medium", "high", "critical"].indexOf(risk); }

function trustedUrl(raw: string, config: ToolBastionConfig): boolean {
  try {
    const host = new URL(raw).hostname.toLowerCase();
    return config.network.allow_domains.some((domain) => host === domain.toLowerCase() || (config.network.allow_subdomains && host.endsWith(`.${domain.toLowerCase()}`)));
  } catch { return false; }
}

export function inspectToolResult(result: unknown, config: ToolBastionConfig): ToolResultInspection {
  const evidence: DetectionEvidence[] = [];
  const redactions: Array<{ fieldPath: string; reason: string }> = [];
  let quarantine = false;
  let highest: RiskLevel = "none";
  let visitedNodes = 0;
  let visitedBytes = 0;
  const add = (fieldPath: string, category: string, severity: RiskLevel, message: string) => {
    if (!evidence.some((item) => item.fieldPath === fieldPath && item.category === category)) evidence.push({ detector: "output_firewall", category, severity, message, fieldPath });
    if (riskRank(severity) > riskRank(highest)) highest = severity;
  };

  const bounded = (fieldPath: string, category: "output_depth_limit" | "output_node_limit" | "output_byte_limit", message: string) => {
    quarantine = true;
    add(fieldPath, category, "high", message);
    return `[QUARANTINED:${category}]`;
  };
  const visit = (value: unknown, fieldPath: string, key = "", depth = 0): unknown => {
    visitedNodes += 1;
    if (depth > config.limits.max_output_depth) return bounded(fieldPath, "output_depth_limit", "Tool output exceeded the configured nesting-depth limit");
    if (visitedNodes > config.limits.max_output_nodes) return bounded(fieldPath, "output_node_limit", "Tool output exceeded the configured node limit");
    visitedBytes += Buffer.byteLength(key, "utf8");
    if (visitedBytes > config.limits.max_output_bytes) return bounded(fieldPath, "output_byte_limit", "Tool output exceeded the configured size limit");
    if (SENSITIVE_KEY.test(key) && config.outputs.redact_secrets) {
      redactions.push({ fieldPath, reason: "sensitive_field" });
      add(fieldPath, "credential_exposure", "critical", "Sensitive output field was redacted");
      return "[REDACTED:sensitive-field]";
    }
    if (typeof value === "string") {
      visitedBytes += Buffer.byteLength(value, "utf8");
      if (visitedBytes > config.limits.max_output_bytes) return bounded(fieldPath, "output_byte_limit", "Tool output exceeded the configured size limit");
      const controlCount = [...value].filter((character) => character.charCodeAt(0) < 9 || (character.charCodeAt(0) > 13 && character.charCodeAt(0) < 32)).length;
      if (value.length > 64 && controlCount / value.length > 0.05) { quarantine = true; add(fieldPath, "binary_output", "high", "Binary-like tool output was quarantined"); return "[QUARANTINED:binary-output]"; }
      if (config.outputs.quarantine_prompt_injection && INJECTION.test(value)) { quarantine = true; add(fieldPath, "prompt_injection", "critical", "Tool output contains instructions directed at the agent"); }
      if (config.outputs.quarantine_untrusted_urls) {
        for (const match of value.matchAll(URL_PATTERN)) if (!trustedUrl(match[0], config)) { quarantine = true; add(fieldPath, "untrusted_url", "high", "Tool output contains a URL outside the configured allowlist"); }
      }
      let sanitized = value;
      if (config.outputs.redact_secrets) {
        for (const pattern of SECRET_PATTERNS) {
          pattern.expression.lastIndex = 0;
          if (pattern.expression.test(sanitized)) {
            pattern.expression.lastIndex = 0;
            sanitized = sanitized.replace(pattern.expression, `[REDACTED:${pattern.category}]`);
            redactions.push({ fieldPath, reason: pattern.category });
            add(fieldPath, "credential_exposure", "critical", "Credential-like output was redacted");
          }
        }
      }
      return sanitized;
    }
    if (typeof value === "number" || typeof value === "boolean" || value === null) {
      visitedBytes += Buffer.byteLength(String(value), "utf8");
      return visitedBytes > config.limits.max_output_bytes ? bounded(fieldPath, "output_byte_limit", "Tool output exceeded the configured size limit") : value;
    }
    if (Array.isArray(value)) {
      const result: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (quarantine && (visitedNodes > config.limits.max_output_nodes || visitedBytes > config.limits.max_output_bytes)) return bounded(fieldPath, "output_node_limit", "Tool output exceeded the configured structural limit");
        result.push(visit(value[index], `${fieldPath}[${index}]`, "", depth + 1));
      }
      return result;
    }
    if (value !== null && typeof value === "object") {
      const result: Record<string, unknown> = {};
      for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) {
        if (quarantine && (visitedNodes > config.limits.max_output_nodes || visitedBytes > config.limits.max_output_bytes)) return bounded(fieldPath, "output_node_limit", "Tool output exceeded the configured structural limit");
        result[childKey] = visit(child, `${fieldPath}.${childKey}`, childKey, depth + 1);
      }
      return result;
    }
    return bounded(fieldPath, "output_node_limit", "Tool output contains an unsupported value type");
  };
  const sanitizedResult = visit(result, "$result");
  const decision = quarantine ? "QUARANTINE" : redactions.length > 0 ? "REDACT" : "PASS";
  return { decision, riskLevel: highest, evidence, redactions, sanitizedResult, ...(quarantine ? { quarantineId: randomUUID() } : {}) };
}
