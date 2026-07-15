import { realpath, stat } from "node:fs/promises";
import { isIP } from "node:net";
import path from "node:path";
import type { DetectionEvidence, RiskLevel, ToolBastionConfig } from "@toolbastion/shared";

type LocatedString = { fieldPath: string; value: string; key: string };

const severityRank: Record<RiskLevel, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function evidence(detector: string, category: string, severity: RiskLevel, message: string, fieldPath: string): DetectionEvidence {
  return { detector, category, severity, message, fieldPath, redactedValue: "[REDACTED]" };
}

function stringsIn(value: unknown, prefix = "args"): LocatedString[] {
  if (typeof value === "string") {
    const key = prefix.split(".").at(-1) ?? prefix;
    return [{ fieldPath: prefix, value, key }];
  }
  if (Array.isArray(value)) return value.flatMap((child, index) => stringsIn(child, `${prefix}.${index}`));
  if (value !== null && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => stringsIn(child, `${prefix}.${key}`));
  }
  return [];
}

function hasPathSemantics(located: LocatedString): boolean {
  const key = located.key.toLowerCase();
  const decoded = decodePath(located.value).trim();
  if (/(?:path|file|directory|folder|cwd|destination)/.test(key)) return true;
  return /^(?:\.{0,2}[\\/]|~[\\/]|[a-zA-Z]:[\\/]|[\\/]{2}|[\\/]|%[^%]+%|\$\{?\w+\}?)/.test(decoded)
    || /(?:^|[\\/])(?:\.env(?:\.|$)|\.ssh|\.aws|\.azure|id_rsa|id_ed25519|credentials)(?:[\\/]|$)/i.test(decoded)
    || /(?:%2e|%2f|%5c)/i.test(located.value);
}

function hasUrlSemantics(located: LocatedString): boolean {
  return /(?:url|uri|endpoint|webhook|host)/.test(located.key.toLowerCase())
    || /^[a-z][a-z0-9+.-]*:\/\//i.test(located.value.trim());
}

function hasShellSemantics(toolName: string, located: LocatedString): boolean {
  const key = located.key.toLowerCase();
  const value = located.value.trim();
  if (/(?:command|cmd|script|shell)/.test(key) || /(?:shell|command|exec|run)/i.test(toolName)) return true;
  return /^(?:npm|npx|pnpm|yarn|node|python\d*|bash|sh|zsh|cmd|powershell|pwsh|curl|wget|git|docker|kubectl|echo|cat|type|get-content|rm|rmdir|del|remove-item|sudo|runas)\b/i.test(value)
    || /\$\([^)]*\)|`[^`]+`|(?:^|\s)(?:rm\s+-rf|rmdir\s+\/s|remove-item\s+.*-recurse)/i.test(value);
}

function decodePath(value: string): string {
  let decoded = value;
  for (let index = 0; index < 2; index += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

function normalizeForMatch(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

function globMatches(pattern: string, value: string): boolean {
  const normalizedPattern = normalizeForMatch(pattern);
  const escaped = normalizedPattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const regexSource = escaped.replaceAll("**", "\u0000").replaceAll("*", "[^/]*").replaceAll("\u0000", ".*");
  return new RegExp(`^(?:${regexSource})$`, process.platform === "win32" ? "i" : "").test(normalizeForMatch(value));
}

async function nearestRealParent(candidate: string): Promise<string> {
  let current = candidate;
  for (;;) {
    try {
      await stat(current);
      return await realpath(current);
    } catch {
      const parent = path.dirname(current);
      if (parent === current) throw new Error("No existing parent for path");
      current = parent;
    }
  }
}

export async function inspectPath(value: string, fieldPath: string, config: ToolBastionConfig): Promise<DetectionEvidence[]> {
  const findings: DetectionEvidence[] = [];
  if (value.includes("\0")) return [evidence("path", "path_null_byte", "critical", "Path contains a null byte", fieldPath)];
  const decoded = decodePath(value).trim();
  if (/^(?:~[/\\]|%[^%]+%|\$\{?\w+\}?)/.test(decoded)) {
    findings.push(evidence("path", "path_expansion_attempt", "high", "Path uses home or environment expansion syntax", fieldPath));
  }
  const portable = decoded.replaceAll("\\", "/");
  if (/^(?:[a-zA-Z]:\/|\/\/)/.test(portable)) {
    if (process.platform !== "win32") findings.push(evidence("path", "windows_absolute_path", "high", "Windows absolute or UNC syntax was detected on a non-Windows host", fieldPath));
    findings.push(evidence("path", "path_outside_project_root", "critical", "Absolute or UNC path is outside the configured project scope", fieldPath));
    return findings;
  }

  const projectRoot = path.resolve(config.project_root);
  let canonicalRoot: string;
  try { canonicalRoot = await realpath(projectRoot); } catch { canonicalRoot = projectRoot; }
  const candidate = path.resolve(projectRoot, portable.split("/").join(path.sep));
  let comparisonCandidate = candidate;
  try { comparisonCandidate = await realpath(candidate); } catch {
    try {
      const parent = await nearestRealParent(path.dirname(candidate));
      comparisonCandidate = path.join(parent, path.basename(candidate));
    } catch {
      findings.push(evidence("path", "path_ambiguous", "high", "Path could not be canonicalized safely", fieldPath));
      return findings;
    }
  }
  const normalizeCase = (input: string) => process.platform === "win32" ? input.toLowerCase() : input;
  const relative = path.relative(normalizeCase(canonicalRoot), normalizeCase(comparisonCandidate));
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    const lexicalRelative = path.relative(normalizeCase(canonicalRoot), normalizeCase(candidate));
    if (!(lexicalRelative === ".." || lexicalRelative.startsWith(`..${path.sep}`) || path.isAbsolute(lexicalRelative))) findings.push(evidence("path", "symlink_escape", "critical", "A symlink or junction resolves outside the configured project root", fieldPath));
    findings.push(evidence("path", "path_outside_project_root", "critical", "Canonical path escapes the configured project root", fieldPath));
    return findings;
  }
  const relativePortable = normalizeForMatch(path.relative(canonicalRoot, candidate));
  if (config.paths.deny.some((pattern) => globMatches(pattern, relativePortable) || globMatches(pattern, `x/${relativePortable}`))) {
    findings.push(evidence("path", "sensitive_path_denied", "critical", "Path matches a configured deny rule", fieldPath));
  }
  if (!config.paths.allow.some((pattern) => globMatches(pattern, relativePortable) || globMatches(pattern, `./${relativePortable}`))) {
    findings.push(evidence("path", "path_not_allowlisted", "high", "Path is not covered by an allow rule", fieldPath));
  }
  return findings;
}

function ipv4Class(host: string): "loopback" | "private" | "link_local" | "public" {
  const octets = host.split(".").map(Number);
  const [a = -1, b = -1] = octets;
  if (a === 127) return "loopback";
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  if (a === 169 && b === 254) return "link_local";
  return "public";
}

export function inspectUrl(value: string, fieldPath: string, config: ToolBastionConfig): DetectionEvidence[] {
  let parsed: URL;
  try { parsed = new URL(value); } catch {
    return [evidence("network", "invalid_url", "high", "Network destination is not a valid absolute URL", fieldPath)];
  }
  const findings: DetectionEvidence[] = [];
  if (!(["http:", "https:"] as string[]).includes(parsed.protocol)) {
    findings.push(evidence("network", "non_http_protocol", "critical", "Only HTTP and HTTPS destinations are supported", fieldPath));
  }
  if (parsed.username || parsed.password) findings.push(evidence("network", "url_userinfo", "high", "URL contains misleading user-info credentials", fieldPath));
  const port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;
  if (!config.network.allowed_ports.includes(port)) findings.push(evidence("network", "disallowed_port", "high", "Destination port is not allowlisted", fieldPath));

  const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) findings.push(evidence("network", "loopback_destination", "critical", "Loopback destinations are denied", fieldPath));
  if (["169.254.169.254", "metadata.google.internal"].includes(host)) findings.push(evidence("network", "metadata_endpoint", "critical", "Cloud metadata endpoint is denied", fieldPath));
  const ipVersion = isIP(host);
  if (ipVersion === 4) {
    const classification = ipv4Class(host);
    if (classification === "loopback" && config.network.deny_loopback) findings.push(evidence("network", "loopback_destination", "critical", "IPv4 loopback is denied", fieldPath));
    if (classification === "private" && config.network.deny_private_ips) findings.push(evidence("network", "private_ip_destination", "critical", "Private IPv4 destination is denied", fieldPath));
    if (classification === "link_local" && config.network.deny_link_local) findings.push(evidence("network", "link_local_destination", "critical", "Link-local IPv4 destination is denied", fieldPath));
  } else if (ipVersion === 6) {
    if (host === "::1") findings.push(evidence("network", "loopback_destination", "critical", "IPv6 loopback is denied", fieldPath));
    if (/^(?:f[cd]|fe[89ab])/.test(host)) findings.push(evidence("network", "private_ip_destination", "critical", "Private or link-local IPv6 destination is denied", fieldPath));
    const embedded = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host)?.[1];
    if (embedded && ipv4Class(embedded) !== "public") findings.push(evidence("network", "embedded_private_ip", "critical", "IPv4-embedded IPv6 destination is denied", fieldPath));
  }

  const domainAllowed = config.network.allow_domains.some((domain) => host === domain.toLowerCase() || (config.network.allow_subdomains && host.endsWith(`.${domain.toLowerCase()}`)));
  if (config.network.default === "deny" && !domainAllowed) findings.push(evidence("network", "domain_not_allowlisted", "high", "Destination domain is not allowlisted", fieldPath));
  for (const key of parsed.searchParams.keys()) {
    if (/(?:token|secret|key|password|authorization|credential)/i.test(key)) {
      findings.push(evidence("network", "sensitive_query_parameter", "critical", "URL query contains a sensitive parameter name", fieldPath));
      break;
    }
  }
  return findings;
}

export function inspectShell(value: string, fieldPath: string): DetectionEvidence[] {
  const findings: DetectionEvidence[] = [];
  const rules: Array<[RegExp, string, RiskLevel, string]> = [
    [/[|;&]|&&|\|\||(?:^|\s)[<>]{1,2}(?:\s|$)/, "shell_metacharacters", "high", "Command contains chaining, pipe, or redirection syntax"],
    [/\$\([^)]*\)|`[^`]+`/, "command_substitution", "critical", "Command contains command substitution"],
    [/(?:powershell|pwsh)\b[^\r\n]*(?:-enc|-encodedcommand)\b/i, "encoded_powershell", "critical", "Encoded PowerShell execution is denied"],
    [/(?:^|\s)(?:sudo|runas)\b/i, "privilege_escalation", "critical", "Privilege escalation command is denied"],
    [/(?:curl|wget|invoke-webrequest)\b[^\r\n]*\|[^\r\n]*(?:sh|bash|powershell|pwsh)/i, "download_pipe_shell", "critical", "Remote download piped to a shell is denied"],
    [/(?:^|\s)(?:rm\s+-rf|rmdir\s+\/s|remove-item\s+.*-recurse|format\s+[a-z]:)/i, "destructive_command", "critical", "Destructive filesystem command is denied"],
    [/(?:printenv|set\s*$|get-childitem\s+env:|env\s*$)/im, "environment_dump", "high", "Environment dumping may expose credentials"],
    [/(?:\.ssh|\.aws|\.azure|id_rsa|credentials)/i, "credential_directory_access", "critical", "Command accesses a credential location"]
  ];
  for (const [pattern, category, severity, message] of rules) if (pattern.test(value)) findings.push(evidence("shell", category, severity, message, fieldPath));
  if (/(?:curl|wget|invoke-webrequest)/i.test(value) && /(?:cat|type|get-content)/i.test(value)) findings.push(evidence("shell", "read_and_exfiltrate", "critical", "Command combines local reads with a network client", fieldPath));
  return findings;
}

export async function inspectArguments(toolName: string, args: Record<string, unknown>, config: ToolBastionConfig): Promise<DetectionEvidence[]> {
  const findings: DetectionEvidence[] = [];
  for (const located of stringsIn(args)) {
    if (hasPathSemantics(located)) findings.push(...await inspectPath(located.value, located.fieldPath, config));
    if (hasUrlSemantics(located)) findings.push(...inspectUrl(located.value, located.fieldPath, config));
    if (hasShellSemantics(toolName, located)) findings.push(...inspectShell(located.value, located.fieldPath));
  }
  return findings.filter((finding, index, all) => all.findIndex((candidate) => candidate.category === finding.category && candidate.fieldPath === finding.fieldPath) === index);
}

export function highestRisk(findings: DetectionEvidence[]): RiskLevel {
  return findings.reduce<RiskLevel>((highest, item) => (severityRank[item.severity] ?? 0) > (severityRank[highest] ?? 0) ? item.severity : highest, "none");
}
