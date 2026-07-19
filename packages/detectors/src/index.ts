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
    || /^(?:[^\s\\/:"'`|;&<>]+[\\/])+\.\.(?:[\\/]|$)/.test(decoded)
    || isSensitiveCredentialPath(decoded)
    || /(?:%2e|%2f|%5c)/i.test(located.value);
}

function isSensitiveCredentialPath(value: string): boolean {
  const normalized = value.replaceAll("\\", "/").toLowerCase();
  return /(?:^|\/)(?:\.env(?:\.[^/]*)?|\.npmrc|\.netrc|\.pypirc|\.envrc|\.git-credentials|id_rsa(?:\.pub)?|id_ed25519(?:\.pub)?|credentials(?:\.json)?|kubeconfig)(?:\/|$)/.test(normalized)
    || /(?:^|\/)(?:\.ssh|\.aws|\.azure)(?:\/|$)/.test(normalized)
    || /(?:^|\/)\.docker\/config\.json$/.test(normalized)
    || /(?:^|\/)\.kube\/config$/.test(normalized)
    || /(?:^|\/)(?:gcloud|\.config\/gcloud)\/application_default_credentials\.json$/.test(normalized)
    || /(?:^|\/)[^/]+\.(?:pem|key|p12|pfx|jks|tfstate)(?:\.[^/]*)?$/.test(normalized);
}

function hasUrlSemantics(located: LocatedString): boolean {
  return /(?:url|uri|endpoint|webhook|host|hostname|address|ip|server|origin|proxy)/.test(located.key.toLowerCase())
    || /^[a-z][a-z0-9+.-]*:\/\//i.test(located.value.trim());
}

function looksLikeNetworkLiteral(value: string): boolean {
  const raw = value.trim().toLowerCase();
  const host = raw.replace(/^\[|\]$/g, "");
  return isIP(host) !== 0
    || /^(?:localhost|metadata\.google\.internal)$/.test(host)
    || /^\d{1,10}$/.test(host)
    || /^\[[0-9a-f:]+\]$/i.test(raw);
}

function looksLikeBareHostname(value: string): boolean {
  const raw = value.trim().toLowerCase();
  if (/\s|[/?#@]/.test(raw)) return false;
  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}(?::\d{1,5})?$/.test(raw);
}

function isNetworkToolName(toolName: string): boolean {
  const segments = toolName.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/);
  return segments.some((segment) => ["fetch", "download", "upload", "http", "url", "webhook", "request", "browse", "connect", "socket", "network"].includes(segment));
}

function isCommandToolName(toolName: string): boolean {
  const segments = toolName.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/);
  return segments.some((segment) => ["command", "shell", "exec", "terminal", "script"].includes(segment));
}

function hasShellSemantics(toolName: string, located: LocatedString): boolean {
  const key = located.key.toLowerCase();
  const value = located.value.trim();
  if (/(?:command|cmd|script|shell)/.test(key) || /(?:shell|command|exec|run)/i.test(toolName)) return true;
  return /^(?:npm|npx|pnpm|yarn|node|python\d*|bash|sh|zsh|cmd|powershell|pwsh|curl|wget|git|docker|kubectl|echo|cat|type|get-content|rm|rmdir|del|remove-item|sudo|runas)\b/i.test(value)
    || /\$\([^)]*\)|`[^`]+`|(?:^|\s)(?:rm\s+-rf|rmdir\s+\/s|remove-item\s+.*-recurse)/i.test(value);
}

function absoluteUrisIn(value: string): string[] {
  return [...value.matchAll(/(?:^|[\s"'=])([a-z][a-z0-9+.-]*:\/\/[^\s"'`\\<>|;&()]+)/gi)].map((match) => match[1]!);
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
  if (isSensitiveCredentialPath(decoded)) {
    findings.push(evidence("path", "sensitive_credential_path", "critical", "Credential-bearing files are denied regardless of project allow rules", fieldPath));
  }
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

function ipv4Class(host: string): "loopback" | "private" | "link_local" | "non_public" | "public" {
  const octets = host.split(".").map(Number);
  const [a = -1, b = -1] = octets;
  if (a === 127) return "loopback";
  if (a === 0 || a === 10 || (a === 100 && b >= 64 && b <= 127) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  if (a === 169 && b === 254) return "link_local";
  if ((a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224) return "non_public";
  return "public";
}

function ipv4MappedIpv6(host: string): string | undefined {
  const match = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
  if (!match) return undefined;
  const high = Number.parseInt(match[1]!, 16);
  const low = Number.parseInt(match[2]!, 16);
  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
}

function inspectParsedUrl(parsed: URL, fieldPath: string, config: ToolBastionConfig): DetectionEvidence[] {
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
    if (classification === "non_public") findings.push(evidence("network", "non_public_ip_destination", "critical", "Non-public IPv4 destination is denied", fieldPath));
  } else if (ipVersion === 6) {
    if ((host === "::" || host === "::1") && config.network.deny_loopback) findings.push(evidence("network", "loopback_destination", "critical", "IPv6 unspecified or loopback destination is denied", fieldPath));
    if (/^f[cd]/.test(host) && config.network.deny_private_ips) findings.push(evidence("network", "private_ip_destination", "critical", "IPv6 unique-local destination is denied", fieldPath));
    if (/^fe[89ab]/.test(host) && config.network.deny_link_local) findings.push(evidence("network", "link_local_destination", "critical", "IPv6 link-local destination is denied", fieldPath));
    const embedded = ipv4MappedIpv6(host);
    if (embedded) {
      const classification = ipv4Class(embedded);
      if (classification === "loopback" && config.network.deny_loopback) findings.push(evidence("network", "embedded_loopback_ip", "critical", "IPv4-mapped IPv6 loopback destination is denied", fieldPath));
      if (classification === "private" && config.network.deny_private_ips) findings.push(evidence("network", "embedded_private_ip", "critical", "IPv4-mapped private destination is denied", fieldPath));
      if (classification === "link_local" && config.network.deny_link_local) findings.push(evidence("network", "embedded_link_local_ip", "critical", "IPv4-mapped link-local destination is denied", fieldPath));
      if (classification === "non_public") findings.push(evidence("network", "embedded_non_public_ip", "critical", "IPv4-mapped non-public destination is denied", fieldPath));
    }
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

export function inspectUrl(value: string, fieldPath: string, config: ToolBastionConfig): DetectionEvidence[] {
  try {
    return inspectParsedUrl(new URL(value), fieldPath, config);
  } catch {
    return [evidence("network", "invalid_url", "high", "Network destination is not a valid absolute URL", fieldPath)];
  }
}

export function inspectNetworkAddress(value: string, fieldPath: string, config: ToolBastionConfig): DetectionEvidence[] {
  const raw = value.trim();
  try {
    const parsed = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? new URL(raw) : new URL(`http://${raw}`);
    return inspectParsedUrl(parsed, fieldPath, config);
  } catch {
    return [evidence("network", "invalid_network_destination", "high", "Network address is not a valid host, IP address, or URL", fieldPath)];
  }
}

export function inspectShell(value: string, fieldPath: string): DetectionEvidence[] {
  const findings: DetectionEvidence[] = [];
  const rules: Array<[RegExp, string, RiskLevel, string]> = [
    [/[|;&]|&&|\|\||(?:^|\s)[<>]{1,2}(?:\s|$)/, "shell_metacharacters", "high", "Command contains chaining, pipe, or redirection syntax"],
    [/\$\([^)]*\)|`[^`]+`/, "command_substitution", "critical", "Command contains command substitution"],
    [/(?:powershell|pwsh)\b[^\r\n]*(?:-enc|-encodedcommand)\b/i, "encoded_powershell", "critical", "Encoded PowerShell execution is denied"],
    [/(?:^|\s)(?:sudo|runas)\b/i, "privilege_escalation", "critical", "Privilege escalation command is denied"],
    [/(?:^|\s)(?:curl|wget|invoke-webrequest|iwr|irm|nc|ncat|telnet)\b/i, "network_client_command", "critical", "Direct network client execution requires an isolated egress guard"],
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
  let requiresTargetEgressGuard = isNetworkToolName(toolName) || isCommandToolName(toolName);
  for (const located of stringsIn(args)) {
    if (hasPathSemantics(located)) findings.push(...await inspectPath(located.value, located.fieldPath, config));
    const networkDestination = hasUrlSemantics(located) || looksLikeNetworkLiteral(located.value) || looksLikeBareHostname(located.value);
    if (networkDestination) findings.push(...inspectNetworkAddress(located.value, located.fieldPath, config));
    if (hasShellSemantics(toolName, located)) {
      findings.push(...inspectShell(located.value, located.fieldPath));
      for (const uri of absoluteUrisIn(located.value)) findings.push(...inspectUrl(uri, located.fieldPath, config));
      requiresTargetEgressGuard = true;
    }
    if (networkDestination) requiresTargetEgressGuard = true;
  }
  if (config.mode === "enforce" && config.network.target_egress === "blocked" && requiresTargetEgressGuard) {
    findings.push(evidence("network", "target_egress_not_isolated", "critical", "Enforce mode blocks target-initiated network or shell execution without Docker no-network isolation", "tool"));
  }
  return findings.filter((finding, index, all) => all.findIndex((candidate) => candidate.category === finding.category && candidate.fieldPath === finding.fieldPath) === index);
}

export function highestRisk(findings: DetectionEvidence[]): RiskLevel {
  return findings.reduce<RiskLevel>((highest, item) => (severityRank[item.severity] ?? 0) > (severityRank[highest] ?? 0) ? item.severity : highest, "none");
}
