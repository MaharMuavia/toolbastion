import { createTwoFilesPatch } from "diff";
import { stringify } from "yaml";
import { describe, expect, it } from "vitest";
import { codexExecArguments, verifyRemediation, type RemediationRequest } from "@mcp-warden/remediation";
import { wardenConfigSchema } from "@mcp-warden/shared";

const current = wardenConfigSchema.parse({
  version: 1,
  mode: "enforce",
  target: { name: "fixture", command: "node" },
  paths: { allow: ["./**"], deny: ["**/.env", "**/.ssh/**"] },
  network: { default: "deny", allow_domains: [], deny_private_ips: true, deny_loopback: true, deny_link_local: true, deny_metadata_endpoints: true },
  tools: { default: "judge", rules: { fetch_url: { action: "allow_when_in_scope", base_risk: "medium" } } }
});
const request: RemediationRequest = { blockedEventId: "event-1", decision: "BLOCK", toolName: "fetch_url", args: { url: "https://api.example.com/data" }, deterministicEvidence: [], expectedSecurityOutcome: "allow_legitimate_call" };
const attacks = [
  { tool: "fetch_url", args: { url: "http://127.0.0.1/private" }, category: "loopback_ssrf" },
  { tool: "read_project_file", args: { path: "../../.ssh/id_rsa" }, category: "path_traversal" }
];

describe("Codex remediation guardrails", () => {
  it("builds a read-only, isolated, structured codex exec invocation", () => {
    const args = codexExecArguments("C:/workspace", "schema.json", "result.json");
    expect(args).toContain("read-only");
    expect(args).toContain("--ignore-user-config");
    expect(args).toContain("--ignore-rules");
    expect(args).toContain("--output-schema");
    expect(args).toContain('approval_policy="never"');
    expect(args).not.toContain("--non-interactive");
  });

  it("accepts a narrow allowlist patch while retaining attack blocks", async () => {
    const proposed = { ...current, network: { ...current.network, allow_domains: ["api.example.com"] } };
    const source = stringify(current);
    const unifiedDiff = createTwoFilesPatch("warden.config.yaml", "warden.config.yaml", source, stringify(proposed));
    const result = await verifyRemediation({ output: { action: "PATCH", unifiedDiff, reasoning: "Narrow domain allowlist", expectedOutcome: "allow_legitimate_call" }, policyYaml: source, request, attackFixtures: attacks });
    expect(result.verified).toBe(true);
    expect(result.patchedYaml).toContain("api.example.com");
  });

  it("rejects removal of an unrelated deny rule", async () => {
    const proposed = { ...current, paths: { ...current.paths, deny: ["**/.env"] }, network: { ...current.network, allow_domains: ["api.example.com"] } };
    const source = stringify(current);
    const unifiedDiff = createTwoFilesPatch("warden.config.yaml", "warden.config.yaml", source, stringify(proposed));
    const result = await verifyRemediation({ output: { action: "PATCH", unifiedDiff, reasoning: "Unsafe broad weakening", expectedOutcome: "allow_legitimate_call" }, policyYaml: source, request, attackFixtures: attacks });
    expect(result.verified).toBe(false);
    expect(result.results.join(" ")).toContain("removes deny rules");
  });
});
