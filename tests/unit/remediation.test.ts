import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parse, stringify } from "yaml";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyProposal, codexExecArguments, readProposal, runCodexRemediation, saveProposal, verifyRemediation, type RemediationRequest } from "@toolbastion/remediation";
import { remediationOutputSchema, toolbastionConfigSchema } from "@toolbastion/shared";

const current = toolbastionConfigSchema.parse({
  version: 1,
  mode: "enforce",
  target: { name: "fixture", command: "node", isolation: { provider: "docker", image: `registry.example/toolbastion-target@sha256:${"c".repeat(64)}` } },
  paths: { allow: ["./**"], deny: ["**/.env", "**/.ssh/**"] },
  network: { default: "deny", allow_domains: [], deny_private_ips: true, deny_loopback: true, deny_link_local: true, deny_metadata_endpoints: true, target_egress: "isolated" },
  tools: { default: "judge", rules: { fetch_url: { action: "allow_when_in_scope", base_risk: "medium" } } }
});
const request: RemediationRequest = {
  blockedEventId: "event-1",
  decision: "BLOCK",
  toolName: "fetch_url",
  args: { url: "https://api.example.com/data" },
  deterministicEvidence: [],
  expectedSecurityOutcome: "allow_legitimate_call"
};
const attacks = [
  { tool: "fetch_url", args: { url: "http://127.0.0.1/private" }, category: "loopback_ssrf" },
  { tool: "read_project_file", args: { path: "../../.ssh/id_rsa" }, category: "path_traversal" }
];
const integrityKey = "test-remediation-integrity-key-32-bytes";
const priorIntegrityKey = process.env.TOOLBASTION_REMEDIATION_HMAC_KEY;

beforeAll(() => { process.env.TOOLBASTION_REMEDIATION_HMAC_KEY = integrityKey; });
afterAll(() => {
  if (priorIntegrityKey === undefined) delete process.env.TOOLBASTION_REMEDIATION_HMAC_KEY;
  else process.env.TOOLBASTION_REMEDIATION_HMAC_KEY = priorIntegrityKey;
});

function configYaml(config: typeof current): string {
  const { envAllowlist, ...target } = config.target;
  return stringify({ ...config, target: { ...target, env_allowlist: envAllowlist } });
}

const addHostOutput = {
  action: "ADD_EXACT_REQUEST_HOST" as const,
  reasoning: "The operator declared a legitimate public destination and local verification will add only its exact host.",
  expectedOutcome: "allow_legitimate_call" as const
};

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

  it("accepts only a locally derived exact-host exception while retaining attack blocks", async () => {
    const source = configYaml(current);
    const result = await verifyRemediation({ output: addHostOutput, policyYaml: source, request, attackFixtures: attacks });
    expect(result.verified).toBe(true);
    expect(result.operation).toEqual({ kind: "add_exact_network_domain", domain: "api.example.com" });
    expect(result.patchedYaml).toContain("api.example.com");
  });

  it("rejects ambiguous, private, and sensitive request destinations", async () => {
    const source = configYaml(current);
    const multipleHosts = await verifyRemediation({
      output: addHostOutput,
      policyYaml: source,
      request: { ...request, args: { first: "https://api.example.com/data", second: "https://other.example.com/data" } },
      attackFixtures: attacks
    });
    expect(multipleHosts.verified).toBe(false);
    expect(multipleHosts.results.join(" ")).toContain("exactly one public HTTP(S) host");

    const privateHost = await verifyRemediation({
      output: addHostOutput,
      policyYaml: source,
      request: { ...request, args: { url: "http://127.0.0.1/private" } },
      attackFixtures: attacks
    });
    expect(privateHost.verified).toBe(false);
    expect(privateHost.results.join(" ")).toContain("public DNS host");

    const sensitiveQuery = await verifyRemediation({
      output: addHostOutput,
      policyYaml: source,
      request: { ...request, args: { url: "https://api.example.com/data?token=opaque" } },
      attackFixtures: attacks
    });
    expect(sensitiveQuery.verified).toBe(false);
    expect(sensitiveQuery.results.join(" ")).toContain("sensitive query");
  });

  it("rejects freeform model diffs and a no-change answer for a requested allow", () => {
    expect(() => remediationOutputSchema.parse({ ...addHostOutput, unifiedDiff: "--- policy" })).toThrow();
    expect(() => remediationOutputSchema.parse({ action: "NO_CHANGE", reasoning: "No change", expectedOutcome: "allow_legitimate_call" })).toThrow();
  });

  it("does not expose raw policy, arguments, project files, or arbitrary environment variables to Codex", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "toolbastion-remediation-runner-"));
    const runner = path.join(directory, "fake-codex.mjs");
    const environmentKey = "TOOLBASTION_REMEDIATION_ENV_SENTINEL";
    const priorEnvironment = process.env[environmentKey];
    await writeFile(runner, `
      import { readdir, writeFile } from "node:fs/promises";
      let prompt = "";
      for await (const chunk of process.stdin) prompt += chunk.toString();
      const args = process.argv.slice(2);
      const output = args[args.indexOf("--output-last-message") + 1];
      const files = await readdir(process.cwd());
      const leaked = prompt.includes("argument-raw-sentinel")
        || prompt.includes("policy-raw-sentinel")
        || process.env.TOOLBASTION_REMEDIATION_ENV_SENTINEL !== undefined
        || files.length !== 0;
      await writeFile(output, JSON.stringify({
        action: "ADD_EXACT_REQUEST_HOST",
        reasoning: leaked ? "leaked" : "clean",
        expectedOutcome: "allow_legitimate_call"
      }));
    `, "utf8");
    process.env[environmentKey] = "environment-raw-sentinel";
    try {
      const config = toolbastionConfigSchema.parse(parse(configYaml({
        ...current,
        target: { ...current.target, args: ["policy-raw-sentinel"] },
        remediation: { ...current.remediation, enabled: true, timeout_ms: 5_000 }
      })));
      const output = await runCodexRemediation({
        request: { ...request, args: { url: "https://api.example.com/argument-raw-sentinel" } },
        config,
        schemaPath: path.resolve("schemas", "remediation.schema.json"),
        executable: process.execPath,
        executableArgs: [runner]
      });
      expect(output.reasoning).toBe("clean");
    } finally {
      if (priorEnvironment === undefined) delete process.env[environmentKey];
      else process.env[environmentKey] = priorEnvironment;
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses stale policies and replay arguments that do not match the verified proposal", async () => {
    const source = configYaml(current);
    const verification = await verifyRemediation({ output: addHostOutput, policyYaml: source, request, attackFixtures: attacks });
    expect(verification.verified).toBe(true);
    const directory = await mkdtemp(path.join(os.tmpdir(), "toolbastion-remediation-test-"));
    try {
      const policyPath = path.join(directory, "toolbastion.config.yaml");
      await writeFile(policyPath, configYaml({ ...current, network: { ...current.network, allow_domains: ["other.example.com"] } }), "utf8");
      const proposal = await saveProposal(directory, request, addHostOutput, verification, source);
      await expect(applyProposal({
        directory,
        proposalId: proposal.proposalId,
        policyPath,
        actor: "tester",
        request,
        attackFixtures: attacks
      })).rejects.toThrow(/changed since proposal verification/);

      await writeFile(policyPath, source, "utf8");
      await expect(applyProposal({
        directory,
        proposalId: proposal.proposalId,
        policyPath,
        actor: "tester",
        request: { ...request, args: { url: "https://api.example.com/different" } },
        attackFixtures: attacks
      })).rejects.toThrow(/Replay arguments do not match/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects a locally modified remediation proposal before it can be applied", async () => {
    const source = configYaml(current);
    const verification = await verifyRemediation({ output: addHostOutput, policyYaml: source, request, attackFixtures: attacks });
    const directory = await mkdtemp(path.join(os.tmpdir(), "toolbastion-remediation-integrity-"));
    try {
      const proposal = await saveProposal(directory, request, addHostOutput, verification, source);
      const proposalPath = path.join(directory, `${proposal.proposalId}.json`);
      const tampered = JSON.parse(await readFile(proposalPath, "utf8")) as Record<string, unknown>;
      tampered.verified = false;
      await writeFile(proposalPath, JSON.stringify(tampered), "utf8");
      await expect(readProposal(directory, proposal.proposalId)).rejects.toThrow(/hash verification failed/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
