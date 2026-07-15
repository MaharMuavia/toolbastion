import { access, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { stringify } from "yaml";
import { auditFilePath, verifyAuditFile } from "@toolbastion/audit";
import { ToolBastionTargetClient } from "@toolbastion/core";
import { createTrustBaseline, writeTrustBaseline } from "@toolbastion/policy";
import { toolbastionConfigSchema } from "@toolbastion/shared";

type DemoResult = { passed: boolean; evidenceDirectory: string; sessionId: string };

function textContent(result: Awaited<ReturnType<Client["callTool"]>>): string {
  return JSON.stringify(result.content);
}

function printResult(label: string, passed: boolean, detail: string): void {
  process.stdout.write(`${passed ? "PASS" : "FAIL"}  ${label.padEnd(30)} ${detail}\n`);
}

export async function runProfessionalDemo(workspace: string, options: { cleanup: boolean }): Promise<DemoResult> {
  const targetEntry = path.join(workspace, "examples", "vulnerable-server", "dist", "index.js");
  const cliEntry = path.join(workspace, "apps", "cli", "dist", "index.js");
  await access(targetEntry);
  await access(cliEntry);

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const evidenceDirectory = path.join(workspace, ".toolbastion", "demo", stamp);
  const projectRoot = path.join(evidenceDirectory, "project");
  const configPath = path.join(evidenceDirectory, "toolbastion.demo.yaml");
  await mkdir(path.join(projectRoot, "src"), { recursive: true });
  await writeFile(path.join(projectRoot, "src", "safe.ts"), "export const protectedByToolBastion = true;\n", "utf8");

  const target = {
    name: "vulnerable-demo",
    command: process.execPath,
    args: [targetEntry],
    cwd: workspace,
    envAllowlist: []
  };
  const discovery = new ToolBastionTargetClient(target);
  await discovery.connect();
  const tools = (await discovery.listTools()).tools;
  await discovery.close();
  await writeTrustBaseline(path.join(projectRoot, ".toolbastion", "toolbastion.lock.json"), createTrustBaseline(target.name, tools));

  const config = toolbastionConfigSchema.parse({
    version: 1,
    mode: "enforce",
    project_root: projectRoot,
    target: { ...target, env_allowlist: [] },
    paths: { allow: ["./src/**"], deny: ["**/.env", "**/.env.*", "**/.ssh/**", "**/.aws/**", "**/.azure/**"] },
    network: { default: "deny", allow_domains: ["api.github.com"] },
    tools: { default: "judge", rules: {
      read_project_file: { base_risk: "low", action: "allow_when_in_scope" },
      get_execution_count: { base_risk: "low", action: "allow" },
      emit_output: { base_risk: "low", action: "allow" }
    } },
    judge: { enabled: false, mode: "offline" },
    remediation: { enabled: false, auto_apply: false }
  });
  const serializable = { ...config, target: { ...config.target, env_allowlist: config.target.envAllowlist } };
  await writeFile(configPath, stringify(serializable), "utf8");

  const transport = new StdioClientTransport({ command: process.execPath, args: [cliEntry, "run", "--config", configPath], cwd: workspace, stderr: "pipe" });
  let diagnostics = "";
  transport.stderr?.on("data", (chunk: Buffer) => { diagnostics += chunk.toString("utf8"); });
  const client = new Client({ name: "toolbastion-professional-demo", version: "0.1.0" });
  let sessionId = "unknown";
  try {
    await client.connect(transport);
    const count = async () => {
      const result = await client.callTool({ name: "get_execution_count", arguments: {} });
      const content = result.content as Array<{ type: string; text?: string }>;
      return Number(content[0]?.text);
    };
    const before = await count();
    const safe = await client.callTool({ name: "read_project_file", arguments: { path: "src/safe.ts" } });
    const afterSafe = await count();
    const traversal = await client.callTool({ name: "read_project_file", arguments: { input: "../../.ssh/id_rsa" } });
    const afterTraversal = await count();
    const ssrf = await client.callTool({ name: "fetch_url", arguments: { value: "http://127.0.0.1/admin" } });
    const injection = await client.callTool({ name: "emit_output", arguments: { kind: "injection" } });
    const secret = await client.callTool({ name: "emit_output", arguments: { kind: "secret" } });

    const rows = [
      ["Safe in-scope tool call", safe.isError !== true && afterSafe === before + 1, `target executions ${before} -> ${afterSafe}`],
      ["Renamed-field traversal", traversal.isError === true && textContent(traversal).includes("path_outside_project_root") && afterTraversal === afterSafe, `target executions stayed ${afterTraversal}`],
      ["Renamed-field loopback SSRF", ssrf.isError === true && textContent(ssrf).includes("loopback_destination"), "blocked before network tool body"],
      ["Hostile tool output", injection.isError === true && textContent(injection).includes("QUARANTINE") && !textContent(injection).includes("Ignore previous instructions"), "prompt injection quarantined"],
      ["Credential-like output", !textContent(secret).includes("TOOLBASTION_TEST_SECRET_NOT_REAL") && textContent(secret).includes("[REDACTED:"), "secret redacted before forwarding"]
    ] as const;

    for (const line of diagnostics.split(/\r?\n/)) {
      try {
        const event = JSON.parse(line) as { eventType?: string; payload?: { sessionId?: string } };
        if (event.eventType === "session_started" && event.payload?.sessionId) sessionId = event.payload.sessionId;
      } catch { /* Human diagnostics are intentionally not JSON. */ }
    }
    if (sessionId === "unknown") throw new Error("Demo could not identify the audit session");
    const verification = await verifyAuditFile(auditFilePath(path.join(projectRoot, ".toolbastion", "audit"), sessionId));
    const auditPassed = verification.valid && verification.eventCount >= 10;

    process.stdout.write("\nTOOLBASTION — KEYLESS ENFORCEMENT PROOF\n\n");
    for (const [label, passed, detail] of rows) printResult(label, passed, detail);
    printResult("Tamper-evident audit chain", auditPassed, `${verification.eventCount} linked events verified`);
    const passed = rows.every(([, result]) => result) && auditPassed;
    process.stdout.write(`\n${passed ? "VERDICT  Enforcement proof passed" : "VERDICT  Enforcement proof failed"}\n`);
    if (options.cleanup) {
      await rm(evidenceDirectory, { recursive: true, force: true });
      process.stdout.write("EVIDENCE verified, then removed by --cleanup\n");
    } else {
      process.stdout.write(`EVIDENCE ${evidenceDirectory}\n`);
    }
    process.stdout.write(`SESSION  ${sessionId}\n`);
    return { passed, evidenceDirectory, sessionId };
  } finally {
    await transport.close();
  }
}
