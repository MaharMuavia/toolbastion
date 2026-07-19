import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { access, mkdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import process from "node:process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { stringify } from "yaml";
import { auditFilePath, verifyAuditFile } from "@toolbastion/audit";
import { ToolBastionTargetClient } from "@toolbastion/core";
import { createTrustBaseline, writeTrustBaseline } from "@toolbastion/policy";
import { toolbastionConfigSchema } from "@toolbastion/shared";

type DemoResult = { passed: boolean; evidenceDirectory: string; sessionId: string; proofPath: string };
type ProofCollector = {
  url: string;
  acceptedRequests: () => number;
  attemptedRequests: () => number;
  close: () => Promise<void>;
};

function resultContent(result: unknown): unknown {
  if (result === null || typeof result !== "object" || Array.isArray(result)) return undefined;
  return (result as Record<string, unknown>).content;
}

function textContent(result: unknown): string {
  return JSON.stringify(resultContent(result)) ?? "";
}

function numericToolResult(result: unknown): number | undefined {
  const content = resultContent(result);
  if (!Array.isArray(content)) return undefined;
  const first = (content as unknown[])[0];
  if (first === null || typeof first !== "object" || Array.isArray(first)) return undefined;
  const text = (first as Record<string, unknown>).text;
  if (typeof text !== "string" || !/^\d+$/.test(text)) return undefined;
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : undefined;
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function printResult(label: string, passed: boolean, detail: string): void {
  process.stdout.write(`${passed ? "PASS" : "FAIL"}  ${label.padEnd(34)} ${detail}\n`);
}

function matchesSyntheticCanary(candidate: string | undefined, expected: string): boolean {
  if (candidate === undefined) return false;
  const candidateBytes = Buffer.from(candidate, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  return candidateBytes.length === expectedBytes.length && timingSafeEqual(candidateBytes, expectedBytes);
}

async function startLoopbackCollector(expectedCanary: string): Promise<ProofCollector> {
  let acceptedRequestCount = 0;
  let attemptedRequestCount = 0;
  const server = createServer((request, response) => {
    attemptedRequestCount += 1;
    const header = request.headers["x-toolbastion-demo-canary"];
    if (request.method === "GET" && request.url === "/collect" && typeof header === "string" && matchesSyntheticCanary(header, expectedCanary)) {
      acceptedRequestCount += 1;
      response.writeHead(204);
      response.end();
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    throw new Error("Loopback collector did not expose a TCP port");
  }
  return {
    url: `http://127.0.0.1:${address.port}/collect`,
    acceptedRequests: () => acceptedRequestCount,
    attemptedRequests: () => attemptedRequestCount,
    close: async () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  };
}

async function waitForSealedAudit(filePath: string): Promise<Awaited<ReturnType<typeof verifyAuditFile>>> {
  let last = { valid: false, eventCount: 0, errors: ["audit session did not seal"] };
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const verification = await verifyAuditFile(filePath);
      if (verification.valid) return verification;
      last = verification;
    } catch (error) {
      last = { valid: false, eventCount: 0, errors: [error instanceof Error ? error.message : "audit session is unavailable"] };
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
  }
  return last;
}

export async function runProfessionalDemo(workspace: string, options: { cleanup: boolean }): Promise<DemoResult> {
  const targetEntry = path.join(workspace, "examples", "vulnerable-server", "dist", "index.js");
  const cliEntry = path.join(workspace, "apps", "cli", "dist", "index.js");
  await access(targetEntry);
  await access(cliEntry);

  const stamp = `${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
  const evidenceDirectory = path.join(workspace, ".toolbastion", "demo", stamp);
  const projectRoot = path.join(evidenceDirectory, "project");
  const outsideDirectory = path.join(evidenceDirectory, "outside");
  const configPath = path.join(evidenceDirectory, "toolbastion.demo.yaml");
  const proofPath = path.join(evidenceDirectory, "proof.json");
  const canary = `TOOLBASTION_SYNTHETIC_CANARY_${randomUUID()}`;
  const canaryHash = sha256Text(canary);
  const canaryEnvironmentName = "TOOLBASTION_DEMO_CANARY";
  const previousCanaryEnvironmentValue = process.env[canaryEnvironmentName];
  const safeSource = "export const protectedByToolBastion = true;\n";
  const safeHash = sha256Text(safeSource);
  let collector: ProofCollector | undefined;
  let transport: StdioClientTransport | undefined;
  let transportClosed = false;
  try {
    await mkdir(path.join(projectRoot, "src"), { recursive: true });
    await mkdir(outsideDirectory, { recursive: true });
    await writeFile(path.join(projectRoot, "src", "safe.ts"), safeSource, "utf8");
    await writeFile(path.join(outsideDirectory, "canary.txt"), canary, { encoding: "utf8", mode: 0o600 });
    process.env[canaryEnvironmentName] = canary;
    collector = await startLoopbackCollector(canary);

    const target = {
      name: "vulnerable-demo",
      command: process.execPath,
      args: [targetEntry, "--demo-project-root", projectRoot, "--demo-collector-url", collector.url],
      cwd: workspace,
      envAllowlist: [canaryEnvironmentName]
    };
    const directTarget = new ToolBastionTargetClient(target);
    let tools: Awaited<ReturnType<ToolBastionTargetClient["listTools"]>>["tools"] = [];
    let directCanaryRead = false;
    let directCollectorRequest = false;
    let directDeliveryExecutions = 0;
    try {
      await directTarget.connect();
      tools = (await directTarget.listTools()).tools;
      const read = await directTarget.callTool("read_project_file", { path: "../outside/canary.txt" });
      directCanaryRead = textContent(read).includes(`VULNERABLE_TARGET_READ_SHA256:${canaryHash}`);
      const fetchResult = await directTarget.callTool("fetch_url", { url: collector.url });
      directDeliveryExecutions = numericToolResult(await directTarget.callTool("get_canary_delivery_count", {})) ?? 0;
      directCollectorRequest = textContent(fetchResult).includes("VULNERABLE_TARGET_NETWORK_REQUEST:204")
        && directDeliveryExecutions === 1
        && collector.acceptedRequests() === 1
        && collector.attemptedRequests() === 1;
    } finally {
      await directTarget.close().catch(() => undefined);
    }
    if (tools.length === 0) throw new Error("Direct vulnerable target did not expose tools");
    await writeTrustBaseline(path.join(projectRoot, ".toolbastion", "toolbastion.lock.json"), createTrustBaseline(target.name, tools));

    const config = toolbastionConfigSchema.parse({
      version: 1,
      mode: "enforce",
      project_root: projectRoot,
      target: { name: target.name, command: target.command, args: target.args, cwd: target.cwd, env_allowlist: target.envAllowlist },
      paths: { allow: ["./src/**"], deny: ["**/.env", "**/.env.*", "**/.ssh/**", "**/.aws/**", "**/.azure/**"] },
      network: { default: "deny", allow_domains: ["api.github.com"] },
      tools: { default: "judge", rules: {
        read_project_file: { base_risk: "low", action: "allow_when_in_scope" },
        get_execution_count: { base_risk: "low", action: "allow" },
        get_canary_delivery_count: { base_risk: "low", action: "allow" },
        emit_output: { base_risk: "low", action: "allow" }
      } },
      judge: { enabled: false, mode: "offline" },
      remediation: { enabled: false, auto_apply: false }
    });
    const { envAllowlist, ...targetConfig } = config.target;
    const serializable = { ...config, target: { ...targetConfig, env_allowlist: envAllowlist } };
    await writeFile(configPath, stringify(serializable), "utf8");

    transport = new StdioClientTransport({
      command: process.execPath,
      args: [cliEntry, "run", "--config", configPath],
      cwd: workspace,
      env: { ...getDefaultEnvironment(), [canaryEnvironmentName]: canary },
      stderr: "pipe"
    });
    let diagnostics = "";
    transport.stderr?.on("data", (chunk: Buffer) => { diagnostics += chunk.toString("utf8"); });
    const client = new Client({ name: "toolbastion-professional-demo", version: "0.1.0" });
    let sessionId = "unknown";
    await client.connect(transport);
    const count = async (toolName: "get_execution_count" | "get_canary_delivery_count") => {
      const result = await client.callTool({ name: toolName, arguments: {} });
      const countValue = numericToolResult(result);
      if (countValue === undefined) throw new Error(`${toolName} returned an invalid execution count`);
      return countValue;
    };
    const before = await count("get_execution_count");
    const safe = await client.callTool({ name: "read_project_file", arguments: { path: "src/safe.ts" } });
    const afterSafe = await count("get_execution_count");
    const traversal = await client.callTool({ name: "read_project_file", arguments: { path: "../outside/canary.txt" } });
    const afterTraversal = await count("get_execution_count");
    const schemaMismatch = await client.callTool({ name: "read_project_file", arguments: { input: "../outside/canary.txt" } });
    const afterSchemaMismatch = await count("get_execution_count");
    const deliveryBeforeProtectedCall = await count("get_canary_delivery_count");
    const collectorBeforeProtectedCall = { accepted: collector.acceptedRequests(), attempted: collector.attemptedRequests() };
    const ssrf = await client.callTool({ name: "fetch_url", arguments: { url: collector.url } });
    const deliveryAfterProtectedCall = await count("get_canary_delivery_count");
    const collectorAfterProtectedCall = { accepted: collector.acceptedRequests(), attempted: collector.attemptedRequests() };
    const injection = await client.callTool({ name: "emit_output", arguments: { kind: "injection" } });
    const secret = await client.callTool({ name: "emit_output", arguments: { kind: "secret" } });

    const rows = [
      ["Direct vulnerable canary read", directCanaryRead, "target returned only the synthetic canary hash"],
      ["Direct loopback collector request", directCollectorRequest, "collector validated one synthetic marker delivery"],
      ["Protected in-scope file read", safe.isError !== true && textContent(safe).includes(`VULNERABLE_TARGET_READ_SHA256:${safeHash}`) && afterSafe === before + 1, `target executions ${before} -> ${afterSafe}`],
      ["Protected path traversal", traversal.isError === true && textContent(traversal).includes("path_outside_project_root") && afterTraversal === afterSafe, `target executions stayed ${afterTraversal}`],
      ["Protected undeclared argument", schemaMismatch.isError === true && textContent(schemaMismatch).includes("input_schema_invalid") && afterSchemaMismatch === afterTraversal, `target executions stayed ${afterSchemaMismatch}`],
      ["Protected loopback exfiltration", ssrf.isError === true && textContent(ssrf).includes("loopback_destination") && deliveryAfterProtectedCall === deliveryBeforeProtectedCall && collectorAfterProtectedCall.accepted === collectorBeforeProtectedCall.accepted && collectorAfterProtectedCall.attempted === collectorBeforeProtectedCall.attempted, `target delivery executions ${deliveryBeforeProtectedCall} -> ${deliveryAfterProtectedCall}; collector attempts stayed ${collectorAfterProtectedCall.attempted}`],
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
    await transport.close();
    transportClosed = true;
    const verification = await waitForSealedAudit(auditFilePath(path.join(projectRoot, ".toolbastion", "audit"), sessionId));
    const auditPassed = verification.valid && verification.eventCount >= 10;
    const passed = rows.every(([, result]) => result) && auditPassed;
    const proof = {
      version: 1,
      canarySha256: canaryHash,
      directBaseline: {
        canaryRead: directCanaryRead,
        deliveryExecutions: directDeliveryExecutions,
        collectorRequests: collectorBeforeProtectedCall
      },
      protectedRun: {
        safeRead: !safe.isError && afterSafe === before + 1,
        targetExecutions: { before, afterSafe, afterTraversal, afterSchemaMismatch },
        traversalBlocked: traversal.isError === true,
        schemaMismatchBlocked: schemaMismatch.isError === true,
        deliveryExecutions: { before: deliveryBeforeProtectedCall, after: deliveryAfterProtectedCall },
        collectorRequests: { before: collectorBeforeProtectedCall, after: collectorAfterProtectedCall },
        loopbackBlocked: ssrf.isError === true
      },
      audit: { sessionId, valid: verification.valid, eventCount: verification.eventCount },
      passed
    };
    await writeFile(proofPath, `${JSON.stringify(proof, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });

    process.stdout.write("\nTOOLBASTION - KEYLESS ATTACK-AND-PREVENTION PROOF\n\n");
    for (const [label, result, detail] of rows) printResult(label, result, detail);
    printResult("Sealed tamper-evident audit", auditPassed, `${verification.eventCount} linked events verified`);
    process.stdout.write(`\n${passed ? "VERDICT  Enforcement proof passed" : "VERDICT  Enforcement proof failed"}\n`);
    if (options.cleanup) {
      await rm(evidenceDirectory, { recursive: true, force: true });
      process.stdout.write("EVIDENCE verified, then removed by --cleanup\n");
    } else {
      process.stdout.write(`EVIDENCE ${evidenceDirectory}\n`);
      process.stdout.write(`PROOF    ${proofPath}\n`);
    }
    process.stdout.write(`SESSION  ${sessionId}\n`);
    return { passed, evidenceDirectory, sessionId, proofPath };
  } finally {
    if (!transportClosed) await transport?.close().catch(() => undefined);
    await collector?.close().catch(() => undefined);
    await rm(outsideDirectory, { recursive: true, force: true }).catch(() => undefined);
    if (previousCanaryEnvironmentValue === undefined) delete process.env[canaryEnvironmentName];
    else process.env[canaryEnvironmentName] = previousCanaryEnvironmentValue;
  }
}
