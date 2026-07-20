#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, appendFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { loadEnvFile } from "node:process";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { parse } from "yaml";
import { z, ZodError } from "zod";
import { startApi } from "@toolbastion/api";
import { readAuditEvents, redactAuditPayload, resolveAuditReadFile, verifyAuditFile, verifyReceipt } from "@toolbastion/audit";
import { findValueBoundsViolation, ToolBastionProxy, ToolBastionTargetClient } from "@toolbastion/core";
import { createTrustBaseline, diffTrustBaseline, readTrustBaseline, writeTrustBaseline } from "@toolbastion/policy";
import { applyProposal, readProposal, rejectProposal, runCodexRemediation, saveProposal, verifyRemediation, type RemediationRequest } from "@toolbastion/remediation";
import { generateSessionReport, renderMarkdownReport } from "@toolbastion/reports";
import { formatZodIssues, sha256, TOOLBASTION_VERSION, toolbastionConfigSchema, type ToolBastionConfig } from "@toolbastion/shared";
import { runProfessionalDemo } from "./demo.js";

const VERSION = TOOLBASTION_VERSION;
const INSTALL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

try { loadEnvFile(path.resolve(".env.local")); } catch { /* Live mode remains explicitly unavailable. */ }

async function loadConfig(filePath: string) {
  const source = await readFile(filePath, "utf8");
  try {
    return toolbastionConfigSchema.parse(parse(source));
  } catch (error) {
    if (error instanceof ZodError) throw new Error(`Invalid policy:\n${formatZodIssues(error).map((issue) => `  - ${issue}`).join("\n")}`);
    throw error;
  }
}

function writeDiagnostic(message: string): void { process.stderr.write(`${message}\n`); }
function trustFile(projectRoot: string): string { return path.resolve(projectRoot, ".toolbastion", "toolbastion.lock.json"); }
function projectDirectory(projectRoot: string, configuredPath: string, label: string): string {
  const root = path.resolve(projectRoot);
  const candidate = path.resolve(root, configuredPath);
  const normalizeCase = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
  const relative = path.relative(normalizeCase(root), normalizeCase(candidate));
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error(`${label} must stay inside project_root`);
  return candidate;
}

async function discover(configPath: string) {
  const config = await loadConfig(configPath);
  const client = new ToolBastionTargetClient(config.target);
  try {
    await client.connect();
    return { config, tools: (await client.listTools()).tools };
  } finally {
    await client.close();
  }
}

const program = new Command()
  .name("toolbastion")
  .description("Local-first security gateway for MCP coding agents")
  .version(VERSION, "-V, --version", "print the ToolBastion version");

program.command("version").description("print the ToolBastion version").action(() => { process.stdout.write(`${VERSION}\n`); });

const policy = program.command("policy").description("validate and inspect ToolBastion policy");
policy.command("validate")
  .description("validate YAML and report precise paths")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.yaml")
  .action(async ({ config }: { config: string }) => {
    const parsed = await loadConfig(config);
    process.stdout.write(`VALID ${config} (version ${parsed.version}, mode ${parsed.mode})\n`);
  });

const trust = program.command("trust").description("manage persistent MCP tool trust");
trust.command("create")
  .description("create an initial target-specific trust baseline; refuses to overwrite one")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.yaml")
  .action(async ({ config: configPath }: { config: string }) => {
    const { config, tools } = await discover(configPath);
    const file = trustFile(config.project_root);
    try { await access(file, constants.F_OK); throw new Error("Trust baseline already exists; inspect its diff and use trust approve --yes"); }
    catch (error) { if (error instanceof Error && error.message.startsWith("Trust baseline")) throw error; }
    const baseline = createTrustBaseline(config.target.name, tools);
    await writeTrustBaseline(file, baseline);
    process.stdout.write(`CREATED ${file}\nBaseline ${baseline.baselineHash}\nTools ${baseline.tools.length}\n`);
  });
trust.command("approve")
  .description("approve a reviewed metadata diff for the configured target")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.yaml")
  .requiredOption("--yes", "confirm that the displayed target metadata diff was reviewed")
  .option("--actor <identity>", "operator identity", process.env.USERNAME ?? process.env.USER ?? "unknown")
  .action(async ({ config: configPath, yes, actor }: { config: string; yes: boolean; actor: string }) => {
    if (!yes) throw new Error("trust approve requires --yes after reviewing the displayed diff");
    const { config, tools } = await discover(configPath);
    const file = trustFile(config.project_root);
    const prior = await readTrustBaseline(file);
    const diff = diffTrustBaseline(prior, tools, config.target.name);
    process.stdout.write(`${JSON.stringify(diff, null, 2)}\n`);
    if (diff.poisoned.length > 0) throw new Error("Refusing to approve poisoned tool metadata");
    const baseline = createTrustBaseline(config.target.name, tools);
    await writeTrustBaseline(file, baseline);
    const auditDirectory = projectDirectory(config.project_root, config.audit.directory, "audit.directory");
    await mkdir(auditDirectory, { recursive: true });
    await appendFile(path.join(auditDirectory, "trust-approvals.jsonl"), `${JSON.stringify({ timestamp: new Date().toISOString(), actor, targetName: config.target.name, priorBaselineHash: prior.baselineHash, baselineHash: baseline.baselineHash, diff })}\n`, { encoding: "utf8", mode: 0o600 });
    process.stdout.write(`APPROVED ${file}\nBaseline ${baseline.baselineHash}\nActor ${actor}\n`);
  });
trust.command("inspect")
  .description("inspect the approved baseline")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.yaml")
  .action(async ({ config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    process.stdout.write(`${JSON.stringify(await readTrustBaseline(trustFile(config.project_root)), null, 2)}\n`);
  });
trust.command("diff")
  .description("compare current tools with the approved baseline")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.yaml")
  .action(async ({ config: configPath }: { config: string }) => {
    const { config, tools } = await discover(configPath);
    const diff = diffTrustBaseline(await readTrustBaseline(trustFile(config.project_root)), tools, config.target.name);
    process.stdout.write(`${JSON.stringify(diff, null, 2)}\n`);
    if (diff.added.length + diff.removed.length + diff.schemaChanged.length + diff.descriptionChanged.length + diff.poisoned.length > 0) process.exitCode = 2;
  });

const audit = program.command("audit").description("verify tamper-evident session logs");
audit.command("verify <session-id>")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.example.yaml")
  .action(async (sessionId: string, { config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    const file = await resolveAuditReadFile(config.project_root, config.audit.directory, sessionId);
    const verification = await verifyAuditFile(file);
    process.stdout.write(`${JSON.stringify({ sessionId, file, ...verification }, null, 2)}\n`);
    if (!verification.valid) process.exitCode = 2;
  });

const receipt = program.command("receipt").description("verify signed per-call receipts");
receipt.command("verify <file>")
  .description("verify receipt schema, Ed25519 signature, hashes, and lifecycle consistency")
  .action(async (file: string) => {
    const verification = verifyReceipt(JSON.parse(await readFile(file, "utf8")));
    process.stdout.write(`${JSON.stringify({ file: path.resolve(file), ...verification }, null, 2)}\n`);
    if (!verification.valid) process.exitCode = 2;
  });

program.command("report <session-id>")
  .description("regenerate a verified report from a session audit log")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.example.yaml")
  .option("-f, --format <format>", "json or markdown", "markdown")
  .option("-o, --output <path>", "write report to a file")
  .action(async (sessionId: string, options: { config: string; format: string; output?: string }) => {
    if (!new Set(["json", "markdown"]).has(options.format)) throw new Error("Report format must be json or markdown");
    const config = await loadConfig(options.config);
    const report = await generateSessionReport(await resolveAuditReadFile(config.project_root, config.audit.directory, sessionId));
    const rendered = options.format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderMarkdownReport(report);
    if (options.output) { await writeFile(options.output, rendered, "utf8"); process.stdout.write(`WROTE ${options.output}\n`); }
    else process.stdout.write(rendered);
  });

const remediation = program.command("remediation").description("review verified Codex policy proposals");
function remediationDirectory(config: Awaited<ReturnType<typeof loadConfig>>): string { return projectDirectory(config.project_root, config.remediation.directory, "remediation.directory"); }

async function readReplayArguments(filePath: string, config: ToolBastionConfig): Promise<Record<string, unknown>> {
  const resolved = path.resolve(filePath);
  const metadata = await stat(resolved);
  if (!metadata.isFile()) throw new Error("Replay arguments path must be a file");
  if (metadata.size > config.limits.max_argument_bytes) throw new Error("Replay arguments exceed max_argument_bytes");
  const source = await readFile(resolved, "utf8");
  if (Buffer.byteLength(source, "utf8") > config.limits.max_argument_bytes) throw new Error("Replay arguments exceed max_argument_bytes");
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error("Replay arguments must contain valid JSON");
  }
  const args = z.record(z.string(), z.unknown()).parse(parsed);
  const violation = findValueBoundsViolation(args, {
    maxBytes: config.limits.max_argument_bytes,
    maxDepth: config.limits.max_argument_depth,
    maxNodes: config.limits.max_argument_nodes
  });
  if (violation) throw new Error(`Replay arguments violate configured bounds: ${violation}`);
  return args;
}

async function remediationAttackFixtures(): Promise<Array<{ tool: string; args: Record<string, unknown>; category?: string }>> {
  return z.array(z.object({ tool: z.string(), args: z.record(z.string(), z.unknown()), category: z.string().optional() }))
    .parse(JSON.parse(await readFile(path.join(INSTALL_ROOT, "fixtures", "attacks", "day2-corpus.json"), "utf8")))
    .map((fixture) => fixture.category === undefined
      ? { tool: fixture.tool, args: fixture.args }
      : { tool: fixture.tool, args: fixture.args, category: fixture.category });
}

remediation.command("propose <session-id> <event-id>")
  .description("generate and verify a Codex proposal from a real blocked audit event")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.yaml")
  .requiredOption("--expected <outcome>", "allow_legitimate_call or keep_attack_blocked")
  .requiredOption("--args-file <path>", "JSON file containing the original blocked arguments")
  .action(async (sessionId: string, eventId: string, options: { config: string; expected: string; argsFile: string }) => {
    const expectedSecurityOutcome = new Set(["allow_legitimate_call", "keep_attack_blocked"]).has(options.expected)
      ? options.expected as RemediationRequest["expectedSecurityOutcome"]
      : undefined;
    if (!expectedSecurityOutcome) throw new Error("Expected outcome must be allow_legitimate_call or keep_attack_blocked");
    const config = await loadConfig(options.config);
    const events = await readAuditEvents(await resolveAuditReadFile(config.project_root, config.audit.directory, sessionId));
    const event = events.find((candidate) => candidate.eventType === "call_blocked" && (candidate.eventId === eventId || candidate.payload.eventId === eventId));
    if (!event) throw new Error(`Blocked event ${eventId} was not found in verified session ${sessionId}`);
    const payload = event.payload;
    const parsed = z.object({
      eventId: z.string(),
      toolName: z.string().min(1),
      argsHash: z.string().regex(/^[a-f0-9]{64}$/),
      deterministicEvidence: z.unknown().optional()
    }).parse(payload);
    const args = await readReplayArguments(options.argsFile, config);
    if (sha256(args) !== parsed.argsHash) throw new Error("Replay arguments do not match the redacted audit event");
    const request: RemediationRequest = {
      blockedEventId: parsed.eventId,
      decision: payload.reason === "operator_approval_required" ? "ASK_USER" : "BLOCK",
      toolName: parsed.toolName,
      args,
      deterministicEvidence: parsed.deterministicEvidence ?? [],
      expectedSecurityOutcome
    };
    const policyYaml = await readFile(options.config, "utf8");
    const output = await runCodexRemediation({
      request,
      config,
      schemaPath: path.join(INSTALL_ROOT, "schemas", "remediation.schema.json")
    });
    const verification = await verifyRemediation({ output, policyYaml, request, attackFixtures: await remediationAttackFixtures() });
    const proposal = await saveProposal(remediationDirectory(config), request, output, verification, policyYaml);
    process.stdout.write(`${JSON.stringify(proposal, null, 2)}\n`);
    if (!proposal.verified) process.exitCode = 2;
  });
remediation.command("inspect <proposal-id>")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.example.yaml")
  .action(async (proposalId: string, { config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    process.stdout.write(`${JSON.stringify(await readProposal(remediationDirectory(config), proposalId), null, 2)}\n`);
  });
remediation.command("reject <proposal-id>")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.example.yaml")
  .action(async (proposalId: string, { config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    process.stdout.write(`${JSON.stringify(await rejectProposal(remediationDirectory(config), proposalId), null, 2)}\n`);
  });
remediation.command("apply <proposal-id>")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.example.yaml")
  .option("--yes", "explicitly confirm applying the verified proposal", false)
  .requiredOption("--args-file <path>", "JSON file containing the original blocked arguments")
  .action(async (proposalId: string, options: { config: string; yes: boolean; argsFile: string }) => {
    if (!options.yes) throw new Error("Applying a policy proposal requires explicit confirmation with --yes");
    const config = await loadConfig(options.config);
    const proposal = await readProposal(remediationDirectory(config), proposalId);
    const request: RemediationRequest = {
      blockedEventId: proposal.blockedEventId,
      decision: proposal.decision,
      toolName: proposal.toolName,
      args: await readReplayArguments(options.argsFile, config),
      deterministicEvidence: [],
      expectedSecurityOutcome: proposal.expectedOutcome
    };
    const applied = await applyProposal({
      directory: remediationDirectory(config),
      proposalId,
      policyPath: path.resolve(options.config),
      actor: os.userInfo().username,
      request,
      attackFixtures: await remediationAttackFixtures()
    });
    process.stdout.write(`${JSON.stringify(applied, null, 2)}\n`);
  });

program.command("doctor")
  .description("check the local runtime and optional configuration")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.yaml")
  .action(async ({ config }: { config: string }) => {
    const [nodeMajor = 0, nodeMinor = 0] = process.versions.node.split(".").map((value) => Number.parseInt(value, 10));
    const supportedNode = nodeMajor > 22 || (nodeMajor === 22 && nodeMinor >= 12);
    let healthy = supportedNode;
    writeDiagnostic(`${supportedNode ? "PASS" : "FAIL"} Node.js ${process.versions.node} (requires >=22.12.0)`);
    writeDiagnostic(`PASS Platform ${process.platform}/${process.arch}`);
    try {
      await access(config, constants.R_OK);
      const parsed = await loadConfig(config);
      writeDiagnostic(`PASS Configuration ${config}`);
      if (parsed.target.isolation.provider === "docker") {
        const target = new ToolBastionTargetClient(parsed.target, () => undefined, () => Promise.resolve(), parsed.limits.tool_timeout_ms, parsed.project_root);
        await target.preflight();
        writeDiagnostic("PASS Docker target isolation image is available at its configured immutable digest");
      }
    } catch (error) {
      const missingConfig = typeof error === "object" && error !== null && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT";
      if (missingConfig) {
        writeDiagnostic(`WARN Configuration ${config}: unavailable`);
      } else {
        healthy = false;
        writeDiagnostic(`FAIL Configuration or target isolation ${config}: ${error instanceof Error ? error.message : "unavailable"}`);
      }
    }
    writeDiagnostic(`${process.env.OPENAI_API_KEY ? "PASS" : "INFO"} OpenAI API key ${process.env.OPENAI_API_KEY ? "is configured" : "is not configured (offline mode available)"}`);
    process.exitCode = healthy ? 0 : 1;
  });

program.command("dashboard")
  .description("start the localhost dashboard with live-event support and verified-fixture fallback")
  .option("-c, --config <path>", "configuration file", "toolbastion.config.example.yaml")
  .option("-p, --port <number>", "localhost port", "4782")
  .option("--event-log <path>", "runtime event log produced by toolbastion run")
  .option("--expose", "acknowledge an intentional non-localhost API bind", false)
  .action(async ({ config, port, eventLog, expose }: { config: string; port: string; eventLog?: string; expose: boolean }) => {
    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) throw new Error("Dashboard port must be between 1 and 65535");
    const rootDir = process.cwd();
    await startApi({
      rootDir,
      configPath: path.resolve(config),
      dashboardRoot: path.join(rootDir, "apps", "dashboard", "dist"),
      allowRemote: expose,
      ...(eventLog === undefined ? {} : { eventLogPath: path.resolve(eventLog) })
    }, parsedPort);
    writeDiagnostic(`ToolBastion dashboard listening on ${process.env.TOOLBASTION_API_HOST === "0.0.0.0" ? `container port ${parsedPort}` : `http://127.0.0.1:${parsedPort}`}`);
  });

program.command("run")
  .description("run ToolBastion as an MCP stdio server")
  .requiredOption("-c, --config <path>", "configuration file")
  .option("--event-log <path>", "redacted lifecycle log for the local dashboard")
  .action(async ({ config: configPath, eventLog }: { config: string; eventLog?: string }) => {
    const config = await loadConfig(configPath);
    const eventLogPath = path.resolve(eventLog ?? path.join(config.project_root, ".toolbastion", "runtime-events.jsonl"));
    await mkdir(path.dirname(eventLogPath), { recursive: true });
    await writeFile(eventLogPath, "", { encoding: "utf8", mode: 0o600 });
    let eventWrites = Promise.resolve();
    const writeRuntimeEvent = (event: unknown, emitDiagnostic = true) => {
      const redacted = redactAuditPayload(event);
      if (emitDiagnostic) writeDiagnostic(JSON.stringify(redacted));
      eventWrites = eventWrites
        .then(() => appendFile(eventLogPath, `${JSON.stringify(redacted)}\n`, { encoding: "utf8", mode: 0o600 }))
        .catch((error: unknown) => { writeDiagnostic(`WARN Dashboard lifecycle log unavailable: ${error instanceof Error ? error.message : "write failed"}`); });
    };
    const proxy = new ToolBastionProxy(config, writeRuntimeEvent);
    let closing = false;
    const heartbeat = setInterval(() => writeRuntimeEvent({ eventId: randomUUID(), timestamp: new Date().toISOString(), eventType: "heartbeat", payload: {} }, false), 5_000);
    heartbeat.unref();
    const shutdown = async () => {
      if (closing) return;
      closing = true;
      clearInterval(heartbeat);
      await proxy.close();
      await eventWrites;
    };
    const shutdownAndExit = () => {
      void shutdown()
        .then(() => process.exit(0))
        .catch((error: unknown) => {
          writeDiagnostic(`toolbastion: shutdown failed: ${error instanceof Error ? error.message : "unexpected error"}`);
          process.exit(1);
        });
    };
    process.once("SIGINT", shutdownAndExit);
    process.once("SIGTERM", shutdownAndExit);
    await proxy.runStdio();
    process.stdin.once("end", () => {
      void shutdown().catch((error: unknown) => {
        writeDiagnostic(`toolbastion: shutdown failed: ${error instanceof Error ? error.message : "unexpected error"}`);
        process.exitCode = 1;
      });
    });
    writeDiagnostic(`ToolBastion protecting target ${config.target.name} in ${config.mode} mode`);
  });

program.command("demo")
  .description("run a real keyless MCP enforcement proof and verify its audit chain")
  .option("--workspace <path>", "built ToolBastion workspace", process.cwd())
  .option("--cleanup", "remove the ignored evidence directory after verification", false)
  .action(async (options: { workspace: string; cleanup: boolean }) => {
    const result = await runProfessionalDemo(path.resolve(options.workspace), { cleanup: options.cleanup });
    if (!result.passed) process.exitCode = 2;
  });

program.parseAsync().catch((error: unknown) => {
  writeDiagnostic(`toolbastion: ${error instanceof Error ? error.message : "unexpected error"}`);
  process.exitCode = 1;
});
