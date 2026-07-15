#!/usr/bin/env node
import { constants } from "node:fs";
import { access, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { loadEnvFile } from "node:process";
import { Command } from "commander";
import { parse } from "yaml";
import { ZodError } from "zod";
import { startApi } from "@mcp-warden/api";
import { auditFilePath, verifyAuditFile } from "@mcp-warden/audit";
import { WardenProxy, WardenTargetClient } from "@mcp-warden/core";
import { createTrustBaseline, diffTrustBaseline, readTrustBaseline, writeTrustBaseline } from "@mcp-warden/policy";
import { applyProposal, readProposal, rejectProposal } from "@mcp-warden/remediation";
import { generateSessionReport, renderMarkdownReport } from "@mcp-warden/reports";
import { formatZodIssues, wardenConfigSchema } from "@mcp-warden/shared";

const VERSION = "0.1.0";

try { loadEnvFile(path.resolve(".env.local")); } catch { /* Live mode remains explicitly unavailable. */ }

async function loadConfig(filePath: string) {
  const source = await readFile(filePath, "utf8");
  try {
    return wardenConfigSchema.parse(parse(source));
  } catch (error) {
    if (error instanceof ZodError) throw new Error(`Invalid policy:\n${formatZodIssues(error).map((issue) => `  - ${issue}`).join("\n")}`);
    throw error;
  }
}

function writeDiagnostic(message: string): void { process.stderr.write(`${message}\n`); }
function trustFile(projectRoot: string): string { return path.resolve(projectRoot, ".warden", "warden.lock.json"); }

async function discover(configPath: string) {
  const config = await loadConfig(configPath);
  const client = new WardenTargetClient(config.target);
  try {
    await client.connect();
    return { config, tools: (await client.listTools()).tools };
  } finally {
    await client.close();
  }
}

const program = new Command()
  .name("warden")
  .description("Local-first security gateway for MCP coding agents")
  .version(VERSION, "-V, --version", "print the Warden version");

program.command("version").description("print the Warden version").action(() => { process.stdout.write(`${VERSION}\n`); });

const policy = program.command("policy").description("validate and inspect Warden policy");
policy.command("validate")
  .description("validate YAML and report precise paths")
  .option("-c, --config <path>", "configuration file", "warden.config.yaml")
  .action(async ({ config }: { config: string }) => {
    const parsed = await loadConfig(config);
    process.stdout.write(`VALID ${config} (version ${parsed.version}, mode ${parsed.mode})\n`);
  });

const trust = program.command("trust").description("manage persistent MCP tool trust");
for (const name of ["create", "approve"] as const) {
  trust.command(name)
    .description(`${name} the current target tool metadata`)
    .option("-c, --config <path>", "configuration file", "warden.config.yaml")
    .action(async ({ config: configPath }: { config: string }) => {
      const { config, tools } = await discover(configPath);
      const baseline = createTrustBaseline(config.target.name, tools);
      const file = trustFile(config.project_root);
      await writeTrustBaseline(file, baseline);
      process.stdout.write(`${name === "create" ? "CREATED" : "APPROVED"} ${file}\nBaseline ${baseline.baselineHash}\nTools ${baseline.tools.length}\n`);
    });
}
trust.command("inspect")
  .description("inspect the approved baseline")
  .option("-c, --config <path>", "configuration file", "warden.config.yaml")
  .action(async ({ config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    process.stdout.write(`${JSON.stringify(await readTrustBaseline(trustFile(config.project_root)), null, 2)}\n`);
  });
trust.command("diff")
  .description("compare current tools with the approved baseline")
  .option("-c, --config <path>", "configuration file", "warden.config.yaml")
  .action(async ({ config: configPath }: { config: string }) => {
    const { config, tools } = await discover(configPath);
    const diff = diffTrustBaseline(await readTrustBaseline(trustFile(config.project_root)), tools);
    process.stdout.write(`${JSON.stringify(diff, null, 2)}\n`);
    if (diff.added.length + diff.removed.length + diff.schemaChanged.length + diff.descriptionChanged.length + diff.poisoned.length > 0) process.exitCode = 2;
  });

const audit = program.command("audit").description("verify tamper-evident session logs");
audit.command("verify <session-id>")
  .option("-c, --config <path>", "configuration file", "warden.config.example.yaml")
  .action(async (sessionId: string, { config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    const file = auditFilePath(path.resolve(config.project_root, config.audit.directory), sessionId);
    const verification = await verifyAuditFile(file);
    process.stdout.write(`${JSON.stringify({ sessionId, file, ...verification }, null, 2)}\n`);
    if (!verification.valid) process.exitCode = 2;
  });

program.command("report <session-id>")
  .description("regenerate a verified report from a session audit log")
  .option("-c, --config <path>", "configuration file", "warden.config.example.yaml")
  .option("-f, --format <format>", "json or markdown", "markdown")
  .option("-o, --output <path>", "write report to a file")
  .action(async (sessionId: string, options: { config: string; format: string; output?: string }) => {
    if (!new Set(["json", "markdown"]).has(options.format)) throw new Error("Report format must be json or markdown");
    const config = await loadConfig(options.config);
    const report = await generateSessionReport(auditFilePath(path.resolve(config.project_root, config.audit.directory), sessionId));
    const rendered = options.format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderMarkdownReport(report);
    if (options.output) { await writeFile(options.output, rendered, "utf8"); process.stdout.write(`WROTE ${options.output}\n`); }
    else process.stdout.write(rendered);
  });

const remediation = program.command("remediation").description("review verified Codex policy proposals");
function remediationDirectory(config: Awaited<ReturnType<typeof loadConfig>>): string { return path.resolve(config.project_root, config.remediation.directory); }
remediation.command("inspect <proposal-id>")
  .option("-c, --config <path>", "configuration file", "warden.config.example.yaml")
  .action(async (proposalId: string, { config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    process.stdout.write(`${JSON.stringify(await readProposal(remediationDirectory(config), proposalId), null, 2)}\n`);
  });
remediation.command("reject <proposal-id>")
  .option("-c, --config <path>", "configuration file", "warden.config.example.yaml")
  .action(async (proposalId: string, { config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    process.stdout.write(`${JSON.stringify(await rejectProposal(remediationDirectory(config), proposalId), null, 2)}\n`);
  });
remediation.command("apply <proposal-id>")
  .option("-c, --config <path>", "configuration file", "warden.config.example.yaml")
  .option("--yes", "explicitly confirm applying the verified proposal", false)
  .action(async (proposalId: string, options: { config: string; yes: boolean }) => {
    if (!options.yes) throw new Error("Applying a policy proposal requires explicit confirmation with --yes");
    const config = await loadConfig(options.config);
    const proposal = await applyProposal(remediationDirectory(config), proposalId, path.resolve(options.config), os.userInfo().username);
    process.stdout.write(`${JSON.stringify(proposal, null, 2)}\n`);
  });

program.command("doctor")
  .description("check the local runtime and optional configuration")
  .option("-c, --config <path>", "configuration file", "warden.config.yaml")
  .action(async ({ config }: { config: string }) => {
    const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
    writeDiagnostic(`${nodeMajor >= 20 ? "PASS" : "FAIL"} Node.js ${process.versions.node} (requires >=20)`);
    writeDiagnostic(`PASS Platform ${process.platform}/${process.arch}`);
    try {
      await access(config, constants.R_OK);
      await loadConfig(config);
      writeDiagnostic(`PASS Configuration ${config}`);
    } catch (error) {
      writeDiagnostic(`WARN Configuration ${config}: ${error instanceof Error ? error.message : "unavailable"}`);
    }
    writeDiagnostic(`${process.env.OPENAI_API_KEY ? "PASS" : "INFO"} OpenAI API key ${process.env.OPENAI_API_KEY ? "is configured" : "is not configured (offline mode available)"}`);
    process.exitCode = nodeMajor >= 20 ? 0 : 1;
  });

program.command("dashboard")
  .description("start the localhost dashboard and fixture session API")
  .option("-c, --config <path>", "configuration file", "warden.config.example.yaml")
  .option("-p, --port <number>", "localhost port", "4782")
  .action(async ({ config, port }: { config: string; port: string }) => {
    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) throw new Error("Dashboard port must be between 1 and 65535");
    const rootDir = process.cwd();
    await startApi({ rootDir, configPath: path.resolve(config), dashboardRoot: path.join(rootDir, "apps", "dashboard", "dist") }, parsedPort);
    writeDiagnostic(`MCP Warden dashboard listening on ${process.env.WARDEN_API_HOST === "0.0.0.0" ? `container port ${parsedPort}` : `http://127.0.0.1:${parsedPort}`}`);
  });

program.command("run")
  .description("run Warden as an MCP stdio server")
  .requiredOption("-c, --config <path>", "configuration file")
  .action(async ({ config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    const proxy = new WardenProxy(config, (event) => writeDiagnostic(JSON.stringify(event)));
    const shutdown = async () => { await proxy.close(); process.exit(0); };
    process.once("SIGINT", () => { void shutdown(); });
    process.once("SIGTERM", () => { void shutdown(); });
    await proxy.runStdio();
    writeDiagnostic(`MCP Warden protecting target ${config.target.name} in ${config.mode} mode`);
  });

program.parseAsync().catch((error: unknown) => {
  writeDiagnostic(`warden: ${error instanceof Error ? error.message : "unexpected error"}`);
  process.exitCode = 1;
});
