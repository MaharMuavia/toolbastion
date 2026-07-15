#!/usr/bin/env node
import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import process from "node:process";
import { Command } from "commander";
import { parse } from "yaml";
import { WardenProxy } from "@mcp-warden/core";
import { wardenConfigSchema } from "@mcp-warden/shared";

const VERSION = "0.1.0";

async function loadConfig(path: string) {
  const source = await readFile(path, "utf8");
  return wardenConfigSchema.parse(parse(source));
}

function writeDiagnostic(message: string): void {
  process.stderr.write(`${message}\n`);
}

const program = new Command()
  .name("warden")
  .description("Local-first security gateway for MCP coding agents")
  .version(VERSION, "-V, --version", "print the Warden version");

program.command("version").description("print the Warden version").action(() => {
  process.stdout.write(`${VERSION}\n`);
});

program
  .command("doctor")
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

program
  .command("run")
  .description("run Warden as an MCP stdio server")
  .requiredOption("-c, --config <path>", "configuration file")
  .action(async ({ config: configPath }: { config: string }) => {
    const config = await loadConfig(configPath);
    const proxy = new WardenProxy(config.target, (event) => writeDiagnostic(JSON.stringify(event)));
    const shutdown = async () => {
      await proxy.close();
      process.exit(0);
    };
    process.once("SIGINT", () => { void shutdown(); });
    process.once("SIGTERM", () => { void shutdown(); });
    await proxy.runStdio();
    writeDiagnostic(`MCP Warden protecting target ${config.target.name} in ${config.mode} mode`);
  });

program.parseAsync().catch((error: unknown) => {
  writeDiagnostic(`warden: ${error instanceof Error ? error.message : "unexpected error"}`);
  process.exitCode = 1;
});
