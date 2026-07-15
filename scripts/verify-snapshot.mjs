import path from "node:path";
import process from "node:process";
import { verifyAuditFile } from "@mcp-warden/audit";

const file = path.resolve("apps", "dashboard", "public", "snapshot", "audit.jsonl");
const result = await verifyAuditFile(file);
process.stdout.write(`${JSON.stringify({ file, ...result }, null, 2)}\n`);
if (!result.valid) process.exitCode = 2;
