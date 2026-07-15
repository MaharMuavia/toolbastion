import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse } from "yaml";
import { runCodexRemediation } from "@mcp-warden/remediation";
import { wardenConfigSchema } from "@mcp-warden/shared";

const workspace = process.cwd();
const policyYaml = await readFile(path.join(workspace, "warden.config.example.yaml"), "utf8");
const config = wardenConfigSchema.parse({ ...parse(policyYaml), remediation: { enabled: true, auto_apply: false, run_regression_suite: true, timeout_ms: 120_000 } });
const output = await runCodexRemediation({
  workspace,
  policyYaml,
  config,
  schemaPath: path.join(workspace, "schemas", "remediation.schema.json"),
  request: {
    blockedEventId: "smoke-attack-event",
    decision: "BLOCK",
    toolName: "read_project_file",
    args: { path: "[REDACTED:sensitive-path]" },
    deterministicEvidence: [{ category: "path_outside_project_root", severity: "critical" }],
    expectedSecurityOutcome: "keep_attack_blocked"
  }
});
process.stdout.write(`${JSON.stringify({ parsed: true, action: output.action, expectedOutcome: output.expectedOutcome })}\n`);
