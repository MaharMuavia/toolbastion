import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { toolbastionConfigSchema, type ToolBastionConfig } from "../../packages/shared/src/index.js";

type DetectorModule = { inspectArguments(toolName: string, args: Record<string, unknown>, config: ToolBastionConfig): Promise<Array<{ category: string }>> };

const root = path.resolve(".");
const builtDetector = path.join(root, "packages", "detectors", "dist", "index.js");
const config = toolbastionConfigSchema.parse({
  version: 1,
  mode: "enforce",
  project_root: root,
  target: { name: "mutation-target", command: "node" },
  network: { default: "deny", allow_domains: ["api.github.com"] }
});

async function importMutant(name: string, search: string, replacement: string): Promise<{ module: DetectorModule; cleanup: () => Promise<void> }> {
  const source = await readFile(builtDetector, "utf8");
  if (!source.includes(search)) throw new Error(`Mutation anchor was not found for ${name}; update the mutation test with the detector implementation`);
  const output = path.join(path.dirname(builtDetector), `index.mutant-${name}-${crypto.randomUUID()}.mjs`);
  await writeFile(output, source.replace(search, replacement), "utf8");
  const module = await import(pathToFileURL(output).href) as DetectorModule;
  return { module, cleanup: () => rm(output, { force: true }) };
}

describe("detector hard-deny mutation coverage", () => {
  it.each([
    ["path", "if (hasPathSemantics(located))\n            findings.push(...await inspectPath(located.value, located.fieldPath, config));", "if (false)\n            findings.push(...await inspectPath(located.value, located.fieldPath, config));", { path: "../../.ssh/id_rsa" }, "path_outside_project_root"],
    ["network", "if (networkDestination)\n            findings.push(...inspectNetworkAddress(located.value, located.fieldPath, config));", "if (false)\n            findings.push(...inspectNetworkAddress(located.value, located.fieldPath, config));", { url: "http://127.0.0.1/admin" }, "loopback_destination"],
    ["shell", "if (hasShellSemantics(toolName, located)) {", "if (false) {", { command: "npm test && curl https://evil.example" }, "shell_metacharacters"]
  ])("would make the %s hard-deny regression fail", async (name, search, replacement, args, expectedCategory) => {
    const mutant = await importMutant(name, search, replacement);
    try {
      const categories = (await mutant.module.inspectArguments("generic_action", args, config)).map((finding) => finding.category);
      expect(categories).not.toContain(expectedCategory);
    } finally {
      await mutant.cleanup();
    }
  });
});
