import path from "node:path";
import { describe, expect, it } from "vitest";
import { evaluateDeterministic } from "../../packages/policy/src/index.js";
import { toolbastionConfigSchema } from "../../packages/shared/src/index.js";

function config(toolCapabilities: Record<string, { filesystem: "none" | "read" | "write"; network: "none" | "deny" | "allowlist"; command_exec: boolean; subprocess: boolean; destructive: boolean }>, docker = false) {
  return toolbastionConfigSchema.parse({
    version: 1,
    mode: "enforce",
    project_root: path.resolve("."),
    target: docker
      ? { name: "capability-target", command: "node", isolation: { provider: "docker", image: `registry.example/tool@sha256:${"d".repeat(64)}` } }
      : { name: "capability-target", command: "node" },
    network: { default: "deny", allow_domains: ["api.github.com"] },
    tools: { default: "allow", rules: {} },
    capabilities: { tools: toolCapabilities }
  });
}

describe("capability authorization", () => {
  it("blocks a missing contract before detector heuristics can authorize a tool", async () => {
    const result = await evaluateDeterministic("innocent_status", {}, config({}));
    expect(result.resolution).toBe("HARD_DENY");
    expect(result.reasonCodes).toContain("missing_capability_contract");
  });

  it("rejects unsupported allowlisted egress and uncontained command capability", async () => {
    const allowlist = await evaluateDeterministic("fetch", { url: "https://api.github.com/repos" }, config({ fetch: { filesystem: "none", network: "allowlist", command_exec: false, subprocess: false, destructive: false } }));
    expect(allowlist.reasonCodes).toContain("network_allowlist_unsupported");
    const command = await evaluateDeterministic("run", { command: "npm test" }, config({ run: { filesystem: "none", network: "none", command_exec: true, subprocess: true, destructive: false } }));
    expect(command.reasonCodes).toContain("capability_containment_required");
  });

  it("allows an fs-only tool and accepts a declared network-denied capability only under Docker no-network containment", async () => {
    const fsOnly = await evaluateDeterministic("read", { path: "packages/shared/src/index.ts" }, config({ read: { filesystem: "read", network: "none", command_exec: false, subprocess: false, destructive: false } }));
    expect(fsOnly.resolution).toBe("SAFE");
    const contained = await evaluateDeterministic("fetch", { url: "https://api.github.com/repos" }, config({ fetch: { filesystem: "none", network: "deny", command_exec: false, subprocess: false, destructive: false } }, true));
    expect(contained.resolution).toBe("SAFE");
  });
});
