import { access, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ToolBastionProxy } from "../../packages/core/src/index.js";
import { toolbastionConfigSchema } from "../../packages/shared/src/index.js";

const projectRoots: string[] = [];

afterEach(async () => {
  await Promise.all(projectRoots.splice(0).map((projectRoot) => rm(projectRoot, { recursive: true, force: true })));
});

describe("Docker target preflight", () => {
  it("fails before opening an audit session when the immutable image is unavailable", async () => {
    const projectRoot = await mkdtemp(path.join(os.tmpdir(), "toolbastion-docker-preflight-"));
    projectRoots.push(projectRoot);
    const config = toolbastionConfigSchema.parse({
      version: 1,
      mode: "enforce",
      project_root: projectRoot,
      target: {
        name: "unavailable-isolated-target",
        command: "node",
        args: ["./server.js"],
        cwd: ".",
        isolation: { provider: "docker", image: `registry.example/unavailable@sha256:${"f".repeat(64)}` }
      },
      network: { target_egress: "isolated" },
      judge: { enabled: false, mode: "offline" }
    });

    const proxy = new ToolBastionProxy(config);
    await expect(proxy.runStdio()).rejects.toThrow(/Docker (is unavailable|image inspection failed|image is not available)/);
    await expect(access(path.join(projectRoot, ".toolbastion", "audit"))).rejects.toThrow();
  }, 15_000);
});
