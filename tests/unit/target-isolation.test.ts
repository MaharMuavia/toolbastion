import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildDockerTargetCommand, ToolBastionProxy } from "../../packages/core/src/index.js";
import { targetServerConfigSchema, toolbastionConfigSchema } from "../../packages/shared/src/index.js";

const image = `registry.example/toolbastion-target@sha256:${"a".repeat(64)}`;

describe("Docker target isolation", () => {
  it("fails before accepting calls when receipt signing is required without a key", async () => {
    const prior = process.env.TOOLBASTION_RECEIPT_PRIVATE_KEY;
    delete process.env.TOOLBASTION_RECEIPT_PRIVATE_KEY;
    try {
      const config = toolbastionConfigSchema.parse({ version: 1, mode: "enforce", project_root: path.resolve("."), target: { name: "target", command: "node" }, receipts: { signing_required: true } });
      await expect(new ToolBastionProxy(config).runStdio()).rejects.toThrow("Receipt signing is required");
    } finally {
      if (prior === undefined) delete process.env.TOOLBASTION_RECEIPT_PRIVATE_KEY;
      else process.env.TOOLBASTION_RECEIPT_PRIVATE_KEY = prior;
    }
  });

  it("builds a pinned, networkless, read-only target launch with bounded resources", () => {
    const projectRoot = path.resolve(".");
    const target = targetServerConfigSchema.parse({
      name: "isolated-target",
      command: "node",
      args: ["./examples/benign-server/dist/index.js"],
      cwd: ".",
      env_allowlist: [],
      isolation: { provider: "docker", image, memory_mb: 256, cpus: 0.5, pids_limit: 64, tmpfs_size_mb: 32 }
    });

    const launch = buildDockerTargetCommand(target, projectRoot, { PATH: "/usr/local/bin", TOOLBASTION_ALLOWED: "allowed" });

    expect(launch.command).toBe("docker");
    expect(launch.args).toContain("--pull=never");
    expect(launch.args).toContain("--network=none");
    expect(launch.args).toContain("--read-only");
    expect(launch.args).toContain("--cap-drop=ALL");
    expect(launch.args).toContain("--security-opt=no-new-privileges");
    expect(launch.args).toContain("--user");
    expect(launch.args).toContain("1000:1000");
    expect(launch.args).toContain("--pids-limit");
    expect(launch.args).toContain("64");
    expect(launch.args).toContain("--memory");
    expect(launch.args).toContain("256m");
    expect(launch.args).toContain("--cpus");
    expect(launch.args).toContain("0.5");
    expect(launch.args).toContain("--tmpfs");
    expect(launch.args).toContain("/tmp:rw,noexec,nosuid,nodev,size=32m");
    expect(launch.args).toContain(`type=bind,src=${projectRoot},dst=/workspace/project,readonly`);
    expect(launch.args).toContain("--workdir");
    expect(launch.args).toContain("/workspace/project");
    expect(launch.args).toContain("/workspace/project/node_modules:rw,noexec,nosuid,nodev,size=16m");
    expect(launch.args).toContain("PATH");
    expect(launch.args).toContain("TOOLBASTION_ALLOWED");
    expect(launch.args).not.toContain("/usr/local/bin");
    expect(launch.args).not.toContain("allowed");
    expect(launch.args.slice(-3)).toEqual([image, "node", "./examples/benign-server/dist/index.js"]);
  });

  it("rejects mutable images, host-absolute execution paths, and unisolated egress exceptions", () => {
    expect(() => toolbastionConfigSchema.parse({
      version: 1,
      mode: "enforce",
      target: { name: "target", command: "node" },
      limits: { max_inflight_calls: 2 }
    })).toThrow(/one in-flight call/);

    expect(() => toolbastionConfigSchema.parse({
      version: 1,
      mode: "enforce",
      target: { name: "target", command: "node", isolation: { provider: "docker", image: "node:22" } },
      network: { target_egress: "isolated" }
    })).toThrow(/immutable sha256 digest/);

    expect(() => toolbastionConfigSchema.parse({
      version: 1,
      mode: "enforce",
      target: { name: "target", command: process.execPath, isolation: { provider: "docker", image } },
      network: { target_egress: "isolated" }
    })).toThrow(/available inside the pinned image/);

    expect(() => toolbastionConfigSchema.parse({
      version: 1,
      mode: "enforce",
      target: { name: "target", command: "node", cwd: "../outside", isolation: { provider: "docker", image } },
      network: { target_egress: "isolated" }
    })).toThrow(/cwd must be relative to project_root/);

    expect(() => toolbastionConfigSchema.parse({
      version: 1,
      mode: "enforce",
      target: { name: "target", command: "node" },
      network: { target_egress: "isolated" }
    })).toThrow(/requires Docker target isolation/);
  });
});
