import { randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { describe, expect, it } from "vitest";
import path from "node:path";
import { buildIsolatedTargetEnvironment, buildTargetEnvironment, resolveTargetArtifactIdentity } from "../../packages/core/src/index.js";

describe("target environment isolation", () => {
  it("inherits only the SDK safe baseline plus explicitly allowlisted variables", () => {
    const inherited = buildTargetEnvironment(["TOOLBASTION_ALLOWED"], {
      PATH: "safe-path",
      TOOLBASTION_ALLOWED: "allowed-value",
      TOOLBASTION_DENIED: "must-not-leak"
    });

    expect(inherited.TOOLBASTION_ALLOWED).toBe("allowed-value");
    expect(inherited.TOOLBASTION_DENIED).toBeUndefined();
  });

  it("ignores shell-function environment payloads", () => {
    expect(buildTargetEnvironment(["TOOLBASTION_FUNCTION"], { TOOLBASTION_FUNCTION: "() { malicious; }" }).TOOLBASTION_FUNCTION).toBeUndefined();
  });

  it("passes only explicitly allowlisted values into a Docker-isolated target", () => {
    const isolated = buildIsolatedTargetEnvironment(["TOOLBASTION_ALLOWED"], {
      PATH: "host-path-must-not-replace-container-path",
      HOME: "host-home-must-not-leak",
      TOOLBASTION_ALLOWED: "allowed-value",
      TOOLBASTION_DENIED: "must-not-leak"
    });

    expect(isolated).toEqual({ TOOLBASTION_ALLOWED: "allowed-value" });
  });

  it("changes the executable build identity when a target entry artifact changes", async () => {
    const root = path.join(os.tmpdir(), `toolbastion-artifact-${randomUUID()}`);
    await mkdir(root, { recursive: true });
    const entry = path.join(root, "target.js");
    try {
      await writeFile(entry, "export const version = 1;\n", "utf8");
      const target = { name: "artifact-target", command: process.execPath, args: [entry], cwd: root, envAllowlist: [] };
      const first = await resolveTargetArtifactIdentity(target, root);
      await writeFile(entry, "export const version = 2;\n", "utf8");
      const second = await resolveTargetArtifactIdentity(target, root);
      if (first.kind !== "executable" || second.kind !== "executable") throw new Error("Expected executable artifact identities");
      expect(first.executableHash).toBe(second.executableHash);
      expect(first.buildHash).not.toBe(second.buildHash);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
