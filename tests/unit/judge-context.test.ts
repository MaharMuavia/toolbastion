import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { loadJudgeContext } from "../../packages/core/src/index.js";
import { toolbastionConfigSchema } from "../../packages/shared/src/index.js";

const temporary = path.resolve(".test-tmp", "judge-context");

function config(contextFile?: string, maxBytes = 8_192) {
  return toolbastionConfigSchema.parse({
    version: 1,
    mode: "enforce",
    project_root: temporary,
    target: { name: "test", command: "node" },
    judge: { enabled: true, mode: "live", context_file: contextFile, context_max_bytes: maxBytes }
  });
}

afterAll(async () => rm(temporary, { recursive: true, force: true }));

describe("bounded local judge context", () => {
  it("labels missing context explicitly", async () => {
    expect(await loadJudgeContext(config())).toMatchObject({ status: "unavailable", reason: "context_file_not_configured" });
  });

  it("loads in-project context and redacts credential-like content", async () => {
    await mkdir(temporary, { recursive: true });
    const syntheticCredential = ["sk", "proj", "NOT_A_REAL_SECRET_123456"].join("-");
    await writeFile(path.join(temporary, "intent.txt"), `Run project tests with ${syntheticCredential}`, "utf8");
    const context = await loadJudgeContext(config("intent.txt"));
    expect(context.status).toBe("available");
    expect(context.summary).toContain("Run project tests");
    expect(context.summary).toContain("[REDACTED:secret]");
    expect(context.summary).not.toContain("NOT_A_REAL_SECRET_123456");
  });

  it("rejects context outside the configured project root and oversized files", async () => {
    await mkdir(temporary, { recursive: true });
    await writeFile(path.join(temporary, "large.txt"), "1234567890", "utf8");
    expect(await loadJudgeContext(config("../outside.txt"))).toMatchObject({ status: "unavailable", reason: "context_file_outside_project_root" });
    expect(await loadJudgeContext(config("large.txt", 4))).toMatchObject({ status: "unavailable", reason: "context_file_too_large" });
  });
});
