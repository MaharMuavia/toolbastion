import { access, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { runProfessionalDemo } from "../../apps/cli/src/demo.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const proofSchema = z.object({
  version: z.literal(1),
  canarySha256: z.string().regex(/^[a-f0-9]{64}$/),
  directBaseline: z.object({
    canaryRead: z.literal(true),
    deliveryExecutions: z.literal(1),
    collectorRequests: z.object({ accepted: z.literal(1), attempted: z.literal(1) })
  }),
  protectedRun: z.object({
    safeRead: z.literal(true),
    targetExecutions: z.object({ before: z.literal(0), afterSafe: z.literal(1), afterTraversal: z.literal(1), afterSchemaMismatch: z.literal(1) }),
    traversalBlocked: z.literal(true),
    schemaMismatchBlocked: z.literal(true),
    deliveryExecutions: z.object({ before: z.literal(0), after: z.literal(0) }),
    collectorRequests: z.object({
      before: z.object({ accepted: z.literal(1), attempted: z.literal(1) }),
      after: z.object({ accepted: z.literal(1), attempted: z.literal(1) })
    }),
    loopbackBlocked: z.literal(true)
  }),
  audit: z.object({ sessionId: z.string().uuid(), valid: z.literal(true), eventCount: z.number().int().min(10) }),
  passed: z.literal(true)
});

describe("keyless attack-and-prevention proof", () => {
  it("shows a controlled direct compromise and a non-executing protected run without retaining the canary", async () => {
    const originalCanaryEnvironmentValue = process.env.TOOLBASTION_DEMO_CANARY;
    const result = await runProfessionalDemo(root, { cleanup: false });
    try {
      expect(result.passed).toBe(true);
      expect(process.env.TOOLBASTION_DEMO_CANARY).toBe(originalCanaryEnvironmentValue);
      const rawProof = await readFile(result.proofPath, "utf8");
      expect(rawProof).not.toContain("TOOLBASTION_SYNTHETIC_CANARY_");
      expect(proofSchema.parse(JSON.parse(rawProof))).toMatchObject({ passed: true });
      await expect(access(path.join(result.evidenceDirectory, "outside", "canary.txt"))).rejects.toThrow();
    } finally {
      await rm(result.evidenceDirectory, { recursive: true, force: true });
    }
  }, 20_000);
});
