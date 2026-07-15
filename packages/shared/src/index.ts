import { createHash } from "node:crypto";
import { z } from "zod";

export const runtimeModeSchema = z.enum(["shadow", "interactive", "enforce"]);
export type RuntimeMode = z.infer<typeof runtimeModeSchema>;

export const targetServerConfigSchema = z.object({
  name: z.string().trim().min(1),
  command: z.string().trim().min(1),
  args: z.array(z.string()).default([]),
  cwd: z.string().optional(),
  envAllowlist: z.array(z.string()).default([])
});
export type TargetServerConfig = z.infer<typeof targetServerConfigSchema>;

export const wardenConfigSchema = z.object({
  version: z.literal(1),
  mode: runtimeModeSchema.default("shadow"),
  target: targetServerConfigSchema
});
export type WardenConfig = z.infer<typeof wardenConfigSchema>;

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, canonicalize(child)])
    );
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

