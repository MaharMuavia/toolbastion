import { describe, expect, it } from "vitest";
import { canonicalJson, sha256, wardenConfigSchema } from "../../packages/shared/src/index.js";

describe("shared security primitives", () => {
  it("canonicalizes object keys before hashing", () => {
    expect(canonicalJson({ z: 1, a: { d: 2, b: 3 } })).toBe('{"a":{"b":3,"d":2},"z":1}');
    expect(sha256({ a: 1, b: 2 })).toBe(sha256({ b: 2, a: 1 }));
  });

  it("rejects unsupported configuration versions", () => {
    expect(() => wardenConfigSchema.parse({ version: 2, target: {} })).toThrow();
  });
});

