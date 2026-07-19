import path from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalJson, sha256, toolbastionConfigSchema } from "../../packages/shared/src/index.js";

describe("shared security primitives", () => {
  it("canonicalizes object keys before hashing", () => {
    expect(canonicalJson({ z: 1, a: { d: 2, b: 3 } })).toBe('{"a":{"b":3,"d":2},"z":1}');
    expect(sha256({ a: 1, b: 2 })).toBe(sha256({ b: 2, a: 1 }));
  });

  it("rejects unsupported configuration versions", () => {
    expect(() => toolbastionConfigSchema.parse({ version: 2, target: {} })).toThrow();
  });

  it("rejects unknown settings and unsafe enforce-mode downgrades", () => {
    expect(() => toolbastionConfigSchema.parse({ version: 1, target: { name: "fixture", command: "node", unexpected: true } })).toThrow(/unrecognized key/i);
    expect(() => toolbastionConfigSchema.parse({ version: 1, mode: "enforce", target: { name: "fixture", command: "node" }, judge: { enabled: true, mode: "offline" } })).toThrow(/offline judge replay/i);
    expect(() => toolbastionConfigSchema.parse({ version: 1, mode: "enforce", target: { name: "fixture", command: "node" }, outputs: { inspect: false } })).toThrow(/output protection/i);
  });

  it("rejects IP, localhost, and resolver-magic network allowlist entries", () => {
    for (const domain of ["127.0.0.1", "localhost", "metadata.google.internal", "nip.io", "127.0.0.1.nip.io", "example.local"]) {
      expect(() => toolbastionConfigSchema.parse({ version: 1, target: { name: "fixture", command: "node" }, network: { allow_domains: [domain] } })).toThrow();
    }
  });

  it("rejects audit directories that can escape project_root", () => {
    for (const directory of ["../audit", "nested/../../audit", path.resolve("outside-audit")]) {
      expect(() => toolbastionConfigSchema.parse({ version: 1, target: { name: "fixture", command: "node" }, audit: { directory } })).toThrow(/directory must be a relative path inside project_root/i);
    }
  });
});
