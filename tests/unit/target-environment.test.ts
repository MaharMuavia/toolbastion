import { describe, expect, it } from "vitest";
import { buildTargetEnvironment } from "../../packages/core/src/index.js";

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
});
