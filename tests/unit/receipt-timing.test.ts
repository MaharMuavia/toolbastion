import { describe, expect, it } from "vitest";
import { ReceiptTiming, type Clock } from "../../packages/core/src/index.js";

function clockAt(...timestamps: string[]): Clock {
  let index = 0;
  return { now: () => new Date(timestamps[Math.min(index++, timestamps.length - 1)]!) };
}

describe("receipt timing", () => {
  it("captures acceptance once and finalizes once without wall-clock sleeps", () => {
    const timing = new ReceiptTiming(clockAt("2026-07-21T00:00:00.000Z", "2026-07-21T00:00:02.000Z", "2026-07-21T00:00:04.000Z"));
    expect(timing.startedAt).toBe("2026-07-21T00:00:00.000Z");
    expect(timing.complete()).toBe("2026-07-21T00:00:02.000Z");
    expect(timing.complete()).toBe("2026-07-21T00:00:02.000Z");
  });

  it("rejects a clock that would create a reversible receipt", () => {
    const timing = new ReceiptTiming(clockAt("2026-07-21T00:00:02.000Z", "2026-07-21T00:00:00.000Z"));
    expect(() => timing.complete()).toThrow("clock moved backwards");
  });
});
