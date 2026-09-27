import { describe, expect, it } from "vitest";

import { commitmentRoot } from "../src/index.js";

describe("transparency scaffold", () => {
  it("computes deterministic commitment roots", () => {
    const commitments = [{ type: "POLICY_CHANGE", digest: "abc" }];

    expect(commitmentRoot(commitments)).toHaveLength(64);
    expect(commitmentRoot(commitments)).toBe(commitmentRoot(commitments));
  });
});
