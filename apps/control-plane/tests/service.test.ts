import { describe, expect, it } from "vitest";

import { describeControlPlane } from "../src/index.js";

describe("control plane scaffold", () => {
  it("keeps control plane off the verifier hot path", () => {
    expect(describeControlPlane()).toMatchObject({ hotPath: false });
  });
});
