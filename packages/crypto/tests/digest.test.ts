import { describe, expect, it } from "vitest";

import { sha256Hex } from "../src/index.js";

describe("digest helpers", () => {
  it("computes stable sha256 hex", () => {
    expect(sha256Hex("aidenid")).toHaveLength(64);
    expect(sha256Hex("aidenid")).toBe(sha256Hex("aidenid"));
  });
});
