import { describe, expect, it } from "vitest";

import { canonicalJwkThumbprintBase64Url, canonicalJwkThumbprintSha256 } from "../src/index.js";

describe("canonical JWK thumbprints", () => {
  it("is stable across object property order for OKP keys", () => {
    const a = canonicalJwkThumbprintSha256({
      kty: "OKP",
      crv: "Ed25519",
      x: "11qYAYdk3m2m2x1DlD-P7X4HEPFGtYI1njfXWcJw0zQ",
      kid: "ignored"
    });
    const b = canonicalJwkThumbprintSha256({
      x: "11qYAYdk3m2m2x1DlD-P7X4HEPFGtYI1njfXWcJw0zQ",
      crv: "Ed25519",
      kty: "OKP"
    });

    expect(a).toHaveLength(64);
    expect(a).toBe(b);
    expect(canonicalJwkThumbprintBase64Url({ kty: "OKP", crv: "Ed25519", x: "11qYAYdk3m2m2x1DlD-P7X4HEPFGtYI1njfXWcJw0zQ" })).toMatch(
      /^[A-Za-z0-9_-]+$/
    );
  });

  it("rejects unsupported key types", () => {
    expect(() => canonicalJwkThumbprintSha256({ kty: "RSA", n: "x", e: "AQAB" })).toThrow(/unsupported/);
  });
});
