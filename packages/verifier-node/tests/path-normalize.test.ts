import { describe, expect, it } from "vitest";

import {
  REJECTED_PATH_SENTINEL,
  normalizePath,
  validateAndNormalizePath
} from "../src/index.js";

describe("path normalization", () => {
  it("drops query strings and resolves dot segments", () => {
    expect(normalizePath("https://example.com/a/./b/../c?x=1")).toEqual({
      path: "/a/c",
      routeTemplate: "/a/c"
    });
  });

  it("templates numeric and opaque identifiers", () => {
    expect(normalizePath("/accounts/123/orders/abcDEF1234567890")).toEqual({
      path: "/accounts/123/orders/abcDEF1234567890",
      routeTemplate: "/accounts/:id/orders/:id"
    });
  });
});

describe("path normalization hostile-input rejection (spec §5.19)", () => {
  describe("validateAndNormalizePath returns null on attack input", () => {
    it("rejects null bytes", () => {
      expect(validateAndNormalizePath("/admin\x00/etc/passwd")).toBeNull();
      expect(validateAndNormalizePath("/api/users/\x00")).toBeNull();
    });

    it("rejects ASCII control characters in [\\x00-\\x1f]", () => {
      expect(validateAndNormalizePath("/api/x\x01y")).toBeNull();
      expect(validateAndNormalizePath("/api/x\x07y")).toBeNull();
      expect(validateAndNormalizePath("/api/x\ty")).toBeNull();
      expect(validateAndNormalizePath("/api/x\ny")).toBeNull();
      expect(validateAndNormalizePath("/api/x\ry")).toBeNull();
      expect(validateAndNormalizePath("/api/x\x1fy")).toBeNull();
    });

    it("rejects DEL (0x7f)", () => {
      expect(validateAndNormalizePath("/api/x\x7fy")).toBeNull();
    });

    it("rejects BiDi override / isolate characters U+202A..U+202E", () => {
      // U+202E (Right-to-Left Override) used for path-spoofing in admin UIs.
      expect(validateAndNormalizePath("‮/admin")).toBeNull();
      expect(validateAndNormalizePath("/x‪/admin")).toBeNull(); // U+202A
      expect(validateAndNormalizePath("/x‫/admin")).toBeNull(); // U+202B
      expect(validateAndNormalizePath("/x‬/admin")).toBeNull(); // U+202C
      expect(validateAndNormalizePath("/x‭/admin")).toBeNull(); // U+202D
    });

    it("rejects BiDi isolate characters U+2066..U+2069", () => {
      expect(validateAndNormalizePath("/x⁦/admin")).toBeNull(); // U+2066
      expect(validateAndNormalizePath("/x⁧/admin")).toBeNull(); // U+2067
      expect(validateAndNormalizePath("/x⁨/admin")).toBeNull(); // U+2068
      expect(validateAndNormalizePath("/x⁩/admin")).toBeNull(); // U+2069
    });

    it("rejects double-encoded percent (post-decode %xx remaining)", () => {
      // %252e%252e/etc/passwd → after one decode → %2e%2e/etc/passwd
      // Second %xx triplet is the double-encode signal.
      expect(validateAndNormalizePath("/%252e%252e/etc/passwd")).toBeNull();
      expect(validateAndNormalizePath("/api/%252fadmin")).toBeNull();
    });

    it("rejects UNC path prefixes (\\\\host\\share)", () => {
      expect(validateAndNormalizePath("\\\\evil\\share\\admin")).toBeNull();
      expect(validateAndNormalizePath("/api/\\\\evil\\share")).toBeNull();
    });

    it("rejects tilde-variant prefixes (~user, ~+, ~-)", () => {
      expect(validateAndNormalizePath("/~root/.ssh/id_rsa")).toBeNull();
      expect(validateAndNormalizePath("/~+/etc")).toBeNull();
      expect(validateAndNormalizePath("/~-/etc")).toBeNull();
    });

    it("accepts ordinary-looking paths", () => {
      expect(validateAndNormalizePath("/api/users/123")).toEqual({
        path: "/api/users/123",
        routeTemplate: "/api/users/:id"
      });
    });

    it("accepts properly singly-encoded segments", () => {
      // Single-encoded space → ' ' after one decode → no second %xx → OK.
      expect(validateAndNormalizePath("/api/has%20space")).toEqual({
        path: "/api/has space",
        routeTemplate: "/api/has space"
      });
    });
  });

  describe("normalizePath fail-closed sentinel for hostile input", () => {
    it("returns the rejection sentinel rather than null for null bytes", () => {
      const result = normalizePath("/admin\x00/etc/passwd");
      expect(result.path.startsWith(REJECTED_PATH_SENTINEL)).toBe(true);
      expect(result.routeTemplate.startsWith(REJECTED_PATH_SENTINEL)).toBe(true);
    });

    it("emits a stable rejection reason in the sentinel path", () => {
      expect(normalizePath("/admin\x00etc").path).toBe(`${REJECTED_PATH_SENTINEL}/null_byte`);
      expect(normalizePath("‮/admin").path).toBe(`${REJECTED_PATH_SENTINEL}/bidi_override`);
      expect(normalizePath("/%252e%252e/etc/passwd").path).toBe(
        `${REJECTED_PATH_SENTINEL}/double_encoded_percent`
      );
      expect(normalizePath("\\\\evil\\share").path).toBe(`${REJECTED_PATH_SENTINEL}/unc_path`);
      expect(normalizePath("/~root/.ssh").path).toBe(`${REJECTED_PATH_SENTINEL}/tilde_prefix`);
    });

    it("preserves backward-compatible behavior for benign input", () => {
      expect(normalizePath("/api/users/123")).toEqual({
        path: "/api/users/123",
        routeTemplate: "/api/users/:id"
      });
    });
  });
});
