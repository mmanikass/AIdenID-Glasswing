import { describe, expect, it } from "vitest";

import { glasswingErrorFromBody, isGlasswingRunResult } from "../src/glasswing/client.js";

describe("glasswingErrorFromBody", () => {
  it("decodes the protected site error shape and the dashboard error shape", () => {
    const site = glasswingErrorFromBody(400, { error: { code: "unsupported_permission_scope", message: "one permission per grant" } });
    expect(site.code).toBe("unsupported_permission_scope");
    expect(site.message).toBe("unsupported_permission_scope: one permission per grant");
    const dashboard = glasswingErrorFromBody(503, { error: "protected_site_not_configured", message: "set the url" });
    expect(dashboard.code).toBe("protected_site_not_configured");
    expect(dashboard.detail).toBe("set the url");
    expect(glasswingErrorFromBody(502, null).code).toBe("http_502");
    expect(glasswingErrorFromBody(500, "not json").code).toBe("http_500");
  });
});

describe("isGlasswingRunResult", () => {
  const request = { method: "GET", url: "https://aidenid.local/catalog" };
  it("accepts a decided run and a refused run that carries a site error code", () => {
    expect(isGlasswingRunResult({ request, session: { sessionId: "s", revocationEpoch: 0 }, decision: { action: "allow" }, effect: { ok: true }, jev: null })).toBe(true);
    expect(isGlasswingRunResult({ request, session: null, decision: null, effect: null, jev: null, error: { code: "session_exchange_failed", message: "revoked" } })).toBe(true);
    expect(isGlasswingRunResult({ request: { method: "", url: "" }, session: null, decision: null, effect: null, jev: null, error: { code: "invalid_run_request", message: "task" } })).toBe(true);
  });
  it("rejects proxy errors and malformed bodies so they surface as errors", () => {
    expect(isGlasswingRunResult({ error: "protected_site_unavailable" })).toBe(false);
    expect(isGlasswingRunResult({ request, error: "string_error" })).toBe(false);
    expect(isGlasswingRunResult(null)).toBe(false);
    expect(isGlasswingRunResult("text")).toBe(false);
  });
});
