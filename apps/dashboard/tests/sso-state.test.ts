import { afterEach, describe, expect, it, vi } from "vitest";

import { GET as completeSso } from "../src/app/auth/callback/route.js";
import { GET as startSso } from "../src/app/auth/start/route.js";
import { SESSION_COOKIE, SSO_STATE_COOKIE } from "../src/auth/constants.js";

const DASHBOARD_URL = "https://dashboard.aidenid.com";

function stateFromStart(response: Response): string {
  const login = new URL(response.headers.get("location") ?? "");
  const callback = new URL(login.searchParams.get("redirect_to") ?? "");
  return callback.searchParams.get("state") ?? "";
}

function callbackRequest(
  state: string | undefined,
  cookieState: string | undefined,
  code = "c".repeat(43),
): Request {
  const callback = new URL("/auth/callback", DASHBOARD_URL);
  if (state !== undefined) callback.searchParams.set("state", state);
  callback.searchParams.set("code", code);
  const headers = new Headers();
  if (cookieState !== undefined) {
    headers.set("Cookie", `${SSO_STATE_COOKIE}=${cookieState}`);
  }
  return new Request(callback, { headers });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("dashboard SSO browser binding", () => {
  it("starts SSO with a high-entropy state in the callback and an HttpOnly cookie", () => {
    const response = startSso(new Request(`${DASHBOARD_URL}/auth/start`));
    const login = new URL(response.headers.get("location") ?? "");
    const callback = new URL(login.searchParams.get("redirect_to") ?? "");
    const state = callback.searchParams.get("state") ?? "";
    const setCookie = response.headers.get("set-cookie") ?? "";

    expect(login.origin).toBe("https://sentinelayer.com");
    expect(callback.origin).toBe(DASHBOARD_URL);
    expect(callback.pathname).toBe("/auth/callback");
    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(setCookie).toContain(`${SSO_STATE_COOKIE}=${state}`);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("SameSite=lax");
    expect(setCookie).toContain("Path=/");
    expect(setCookie).toContain("Max-Age=300");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("does not trust a forwarded host when the canonical URL is not configured", () => {
    const request = new Request("https://attacker.example/auth/start", {
      headers: { "X-Forwarded-Host": "attacker.example" },
    });

    const callback = new URL(
      new URL(startSso(request).headers.get("location") ?? "").searchParams.get(
        "redirect_to",
      ) ?? "",
    );

    expect(callback.origin).toBe(DASHBOARD_URL);
  });

  it("honors an explicit HTTPS dashboard origin", () => {
    vi.stubEnv("AIDENID_DASHBOARD_URL", "https://clearance.example/path");

    const callback = new URL(
      new URL(
        startSso(new Request(`${DASHBOARD_URL}/auth/start`)).headers.get(
          "location",
        ) ?? "",
      ).searchParams.get("redirect_to") ?? "",
    );

    expect(callback.origin).toBe("https://clearance.example");
    expect(callback.pathname).toBe("/auth/callback");
  });

  it("fails closed on a non-HTTPS remote dashboard origin", () => {
    vi.stubEnv("AIDENID_DASHBOARD_URL", "http://clearance.example");

    expect(() => startSso(new Request(`${DASHBOARD_URL}/auth/start`))).toThrow(
      "must use HTTPS",
    );
  });

  it.each([
    ["missing callback state", undefined, "cookie"],
    ["missing state cookie", "callback", undefined],
    ["mismatched state", "a".repeat(43), "b".repeat(43)],
    ["malformed state", "not-base64url", "not-base64url"],
  ])("rejects %s before exchanging the code", async (_name, state, cookie) => {
    const fetchSpy = vi.fn(() => {
      throw new Error("the exchange must not run");
    });
    vi.stubGlobal("fetch", fetchSpy);

    const response = await completeSso(callbackRequest(state, cookie));

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe(
      `${DASHBOARD_URL}/login?error=sso`,
    );
    expect(response.headers.get("set-cookie")).toContain(
      `${SSO_STATE_COOKIE}=`,
    );
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects a malformed handoff code before exchange", async () => {
    const start = startSso(new Request(`${DASHBOARD_URL}/auth/start`));
    const state = stateFromStart(start);
    const fetchSpy = vi.fn(() => {
      throw new Error("the exchange must not run");
    });
    vi.stubGlobal("fetch", fetchSpy);

    const response = await completeSso(
      callbackRequest(state, state, "oversized-or-malformed"),
    );

    expect(response.headers.get("location")).toBe(
      `${DASHBOARD_URL}/login?error=sso`,
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("exchanges a browser-bound code and consumes state on success", async () => {
    const start = startSso(new Request(`${DASHBOARD_URL}/auth/start`));
    const state = stateFromStart(start);
    const fetchSpy = vi.fn(async () => Response.json({ token: "session-jwt" }));
    vi.stubGlobal("fetch", fetchSpy);

    const response = await completeSso(callbackRequest(state, state));
    const setCookie = response.headers.get("set-cookie") ?? "";

    expect(response.headers.get("location")).toBe(`${DASHBOARD_URL}/`);
    expect(fetchSpy).toHaveBeenCalledOnce();
    expect(setCookie).toContain(`${SSO_STATE_COOKIE}=`);
    expect(setCookie).toContain("Max-Age=0");
    expect(SESSION_COOKIE).toBe("__Host-aidenid_session");
    expect(setCookie).toContain(`${SESSION_COOKIE}=session-jwt`);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("rejects a replay after the state cookie has been consumed", async () => {
    const start = startSso(new Request(`${DASHBOARD_URL}/auth/start`));
    const state = stateFromStart(start);
    const fetchSpy = vi.fn(async () => Response.json({ token: "session-jwt" }));
    vi.stubGlobal("fetch", fetchSpy);

    await completeSso(callbackRequest(state, state));
    const replay = await completeSso(callbackRequest(state, undefined));

    expect(replay.headers.get("location")).toBe(
      `${DASHBOARD_URL}/login?error=sso`,
    );
    expect(fetchSpy).toHaveBeenCalledOnce();
  });
});
