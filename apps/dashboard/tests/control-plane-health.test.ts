import { describe, expect, it, vi } from "vitest";

import { checkControlPlaneHealth } from "../src/controlPlaneHealth.js";

describe("dashboard control-plane health probe", () => {
  it("fails closed when the upstream URL is missing or invalid", async () => {
    const fetchImpl = vi.fn<typeof fetch>();

    await expect(checkControlPlaneHealth({}, fetchImpl)).resolves.toBe(
      "unavailable",
    );
    await expect(
      checkControlPlaneHealth(
        { AIDENID_CONTROL_PLANE_URL: "file:///etc/passwd" },
        fetchImpl,
      ),
    ).resolves.toBe("unavailable");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("requests only the fixed health endpoint without caching", async () => {
    let requestedUrl = "";
    let requestedCache: unknown;
    const fetchImpl: typeof fetch = async (input, init) => {
      requestedUrl = String(input);
      requestedCache = init?.cache;
      return Response.json({ ok: true, service: "aidenid-control-plane" });
    };

    await expect(
      checkControlPlaneHealth(
        { AIDENID_CONTROL_PLANE_URL: "http://127.0.0.1:4000/base" },
        fetchImpl,
      ),
    ).resolves.toBe("connected");
    expect(requestedUrl).toBe("http://127.0.0.1:4000/healthz");
    expect(requestedCache).toBe("no-store");
  });

  it("reports unavailable for non-success, malformed, and unreachable health checks", async () => {
    const env = { AIDENID_CONTROL_PLANE_URL: "http://127.0.0.1:4000" };
    const unhealthy: typeof fetch = async () =>
      Response.json({ ok: false, service: "aidenid-control-plane" }, { status: 503 });
    const malformed: typeof fetch = async () =>
      Response.json({ ok: true, service: "other-service" });
    const unreachable: typeof fetch = async () => {
      throw new Error("connection refused");
    };

    await expect(checkControlPlaneHealth(env, unhealthy)).resolves.toBe(
      "unavailable",
    );
    await expect(checkControlPlaneHealth(env, malformed)).resolves.toBe(
      "unavailable",
    );
    await expect(checkControlPlaneHealth(env, unreachable)).resolves.toBe(
      "unavailable",
    );
  });
});
