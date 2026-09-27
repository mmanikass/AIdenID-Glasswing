import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const canaryScript = fileURLToPath(
  new URL("../../../scripts/check-dashboard-live.mjs", import.meta.url),
);
const operatorToken = "operator_test_token_123456";
const controlPlaneToken = "service_ingest_test_token_123456";

interface CanaryProcessResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

let server: Server;
let baseUrl: string;
let leakAnonymousStream = false;
let probe: Record<string, unknown> | undefined;
let anonymousStreamRequests = 0;
let authenticatedStreamRequests = 0;
let decisionPostRequests = 0;
let unauthorizedDecisionPostRequests = 0;

function runCanary(
  args: readonly string[],
  envUpdates: Readonly<NodeJS.ProcessEnv> = {},
): Promise<CanaryProcessResult> {
  const env = { ...process.env };
  delete env.AIDENID_CONTROL_PLANE_URL;
  delete env.AIDENID_CONTROL_PLANE_API_KEY;
  delete env.AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN;
  delete env.AIDENID_DASHBOARD_SITE_ID;
  Object.assign(env, envUpdates);

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [canaryScript, baseUrl, ...args], {
      env,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("dashboard live canary", () => {
  beforeAll(async () => {
    server = createServer(async (request, response) => {
      const url = new URL(request.url ?? "/", "http://localhost");
      if (url.pathname === "/api/status") {
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(
          JSON.stringify({
            service: "aidenid-clearance-dashboard",
            mode: "live_control_plane",
            fallbackDataEnabled: false,
            controlPlaneStreamConfigured: true,
            operatorActionsConfigured: true,
            policyPreviewConfigured: true,
          }),
        );
        return;
      }

      if (url.pathname === "/v1/decisions" && request.method === "POST") {
        decisionPostRequests += 1;
        if (request.headers.authorization !== `Bearer ${controlPlaneToken}`) {
          unauthorizedDecisionPostRequests += 1;
          response.writeHead(401, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: "service_auth_required" }));
          return;
        }
        let body = "";
        for await (const chunk of request) {
          body += chunk.toString();
        }
        probe = JSON.parse(body) as Record<string, unknown>;
        response.writeHead(201, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ decision: { id: "dec_probe" } }));
        return;
      }

      if (url.pathname === "/api/decisions/stream") {
        if (request.headers.authorization !== `Bearer ${operatorToken}`) {
          anonymousStreamRequests += 1;
          if (leakAnonymousStream) {
            response.writeHead(200, {
              "Content-Type": "text/event-stream",
              "X-AIdenID-Dashboard-Data-Source": "live",
            });
            response.end('event: recorded\ndata: {"request_id":"leaked"}\n\n');
            return;
          }
          response.writeHead(401, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: "operator_auth_required" }));
          return;
        }

        authenticatedStreamRequests += 1;
        response.writeHead(200, {
          "Content-Type": "text/event-stream",
          "X-AIdenID-Dashboard-Data-Source": "live",
        });
        response.end(
          probe === undefined
            ? ""
            : `id: 1\nevent: recorded\ndata: ${JSON.stringify({ request_id: probe.request_id, site_id: probe.site_id })}\n\n`,
        );
        return;
      }

      response.writeHead(404);
      response.end();
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  beforeEach(() => {
    leakAnonymousStream = false;
    probe = undefined;
    anonymousStreamRequests = 0;
    authenticatedStreamRequests = 0;
    decisionPostRequests = 0;
    unauthorizedDecisionPostRequests = 0;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((cause) =>
        cause === undefined ? resolve() : reject(cause),
      );
    });
  });

  it("proves the public anonymous stream boundary without privileged credentials", async () => {
    const result = await runCanary([]);

    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: true,
      anonymousStreamDenied: true,
      anonymousStreamStatus: 401,
      authenticatedStreamObserved: false,
      streamDataSource: null,
    });
    expect(anonymousStreamRequests).toBe(1);
    expect(authenticatedStreamRequests).toBe(0);
  });

  it("observes an exact same-site probe over an authenticated continuous stream", async () => {
    const result = await runCanary(
      [
        "--emit-probe",
        "--control-plane-url",
        baseUrl,
        "--site-id",
        "sit_canary_test",
      ],
      {
        AIDENID_CONTROL_PLANE_API_KEY: controlPlaneToken,
        AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: operatorToken,
      },
    );

    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: true,
      anonymousStreamDenied: true,
      anonymousStreamStatus: 401,
      authenticatedStreamObserved: true,
      streamDataSource: "live",
      observedProbe: true,
    });
    expect(probe?.site_id).toBe("sit_canary_test");
    expect(decisionPostRequests).toBe(1);
    expect(unauthorizedDecisionPostRequests).toBe(0);
    expect(anonymousStreamRequests).toBe(1);
    expect(authenticatedStreamRequests).toBe(1);
  });

  it("fails before network access when an emit probe lacks service authentication", async () => {
    const result = await runCanary(
      [
        "--emit-probe",
        "--control-plane-url",
        baseUrl,
        "--site-id",
        "sit_canary_test",
      ],
      { AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: operatorToken },
    );

    expect(result.code).toBe(2);
    expect(result.stderr).toContain(
      "authenticated emit probes require AIDENID_CONTROL_PLANE_API_KEY",
    );
    expect(result.stdout).toBe("");
    expect(decisionPostRequests).toBe(0);
    expect(anonymousStreamRequests).toBe(0);
    expect(authenticatedStreamRequests).toBe(0);
  });

  it("fails when the control plane rejects the supplied service credential", async () => {
    const result = await runCanary(
      [
        "--emit-probe",
        "--control-plane-url",
        baseUrl,
        "--site-id",
        "sit_canary_test",
      ],
      {
        AIDENID_CONTROL_PLANE_API_KEY: "wrong_service_ingest_token_123456",
        AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: operatorToken,
      },
    );

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "synthetic decision emit failed with HTTP 401",
    );
    expect(decisionPostRequests).toBe(1);
    expect(unauthorizedDecisionPostRequests).toBe(1);
    expect(anonymousStreamRequests).toBe(1);
    expect(authenticatedStreamRequests).toBe(0);
  });

  it("fails when anonymous callers receive live SSE data", async () => {
    leakAnonymousStream = true;

    const result = await runCanary([]);

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "anonymous decision stream must fail closed with HTTP 401, got 200",
    );
    expect(anonymousStreamRequests).toBe(1);
    expect(authenticatedStreamRequests).toBe(0);
  });
});
