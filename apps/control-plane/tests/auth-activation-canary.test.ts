import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createControlPlaneRuntime } from "../src/app.js";
import { runControlPlaneAuthActivationCanary } from "../src/canaries/authActivation.js";
import {
  InMemoryControlPlaneStore,
  PostgresControlPlaneStore,
} from "../src/services/store.js";

const serviceActorId = "verifier_control_plane_api_key";
const serviceToken = "verifier_service_token_test_123456";
const siteId = "sit_auth_activation_test";
const requestId = "req_auth_activation_test";
const activationEnv = {
  AIDENID_ROUTE_ACCESS_GUARD_ENABLED: "true",
  AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL: "false",
  AIDENID_OPERATOR_TOKENS: JSON.stringify({ [serviceActorId]: serviceToken }),
  AIDENID_OPERATOR_SERVICE_PRINCIPALS: JSON.stringify({
    [serviceActorId]: {
      principal_kind: "service",
      service_roles: ["decision_ingest", "decision_status"],
    },
  }),
};

const originalGuard = process.env.AIDENID_ROUTE_ACCESS_GUARD_ENABLED;
const originalTransitional =
  process.env.AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL;

beforeEach(() => {
  process.env.AIDENID_ROUTE_ACCESS_GUARD_ENABLED = "true";
  process.env.AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL = "false";
});

afterEach(() => {
  if (originalGuard === undefined)
    delete process.env.AIDENID_ROUTE_ACCESS_GUARD_ENABLED;
  else process.env.AIDENID_ROUTE_ACCESS_GUARD_ENABLED = originalGuard;
  if (originalTransitional === undefined)
    delete process.env.AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL;
  else
    process.env.AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL = originalTransitional;
});

function runtimeFactory(store: InMemoryControlPlaneStore) {
  return () =>
    createControlPlaneRuntime({
      store,
      logger: false,
      decisionOutboxRetentionDays: 0,
      operatorAuth: {
        entries: [
          {
            actorId: serviceActorId,
            token: serviceToken,
            principalKind: "service",
            serviceRoles: ["decision_ingest", "decision_status"],
          },
        ],
      },
    });
}

function recordCanaryDecision(store: InMemoryControlPlaneStore): void {
  store.recordDecision({
    id: "dec_auth_activation_test",
    siteId,
    requestId,
    actorClass: "unknown",
    decision: "allow",
    recommendedDecision: "allow",
    routeTemplate: "/auth-activation-canary",
    method: "GET",
    occurredAt: "2026-07-14T00:00:00.000Z",
    latencyUs: 1_000,
    reasonCodes: ["auth_activation_canary"],
  });
}

describe("control-plane auth activation canary", () => {
  it("proves durable correlation and least-privilege route behavior without exposing the service token", async () => {
    const store = new InMemoryControlPlaneStore();
    recordCanaryDecision(store);

    const result = await runControlPlaneAuthActivationCanary({
      requestId,
      siteId,
      serviceActorId,
      env: activationEnv,
      createRuntime: runtimeFactory(store),
    });

    expect(result).toEqual({
      event: "control_plane_auth_activation_canary_pass",
      request_id: requestId,
      site_id: siteId,
      decision_id: "dec_auth_activation_test",
      decision: "allow",
      actor_class: "unknown",
      route_template: "/auth-activation-canary",
      anonymous_status: 401,
      service_status: 202,
      operator_read_status: 403,
      public_metadata_status: 200,
      guard_enabled: true,
      transitional_access_enabled: false,
      service_roles: ["decision_ingest", "decision_status"],
    });
    expect(JSON.stringify(result)).not.toContain(serviceToken);
  });

  it("fails before runtime creation when transitional access is enabled", async () => {
    const createRuntime = vi.fn(
      runtimeFactory(new InMemoryControlPlaneStore()),
    );

    await expect(
      runControlPlaneAuthActivationCanary({
        requestId,
        siteId,
        serviceActorId,
        env: {
          ...activationEnv,
          AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL: "true",
        },
        createRuntime,
      }),
    ).rejects.toThrow(
      "AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL must be exactly false",
    );
    expect(createRuntime).not.toHaveBeenCalled();
  });

  it("does not copy arbitrary HTTP response bodies into canary errors", async () => {
    const store = new InMemoryControlPlaneStore();
    recordCanaryDecision(store);
    const responseSecret = "must_not_reach_cloudwatch";
    const createRuntime = async () => {
      const runtime = await runtimeFactory(store)();
      runtime.app.addHook("onSend", async (request, reply, payload) => {
        if (
          request.url.includes("/await") &&
          request.headers.authorization === undefined
        ) {
          reply.type("application/json");
          return JSON.stringify({ error: "unexpected_error", responseSecret });
        }
        return payload;
      });
      return runtime;
    };

    const failure = await runControlPlaneAuthActivationCanary({
      requestId,
      siteId,
      serviceActorId,
      env: activationEnv,
      createRuntime,
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toContain("got HTTP 401");
    expect((failure as Error).message).not.toContain(responseSecret);
  });

  it("rejects over-privileged or incomplete verifier service-role policy", async () => {
    const env = {
      ...activationEnv,
      AIDENID_OPERATOR_SERVICE_PRINCIPALS: JSON.stringify({
        [serviceActorId]: {
          principal_kind: "service",
          service_roles: ["decision_ingest"],
        },
      }),
    };

    await expect(
      runControlPlaneAuthActivationCanary({
        requestId,
        siteId,
        serviceActorId,
        env,
        createRuntime: runtimeFactory(new InMemoryControlPlaneStore()),
      }),
    ).rejects.toThrow(
      "must have exactly decision_ingest and decision_status roles",
    );
  });

  it("fails closed when the exact verifier decision never reaches durable storage", async () => {
    let clock = 0;
    await expect(
      runControlPlaneAuthActivationCanary({
        requestId,
        siteId,
        serviceActorId,
        timeoutMs: 1_000,
        pollIntervalMs: 500,
        env: activationEnv,
        createRuntime: runtimeFactory(new InMemoryControlPlaneStore()),
        now: () => clock,
        sleep: async (ms) => {
          clock += ms;
        },
      }),
    ).rejects.toThrow(`timed out waiting for persisted decision ${requestId}`);
  });

  it("queries PostgreSQL by both site and request id with a bounded result", async () => {
    const query = vi.fn(async () => ({ rows: [], rowCount: 0 }));
    const store = new PostgresControlPlaneStore({ query });

    await expect(
      store.findDecisionByRequestId(siteId, requestId),
    ).resolves.toBeUndefined();
    expect(query).toHaveBeenCalledWith(
      expect.stringMatching(
        /WHERE site_id = \$1 AND request_id = \$2[\s\S]*LIMIT 1/,
      ),
      [siteId, requestId],
    );
  });
});
