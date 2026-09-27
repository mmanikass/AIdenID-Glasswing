import { describe, expect, it } from "vitest";

import { createControlPlaneRuntime } from "../src/index.js";
import { ROUTE_ACCESS_MANIFEST } from "../src/plugins/routeAccessManifest.js";

/**
 * Companion to route-authorization.test.ts, which stubs
 * AIDENID_ROUTE_ACCESS_GUARD_ENABLED=true in beforeEach and therefore validates the
 * guard-ON world exclusively. Production runs with that flag UNSET: the deny-by-default
 * guard does not execute, and the only in-process authorization is whatever each handler
 * does for itself. Nothing covered that configuration, which is why a tenant-spanning
 * anonymous read (GET /v1/decisions, closed by #284) and an anonymous grant-issuance path
 * both sat unnoticed behind a 194-case authorization suite that was green the whole time.
 *
 * These tests deliberately do NOT stub the flag. They pin what the shipped configuration
 * actually enforces, so that:
 *   - a NEW route reachable anonymously fails here immediately, and
 *   - closing a known gap ALSO fails here, with a message saying to delete its entry.
 * Both directions are intentional: the list below is a ledger of accepted exposure, and it
 * should only ever shrink.
 */

const ADMIN_TOKEN = "guard_off_probe_admin_token_1234567890";

const SAMPLE_PARAMS: Readonly<Record<string, string>> = {
  id: "dec_guard_off_probe",
  tenantId: "ten_guard_off_probe",
  exportId: "bex_guard_off_probe",
  operatorActorId: "op_guard_off_probe",
  notificationId: "arn_guard_off_probe",
  submissionId: "ais_guard_off_probe",
  endpointId: "whe_guard_off_probe",
  chainId: "chn_guard_off_probe",
};

/** Routes that are anonymous ON PURPOSE. Adding to this list is a policy decision. */
const INTENTIONALLY_PUBLIC = new Set([
  "GET /healthz",
  "GET /readyz",
  "POST /v1/identities",
  "GET /.well-known/oauth-protected-resource",
  "GET /v1/mcp/protected-resource-metadata",
  "GET /v1/mcp/front-door/roadmap",
]);

/**
 * Routes the manifest classifies as PROTECTED but whose handlers do not gate themselves,
 * so they are reachable anonymously whenever the guard flag is off — i.e. in production
 * today. These are contained ONLY by the edge WAF, which 403s /v1/*. Each one must be
 * closed by a handler-level check (as #284 did for GET /v1/decisions and #286 does for
 * POST /v1/grants) or by enabling the guard, BEFORE the WAF block is narrowed.
 */
const KNOWN_UNGATED_WHILE_GUARD_OFF = new Set([
  // POST /v1/targets was closed by the operator-gate that accompanies this change, and
  // POST /v1/grants by #286 — steps 1 and 2 of the forgery chain. Both removed from this
  // ledger on 2026-08-13; see the chain test below.
  "POST /v1/sessions/exchange",
  "POST /v1/decisions",
  "POST /v1/policy-copilot/suggestions",
  "GET /v1/persona-audits",
]);

function materialize(template: string): string {
  const path = template.replace(/:([A-Za-z][A-Za-z0-9]*)/g, (_match, name: string) => {
    const value = SAMPLE_PARAMS[name];
    if (value === undefined) {
      throw new Error(`route template has no probe value for :${name}`);
    }
    return value;
  });
  return template === "/v1/decisions/:id/await" ? `${path}?timeout_ms=1` : path;
}

async function guardOffRuntime() {
  return createControlPlaneRuntime({
    operatorAuth: {
      entries: [{ actorId: "guard_off_admin", token: ADMIN_TOKEN, roles: ["admin"] }],
      env: "",
    },
    decisionOutboxRetentionDays: 0,
  });
}

describe("control-plane authorization with the route-access guard OFF", () => {
  it("does not enable the guard by default", () => {
    // The premise of this whole file. If this ever flips, these expectations are testing
    // a configuration production no longer runs, and the file must be revisited.
    expect(process.env.AIDENID_ROUTE_ACCESS_GUARD_ENABLED).not.toBe("true");
  });

  it("pins exactly which routes an anonymous caller can reach", async () => {
    const runtime = await guardOffRuntime();
    try {
      const reachable: string[] = [];
      for (const entry of ROUTE_ACCESS_MANIFEST) {
        const key = `${entry.method} ${entry.template}`;
        const response = await runtime.app.inject({
          method: entry.method as "GET",
          url: materialize(entry.template),
          ...(["POST", "PUT", "PATCH", "DELETE"].includes(entry.method) ? { payload: {} } : {}),
        });
        // 401/403/503 mean the request was refused on identity. Anything else means it was
        // ADMITTED and handled — 400 still proves it reached body validation, 404 that it
        // reached a store lookup.
        const refused = [401, 403, 503].includes(response.statusCode);
        if (!refused) {
          reachable.push(key);
        }
      }

      const expected = [...INTENTIONALLY_PUBLIC, ...KNOWN_UNGATED_WHILE_GUARD_OFF].sort();
      expect(
        reachable.sort(),
        "anonymous reachability changed. A NEW entry is a regression: gate the handler. " +
          "A MISSING entry means a gap was closed — delete it from KNOWN_UNGATED_WHILE_GUARD_OFF.",
      ).toEqual(expected);
    } finally {
      await runtime.app.close();
    }
  });

  it("blocks the anonymous forgery chain at its first step", async () => {
    // targets -> grants -> sessions/exchange with no credential at any step completed end to
    // end before #286, and minted a signed session for a victim site. Both of the first two
    // legs are now gated: targets by this change, grants by #286. Either alone breaks the
    // chain; asserting both keeps each honest, so removing one gate cannot be masked by the
    // other still holding.
    const runtime = await guardOffRuntime();
    try {
      const target = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        payload: {
          site_id: "sit_guard_off_probe",
          name: "Guard Off Probe",
          origin: "https://guard-off-probe.example.com",
        },
      });
      expect(
        target.statusCode,
        "REGRESSION: anonymous target creation is open again. Ungated, an anonymous caller " +
          "can claim an existing tenant's site_id under an origin it controls, and step 1 of " +
          "the session-forgery chain reopens.",
      ).toBe(401);
      expect(target.json()).toMatchObject({ error: "operator_auth_required" });

      // Independently assert the grant leg, using an admin-created target so this leg is
      // exercised on its own merits rather than passing only because step 1 stopped first.
      const authedTarget = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
        payload: {
          site_id: "sit_guard_off_probe2",
          name: "Guard Off Probe 2",
          origin: "https://guard-off-probe2.example.com",
        },
      });
      expect(authedTarget.statusCode).toBe(201);

      const grant = await runtime.app.inject({
        method: "POST",
        url: "/v1/grants",
        payload: {
          target_id: authedTarget.json<{ id: string }>().id,
          subject: "anonymous_caller",
          permissions: ["orders:read"],
        },
      });
      expect(
        grant.statusCode,
        "REGRESSION: anonymous grant issuance is open again. #286 gated this leg; without it " +
          "the targets -> grants -> exchange session-forgery chain completes.",
      ).toBe(401);
      expect(grant.json()).toMatchObject({ error: "operator_auth_required" });
    } finally {
      await runtime.app.close();
    }
  });

  it("records that possession of a grant id is still enough to mint a session", async () => {
    // The residual after #286. The exchange handler looks a grant up by id and never
    // establishes WHO is asking, and the grant carries no bound proof key, so anyone who
    // learns a grant id can mint a session for it under THEIR OWN cnf.jkt. That is a
    // proof-of-possession bypass, not merely an anonymous read: the token names the
    // legitimate subject while being bound to the caller's key.
    //
    // Closing this needs audience/proof-key binding on the grant (or the guard flip, which
    // fails the route closed until AUTH-1) — NOT an operator gate, because the route's
    // principal class is exchange_principal and no such credential exists yet.
    const runtime = await guardOffRuntime();
    try {
      const target = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
        payload: { site_id: "sit_pop_probe", name: "PoP Probe", origin: "https://pop-probe.example.com" },
      });
      const grant = await runtime.app.inject({
        method: "POST",
        url: "/v1/grants",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` }, // minted legitimately
        payload: { target_id: target.json<{ id: string }>().id, subject: "legitimate_subject", permissions: ["orders:read"] },
      });
      expect(grant.statusCode).toBe(201);
      const issued = grant.json<{ id: string; site_id: string; resource: string }>();

      const exchange = await runtime.app.inject({
        method: "POST",
        url: "/v1/sessions/exchange",
        payload: {
          grant_id: issued.id,
          audience: issued.site_id,
          resource: issued.resource,
          requested_permissions: ["orders:read"],
          proof_jkt: "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", // NOT the grant holder's key
        },
      });

      expect(
        exchange.statusCode,
        "grant-id possession no longer mints a session — that is GOOD. Update this test to " +
          "assert the refusal and drop POST /v1/sessions/exchange from the ledger above.",
      ).toBe(201);
      const claims = JSON.parse(
        Buffer.from(exchange.json<{ access_token: string }>().access_token.split(".")[1] ?? "", "base64url").toString("utf8"),
      ) as { sub?: string; cnf?: { jkt?: string } };
      // The session names the legitimate subject but is bound to the caller's proof key.
      expect(claims.sub).toBe("legitimate_subject");
      expect(claims.cnf?.jkt).toBe("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
    } finally {
      await runtime.app.close();
    }
  });
});
