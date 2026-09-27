import { createControlPlaneRuntime, revokeChain, withChainAuthority } from "@aidenid/control-plane";
import { decodeCompactJwt } from "@aidenid/crypto";
import { verifyCryptoPath, type VerifierCryptoOptions } from "@aidenid/verifier-node";
import { describe, expect, it } from "vitest";

import { buildSignedHeaders, exchangeSession, httpSignatureTrustEntry, mintAgentKey, SessionExchangeError } from "../src/index.js";

const ADMIN_TOKEN = "test_operator_token_admin_123456";
const OPERATOR_AUTH = { entries: [{ actorId: "platform_admin", token: ADMIN_TOKEN, roles: ["admin"] }] } as const;
const ADMIN_HEADERS = { Authorization: `Bearer ${ADMIN_TOKEN}` };
const SITE_ID = "sit_glasswing";
const ORIGIN = "https://shop.glasswing.test";
const CATALOG = `${ORIGIN}/api/catalog`;

/** Route the control plane's in-process HTTP through fetch-shaped calls for exchangeSession. */
function injectFetch(app: Awaited<ReturnType<typeof createControlPlaneRuntime>>["app"]): typeof fetch {
  return (async (input, init) => {
    const url = new URL(String(input));
    const response = await app.inject({
      method: (init?.method ?? "GET") as "GET" | "POST",
      url: url.pathname + url.search,
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      payload: init?.body === undefined ? undefined : String(init.body)
    });
    return new Response(response.body, { status: response.statusCode, headers: response.headers as Record<string, string> });
  }) as typeof fetch;
}

describe("kernel end to end: grant -> exchange -> signed request -> effect -> revoke -> refused", () => {
  it("runs the whole demo spine against the real control plane and verifier crypto path", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 90, operatorAuth: OPERATOR_AUTH });
    try {
      // Owner registers the protected site and issues a scoped grant to the minted agent.
      const target = (
        await runtime.app.inject({ method: "POST", url: "/v1/targets", headers: ADMIN_HEADERS, payload: { tenant_id: "ten_demo", site_id: SITE_ID, name: "Glasswing Shop", origin: CATALOG } })
      ).json<{ id: string }>();
      const agent = mintAgentKey();
      const grant = (
        await runtime.app.inject({
          method: "POST",
          url: "/v1/grants",
          headers: ADMIN_HEADERS,
          payload: { target_id: target.id, subject: "agent:gpt-luna-xh", resource: CATALOG, permissions: ["catalog:read"], expires_in_seconds: 600 }
        })
      ).json<{ id: string; chain_id: string }>();

      // Agent exchanges the grant for a session bound to its own key.
      const session = await exchangeSession(agent, {
        controlPlaneUrl: "http://control-plane.local",
        grantId: grant.id,
        audience: SITE_ID,
        resource: CATALOG,
        requestedPermissions: ["catalog:read"],
        fetchImpl: injectFetch(runtime.app)
      });
      expect(session.tokenType).toBe("DPoP");
      expect(decodeCompactJwt(session.accessToken).payload).toMatchObject({ cnf: { jkt: agent.thumbprint }, chain_id: grant.chain_id, revocation_epoch: 0 });

      // The protected site trusts the control plane's PUBLISHED session key and the agent's HTTP key.
      const jwks = (await runtime.app.inject({ method: "GET", url: "/.well-known/aidenid-session-jwks.json" })).json<{ issuer: string; keys: Record<string, unknown>[] }>();
      const { kid: _kid, use: _use, alg: _alg, ...publishedJwk } = jwks.keys[0]!;
      const crypto: VerifierCryptoOptions = {
        sessionTokenPublicJwksByIssuer: { [jwks.issuer]: publishedJwk },
        httpMessageSignaturePublicJwksByKeyId: httpSignatureTrustEntry(agent),
        requireHttpSignatureNonce: true
      };

      // Signed request -> verifier crypto path -> effect under the chain lease.
      const headers = buildSignedHeaders(agent, { method: "GET", url: CATALOG, sessionToken: session.accessToken });
      const verified = verifyCryptoPath({ method: "GET", url: CATALOG, headers }, SITE_ID, crypto, new Date());
      expect(verified).toMatchObject({ verified: true, issuer: jwks.issuer, subject: "agent:gpt-luna-xh" });
      const claims = decodeCompactJwt(session.accessToken).payload as { chain_id: string; revocation_epoch: number };
      const effect = await withChainAuthority(runtime.services, { chainId: claims.chain_id, tokenRevocationEpoch: claims.revocation_epoch }, () => ({ items: 3 }));
      expect(effect).toEqual({ ok: true, epoch: 0, value: { items: 3 } });

      // Owner revokes. The next signed request still verifies cryptographically (global floor is 0)
      // but the co-located effect boundary refuses it, and a new exchange is refused too.
      const revocation = await revokeChain(runtime.services, { chainId: grant.chain_id, reason: "owner_revoked", actorId: "platform_admin" });
      expect(revocation.epoch).toBe(1);
      const again = buildSignedHeaders(agent, { method: "GET", url: CATALOG, sessionToken: session.accessToken });
      expect(verifyCryptoPath({ method: "GET", url: CATALOG, headers: again }, SITE_ID, crypto, new Date()).verified).toBe(true);
      const refused = await withChainAuthority(runtime.services, { chainId: claims.chain_id, tokenRevocationEpoch: claims.revocation_epoch }, () => ({ items: 3 }));
      expect(refused).toEqual({ ok: false, reason: "grant_revoked" });
      await expect(
        exchangeSession(agent, { controlPlaneUrl: "http://control-plane.local", grantId: grant.id, audience: SITE_ID, resource: CATALOG, requestedPermissions: ["catalog:read"], fetchImpl: injectFetch(runtime.app) })
      ).rejects.toMatchObject({ status: 403, code: "grant_not_active" } satisfies Partial<SessionExchangeError>);

      // And a verifier that raised its floor to the new epoch refuses the old token outright.
      expect(verifyCryptoPath({ method: "GET", url: CATALOG, headers: again }, SITE_ID, { ...crypto, minRevocationEpoch: revocation.epoch }, new Date())).toMatchObject({ verified: false, reason: "revoked" });
    } finally {
      await runtime.app.close();
    }
  });
});
