import { createHash, generateKeyPairSync } from "node:crypto";

import { SessionExchangeRequestSchema, SessionExchangeResponseSchema } from "@aidenid/common-schemas";
import { signCompactJws } from "@aidenid/crypto";
import { makeOutboxEvent } from "@aidenid/eventing";
import type { FastifyInstance } from "fastify";

import { prefixedId } from "../ids.js";
import type { ControlPlaneServices, GrantRecord } from "../types.js";

const { privateKey: defaultPrivateKey } = generateKeyPairSync("ed25519");
const CONTROL_PLANE_KEY_ID = "cpk_local_ed25519";

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function requestedPermissionsAllowed(grant: GrantRecord, requested: readonly string[]): boolean {
  const grantPermissions = new Set(grant.permissions);
  return requested.every((permission) => grantPermissions.has(permission));
}

export async function registerSessionRoutes(app: FastifyInstance, services: ControlPlaneServices): Promise<void> {
  app.post("/v1/sessions/exchange", async (request, reply) => {
    const parsed = SessionExchangeRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_session_exchange", details: parsed.error.issues });
    }

    const killSwitch = services.killSwitch.current();
    if (killSwitch.active && killSwitch.denyNewSessions) {
      return reply.code(403).send({
        error: "kill_switch_active",
        reason: killSwitch.reason ?? "new sessions disabled",
        updated_at: killSwitch.updatedAt
      });
    }

    const grant = await services.store.getGrant(parsed.data.grant_id);
    if (grant === undefined) {
      return reply.code(404).send({ error: "grant_not_found" });
    }
    if (grant.revokedAt !== undefined || Date.parse(grant.expiresAt) <= Date.now()) {
      return reply.code(403).send({ error: "grant_not_active" });
    }
    if (parsed.data.audience !== grant.siteId || parsed.data.resource !== grant.resource) {
      return reply.code(403).send({ error: "audience_or_resource_mismatch" });
    }
    if (!requestedPermissionsAllowed(grant, parsed.data.requested_permissions)) {
      return reply.code(403).send({ error: "permission_exceeds_grant" });
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiresAtSeconds = nowSeconds + services.sessionTtlSeconds;
    const revocationEpoch = await services.store.currentEpoch(grant.chainId);
    const claims = {
      iss: services.issuer,
      sub: grant.subject,
      aud: grant.siteId,
      resource: grant.resource,
      site_id: grant.siteId,
      grant_id: grant.id,
      chain_id: grant.chainId,
      permissions: parsed.data.requested_permissions,
      ...(parsed.data.llm_brand === undefined ? {} : { llm_brand: parsed.data.llm_brand }),
      cnf: { jkt: parsed.data.proof_jkt },
      revocation_epoch: revocationEpoch,
      iat: nowSeconds,
      nbf: nowSeconds,
      exp: expiresAtSeconds
    };
    const accessToken = signCompactJws(claims, defaultPrivateKey, "EdDSA", { kid: CONTROL_PLANE_KEY_ID });
    const session = await services.store.createSession({
      grantId: grant.id,
      chainId: grant.chainId,
      siteId: grant.siteId,
      tokenHashSha256: tokenHash(accessToken),
      proofJkt: parsed.data.proof_jkt,
      revocationEpoch,
      issuedAt: new Date(nowSeconds * 1000).toISOString(),
      expiresAt: new Date(expiresAtSeconds * 1000).toISOString()
    });
    await services.outbox.publish(
      makeOutboxEvent(prefixedId("evt"), "SESSION_ISSUED_HASH", {
        session_id: session.id,
        grant_id: grant.id,
        chain_id: grant.chainId,
        token_sha256: session.tokenHashSha256
      })
    );

    const response = SessionExchangeResponseSchema.parse({
      access_token: accessToken,
      token_type: "DPoP",
      expires_in: services.sessionTtlSeconds,
      session_id: session.id,
      revocation_epoch: revocationEpoch
    });
    return reply.code(201).send(response);
  });
}
