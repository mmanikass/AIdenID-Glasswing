import { describe, expect, it } from "vitest";

import { createControlPlaneRuntime } from "../src/app.js";

const SCOPED_TOKEN = "test_scoped_operator_token_123456";
const LEGACY_TOKEN = "test_legacy_admin_token_123456";

const scopedHeaders = { authorization: `Bearer ${SCOPED_TOKEN}` };
const legacyHeaders = { authorization: `Bearer ${LEGACY_TOKEN}` };

describe("operator site scopes", () => {
  it("limits target, grant, and revoke authority to assigned sites while preserving unscoped admins", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: {
        entries: [
          { actorId: "site_operator", token: SCOPED_TOKEN, roles: ["admin"], sites: ["sit_scoped"] },
          { actorId: "platform_admin", token: LEGACY_TOKEN, roles: ["admin"] }
        ]
      }
    });

    try {
      const scopedTargetResponse = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: scopedHeaders,
        payload: {
          tenant_id: "ten_scoped",
          site_id: "sit_scoped",
          name: "Scoped Shop",
          origin: "https://scoped.example.com"
        }
      });
      expect(scopedTargetResponse.statusCode).toBe(201);
      const scopedTarget = scopedTargetResponse.json<{ id: string; site_id: string; origin: string }>();

      const foreignTargetDenied = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: scopedHeaders,
        payload: {
          tenant_id: "ten_foreign",
          site_id: "sit_foreign",
          name: "Foreign Shop",
          origin: "https://foreign.example.com"
        }
      });
      expect(foreignTargetDenied.statusCode).toBe(403);
      expect(foreignTargetDenied.json()).toMatchObject({ error: "operator_forbidden" });

      const foreignTargetResponse = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: legacyHeaders,
        payload: {
          tenant_id: "ten_foreign",
          site_id: "sit_foreign",
          name: "Foreign Shop",
          origin: "https://foreign.example.com"
        }
      });
      expect(foreignTargetResponse.statusCode).toBe(201);
      const foreignTarget = foreignTargetResponse.json<{ id: string; origin: string }>();

      const scopedGrantResponse = await runtime.app.inject({
        method: "POST",
        url: "/v1/grants",
        headers: scopedHeaders,
        payload: { target_id: scopedTarget.id, subject: "user_scoped", permissions: ["orders:read"] }
      });
      expect(scopedGrantResponse.statusCode).toBe(201);
      const scopedGrant = scopedGrantResponse.json<{ id: string; chain_id: string }>();

      const foreignGrantDenied = await runtime.app.inject({
        method: "POST",
        url: "/v1/grants",
        headers: scopedHeaders,
        payload: { target_id: foreignTarget.id, subject: "user_foreign", permissions: ["orders:read"] }
      });
      expect(foreignGrantDenied.statusCode).toBe(403);
      expect(foreignGrantDenied.json()).toMatchObject({ error: "operator_forbidden" });

      const foreignGrantResponse = await runtime.app.inject({
        method: "POST",
        url: "/v1/grants",
        headers: legacyHeaders,
        payload: { target_id: foreignTarget.id, subject: "user_foreign", permissions: ["orders:read"] }
      });
      expect(foreignGrantResponse.statusCode).toBe(201);
      const foreignGrant = foreignGrantResponse.json<{ chain_id: string }>();

      const scopedOwnRevoke = await runtime.app.inject({
        method: "POST",
        url: "/v1/revoke",
        headers: scopedHeaders,
        payload: { chain_id: scopedGrant.chain_id, reason: "site_cleanup", actor_id: "site_operator" }
      });
      expect(scopedOwnRevoke.statusCode).toBe(202);

      const scopedForeignRevoke = await runtime.app.inject({
        method: "POST",
        url: "/v1/revoke",
        headers: scopedHeaders,
        payload: { chain_id: foreignGrant.chain_id, reason: "site_cleanup", actor_id: "site_operator" }
      });
      expect(scopedForeignRevoke.statusCode).toBe(403);
      expect(scopedForeignRevoke.json()).toMatchObject({ error: "operator_forbidden" });

      const legacyRevoke = await runtime.app.inject({
        method: "POST",
        url: "/v1/revoke",
        headers: legacyHeaders,
        payload: { chain_id: foreignGrant.chain_id, reason: "platform_cleanup", actor_id: "platform_admin" }
      });
      expect(legacyRevoke.statusCode).toBe(202);
    } finally {
      await runtime.app.close();
    }
  });

  it("rejects empty, duplicate, or malformed site scopes", async () => {
    for (const sites of [[], ["sit_duplicate", "sit_duplicate"], ["site_without_prefix"]]) {
      await expect(
        createControlPlaneRuntime({
          operatorAuth: {
            entries: [{ actorId: "site_operator", token: SCOPED_TOKEN, roles: ["admin"], sites }]
          }
        })
      ).rejects.toThrow(/site scope|site id/i);
    }
  });
});
