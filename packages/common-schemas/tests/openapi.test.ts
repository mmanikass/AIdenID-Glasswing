import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { buildOpenApiDocument } from "../src/openapi.js";

describe("OpenAPI generation", () => {
  it("keeps checked-in OpenAPI output in sync with the generator", () => {
    const generated = JSON.parse(readFileSync(new URL("../../../docs/api/openapi.json", import.meta.url), "utf8"));

    expect(generated).toEqual(buildOpenApiDocument());
  });

  it("publishes shared enum schemas", () => {
    const doc = buildOpenApiDocument();

    expect(doc.components.schemas.ActorClass).toMatchObject({
      enum: ["verified_agent", "signed_agent", "likely_human", "suspicious_automation", "unknown"]
    });
    expect(doc.components.schemas.DecisionAction).toMatchObject({
      enum: ["allow", "throttle", "queue", "sandbox", "deny", "price_required"]
    });
    expect(doc.components.schemas.OperatorAction).toMatchObject({
      enum: ["allow", "throttle", "queue", "sandbox", "deny", "price_required", "quarantine"]
    });
  });

  it("documents verifier deny registration hints", () => {
    const doc = buildOpenApiDocument();

    expect(doc.components.schemas.VerifierDenyResponse).toMatchObject({
      type: "object",
      required: ["code", "message", "requestId", "decision"],
      properties: {
        register_url: { type: "string", format: "uri" },
        docs_url: { type: "string", format: "uri" },
        identity_challenge: { $ref: "#/components/schemas/AgentIdentityChallenge" }
      },
      additionalProperties: false
    });
  });

  it("documents agent identity challenge submission endpoints", () => {
    const doc = buildOpenApiDocument();

    expect(doc.paths).toHaveProperty("/v1/identities");
    expect(doc.paths).toHaveProperty("/v1/identities/submissions");
    expect(doc.paths).toHaveProperty("/v1/identities/submissions/{submission_id}/review");
    expect(doc.paths).toHaveProperty("/v1/identities/review-notifications");
    expect(doc.paths).toHaveProperty("/v1/identities/review-notifications/{notification_id}");
    expect(doc.components.schemas.AgentIdentityChallenge).toMatchObject({
      required: expect.arrayContaining(["required_fields", "optional_fields", "allowed_purposes", "cascade_layers", "submit"]),
      properties: {
        type: { const: "aidenid.agent_identity_challenge" },
        allowed_purposes: { minItems: 10, maxItems: 10 },
        cascade_layers: { minItems: 4, maxItems: 4 }
      },
      additionalProperties: false
    });
    expect(doc.components.schemas.AgentIdentityChallengeSubmissionRequest).toMatchObject({
      required: [
        "site_id",
        "purpose",
        "requested_access_duration_seconds",
        "provider_name",
        "contact_url",
        "cascade_attestation"
      ],
      properties: {
        purpose: { $ref: "#/components/schemas/AgentIdentityPurpose" },
        requested_access_duration_seconds: { minimum: 60, maximum: 7776000 },
        purpose_rationale: { maxLength: 1024 },
        delegation_authority_jwk_thumbprint_sha256: { pattern: "^[a-f0-9]{64}$" },
        cascade_attestation: { minItems: 4, maxItems: 4 }
      },
      additionalProperties: false
    });
    expect(doc.components.schemas.AgentIdentityChallengeReviewRequest).toMatchObject({
      properties: {
        default_action: { $ref: "#/components/schemas/DecisionAction", default: "allow" },
        default_scope_routes: { $ref: "#/components/schemas/OperatorDefaultScopeRoutes" },
        default_scope_redirect_path: { $ref: "#/components/schemas/OperatorDefaultScopeRedirectPath" },
        approval_expires_at: { type: "string", format: "date-time" }
      },
      additionalProperties: false
    });
    expect(doc.components.schemas.OperatorReputation).toMatchObject({
      required: expect.arrayContaining(["default_action", "default_scope_routes"]),
      properties: {
        status: { type: "string", enum: ["active", "watchlist", "suspended", "expired"] },
        default_action: { $ref: "#/components/schemas/DecisionAction" },
        default_scope_routes: { $ref: "#/components/schemas/OperatorDefaultScopeRoutes" },
        expires_at: { type: "string", format: "date-time", nullable: true }
      }
    });
    expect(doc.components.schemas.AgentIdentityPurpose).toMatchObject({
      enum: expect.arrayContaining(["research", "ai_training", "competitive_intelligence", "other"])
    });
    expect(doc.components.schemas.AgentIdentityReviewNotification).toMatchObject({
      required: expect.arrayContaining(["id", "submission_id", "review_decision", "status"])
    });
  });

  it("documents MCP protected-resource metadata discovery", () => {
    const doc = buildOpenApiDocument();

    expect(doc.paths).toHaveProperty("/.well-known/oauth-protected-resource");
    expect(doc.paths).toHaveProperty("/v1/mcp/protected-resource-metadata");
    expect(doc.components.schemas.McpProtectedResourceMetadata).toMatchObject({
      type: "object",
      required: expect.arrayContaining(["resource", "authorization_servers", "dpop_bound_access_tokens_required"]),
      properties: {
        bearer_methods_supported: { type: "array", items: { enum: ["header"] } },
        dpop_bound_access_tokens_required: { const: true }
      },
      additionalProperties: false
    });
  });

  it("documents tenant metering ledger endpoints", () => {
    const doc = buildOpenApiDocument();

    expect(doc.paths).toHaveProperty("/v1/tenants/{tenant_id}/pricing-plan");
    expect(doc.paths).toHaveProperty("/v1/billing/rollups");
    expect(doc.paths).toHaveProperty("/v1/billing/exports");
    expect(doc.paths).toHaveProperty("/v1/billing/exports/{export_id}/delivery-receipt");
    expect(doc.paths).toMatchObject({
      "/v1/billing/exports": {
        get: {
          parameters: expect.arrayContaining([
            expect.objectContaining({ name: "tenant_id" }),
            expect.objectContaining({ name: "provider" }),
            expect.objectContaining({ name: "status" }),
            expect.objectContaining({ name: "period_start" }),
            expect.objectContaining({ name: "period_end" }),
            expect.objectContaining({ name: "limit" })
          ])
        }
      }
    });
    expect(doc.components.schemas.UsageMeterResponse).toMatchObject({
      properties: {
        usage: {
          required: expect.arrayContaining([
            "billable_cleared_decision_count",
            "overage_cleared_decision_count",
            "pricing_plan_tier",
            "billing_unit_price_usd",
            "price_required_gross_usd"
          ])
        }
      }
    });
    expect(doc.components.schemas.BillingPeriodRollup).toMatchObject({
      required: expect.arrayContaining(["invoice_line_item_id", "export_idempotency_key"])
    });
    expect(doc.components.schemas.BillingExport).toMatchObject({
      required: expect.arrayContaining(["provider", "idempotency_key", "payload_sha256", "payload"]),
      properties: {
        provider: { $ref: "#/components/schemas/BillingExportProvider" },
        provider_receipt_payload_sha256: { type: "string", pattern: "^[a-f0-9]{64}$" }
      }
    });
    expect(doc.components.schemas.BillingExportDeliveryReceiptRequest).toMatchObject({
      required: ["provider_receipt_id", "provider_receipt_status"],
      additionalProperties: false
    });
  });
});
