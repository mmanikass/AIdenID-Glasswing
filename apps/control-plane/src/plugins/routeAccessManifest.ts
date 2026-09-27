import type { OperatorRole, ServiceRole } from "./operatorAuth.js";

// Re-exported so consumers can import the principal-role types from one place.
export type { ServiceRole };

/**
 * A single acceptable way to satisfy a route's access policy. A route lists an
 * array of these (ANY-OF): a request is authorized if it satisfies at least one
 * rule. An empty array — or a route absent from the manifest — is DENIED. This
 * default-deny is the anti-omission property: a newly added route that nobody
 * classified fails closed rather than silently exposing itself.
 */
export type AccessRule =
  | { readonly kind: "public" }
  | { readonly kind: "operator"; readonly role: OperatorRole }
  | { readonly kind: "service"; readonly role: ServiceRole }
  | { readonly kind: "exchange_principal" };

export interface RouteAccessEntry {
  /** Upper-case HTTP method as Fastify reports it. */
  readonly method: string;
  /** Normalized route template as Fastify exposes it via RouteOptions.url (":param" form). */
  readonly template: string;
  /** ANY-OF access rules. Empty => deny. */
  readonly access: readonly AccessRule[];
  /**
   * Rules accepted ONLY during the temporary WAF-containment transition, in
   * addition to `access`. These MUST be removed before the /v1 WAF block is
   * retired; they exist so a live caller is not broken mid-migration. They are
   * never part of the durable policy.
   */
  readonly transitional?: {
    readonly rules: readonly AccessRule[];
    readonly reason: string;
  };
}

const PUBLIC: readonly AccessRule[] = [{ kind: "public" }];
const EXCHANGE: readonly AccessRule[] = [{ kind: "exchange_principal" }];
const op = (role: OperatorRole): AccessRule => ({ kind: "operator", role });
const svc = (role: ServiceRole): AccessRule => ({ kind: "service", role });

/**
 * Authoritative route -> access policy for every registered control-plane route.
 * The onRequest guard (routeAccessGuard) enforces this; the contract test suite
 * asserts it covers exactly the set of registered routes (no unlisted route, no
 * stale entry). Keep in sync with the route registrations.
 */
export const ROUTE_ACCESS_MANIFEST: readonly RouteAccessEntry[] = [
  // ---- public: exactly six deliberately anonymous registrations ----
  { method: "GET", template: "/healthz", access: PUBLIC },
  { method: "GET", template: "/readyz", access: PUBLIC },
  { method: "POST", template: "/v1/identities", access: PUBLIC }, // agent challenge submission
  { method: "GET", template: "/.well-known/oauth-protected-resource", access: PUBLIC },
  { method: "GET", template: "/v1/mcp/protected-resource-metadata", access: PUBLIC },
  { method: "GET", template: "/v1/mcp/front-door/roadmap", access: PUBLIC },
  { method: "GET", template: "/.well-known/aidenid-session-jwks.json", access: PUBLIC }, // session-token verification key

  // ---- exchange principal: proof-bound; fails closed until AUTH-1 binding exists ----
  { method: "POST", template: "/v1/sessions/exchange", access: EXCHANGE },

  // ---- service principals (verifier) ----
  {
    method: "POST",
    template: "/v1/decisions",
    access: [svc("decision_ingest")],
    transitional: {
      rules: [op("decision_operator")],
      reason:
        "TRANSITIONAL ONLY while the public /v1 WAF block is active. The live verifier token still carries operator roles; remove this fallback and rely on service:decision_ingest alone once the operator-token registry is re-scoped to a service principal, before WAF retirement.",
    },
  },
  { method: "GET", template: "/v1/decisions/:id/await", access: [svc("decision_status"), op("decision_search")] },

  // ---- operator:decision_search (decision observability reads + usage reads) ----
  // Reclassified from public on 2026-08-13 to follow the landed handler: #285 gates this route
  // with requireOperatorRole(decision_search) in adoption.ts. The manifest is the older
  // generation, so it follows main rather than re-opening the route as a merge side effect.
  // Whether onboarding should be reachable before a prospect holds an operator token is a
  // product decision tracked on this PR, not something this reclassification forecloses.
  { method: "GET", template: "/v1/onboarding/target-plan", access: [op("decision_search")] },
  { method: "GET", template: "/v1/decisions", access: [op("decision_search")] },
  { method: "GET", template: "/v1/decisions/search", access: [op("decision_search")] },
  { method: "GET", template: "/v1/decisions/chain-segment", access: [op("decision_search")] },
  { method: "GET", template: "/v1/decisions/:id/receipt", access: [op("decision_search")] },
  { method: "GET", template: "/v1/decisions/stream", access: [op("decision_search")] },
  { method: "GET", template: "/v1/quarantine/pins", access: [op("decision_search")] },
  { method: "GET", template: "/v1/usage/meter", access: [op("decision_search")] },
  { method: "GET", template: "/v1/usage/price-required", access: [op("decision_search")] },
  { method: "GET", template: "/v1/counterfactuals/enforcement", access: [op("decision_search")] },

  // ---- operator:decision_operator (per-decision operator action only) ----
  { method: "PATCH", template: "/v1/decisions/:id/operator-action", access: [op("decision_operator")] },

  // ---- operator:admin (global / tenant / compliance controls) ----
  { method: "POST", template: "/v1/targets", access: [op("admin")] },
  { method: "POST", template: "/v1/grants", access: [op("admin")] },
  { method: "POST", template: "/v1/revoke", access: [op("admin")] },
  { method: "GET", template: "/v1/kill-switch", access: [op("admin")] },
  { method: "POST", template: "/v1/kill-switch", access: [op("admin")] },
  { method: "DELETE", template: "/v1/kill-switch", access: [op("admin")] },
  { method: "POST", template: "/v1/policy-copilot/suggestions", access: [op("admin")] },
  { method: "GET", template: "/v1/tenants/:tenantId/quota", access: [op("admin")] },
  { method: "PUT", template: "/v1/tenants/:tenantId/quota", access: [op("admin")] },
  { method: "GET", template: "/v1/tenants/:tenantId/pricing-plan", access: [op("admin")] },
  { method: "PUT", template: "/v1/tenants/:tenantId/pricing-plan", access: [op("admin")] },
  { method: "GET", template: "/v1/billing/rollups", access: [op("admin")] },
  { method: "POST", template: "/v1/billing/rollups", access: [op("admin")] },
  { method: "GET", template: "/v1/billing/exports", access: [op("admin")] },
  { method: "POST", template: "/v1/billing/exports", access: [op("admin")] },
  { method: "POST", template: "/v1/billing/exports/:exportId/delivery-receipt", access: [op("admin")] },
  { method: "POST", template: "/v1/privacy/erase", access: [op("admin")] },
  { method: "GET", template: "/v1/privacy/erasures", access: [op("admin")] },
  { method: "GET", template: "/v1/webhooks/endpoints", access: [op("admin")] },
  { method: "POST", template: "/v1/webhooks/endpoints", access: [op("admin")] },
  { method: "POST", template: "/v1/webhooks/signature-preview", access: [op("admin")] },

  // ---- operator:operator_reputation (identity review + reputation + persona) ----
  { method: "GET", template: "/v1/operators/reputation", access: [op("operator_reputation")] },
  { method: "GET", template: "/v1/operators/reputation/:operatorActorId", access: [op("operator_reputation")] },
  { method: "PUT", template: "/v1/operators/reputation/:operatorActorId", access: [op("operator_reputation")] },
  { method: "GET", template: "/v1/identities/submissions", access: [op("operator_reputation")] },
  { method: "GET", template: "/v1/identities/review-notifications", access: [op("operator_reputation")] },
  { method: "PATCH", template: "/v1/identities/review-notifications/:notificationId", access: [op("operator_reputation")] },
  { method: "PATCH", template: "/v1/identities/submissions/:submissionId/review", access: [op("operator_reputation")] },
  { method: "GET", template: "/v1/persona-audits", access: [op("operator_reputation")] },
];

const MANIFEST_BY_KEY: ReadonlyMap<string, RouteAccessEntry> = new Map(
  ROUTE_ACCESS_MANIFEST.map((entry) => [`${entry.method.toUpperCase()} ${entry.template}`, entry]),
);

/** Manifest key for a (method, template) pair. */
export function routeAccessKey(method: string, template: string): string {
  return `${method.toUpperCase()} ${template}`;
}

/**
 * Look up the durable access rules for a route. Returns undefined when the route
 * is not in the manifest — callers MUST treat undefined as DENY (default-deny).
 */
export function lookupRouteAccess(method: string, template: string): RouteAccessEntry | undefined {
  return MANIFEST_BY_KEY.get(routeAccessKey(method, template));
}
