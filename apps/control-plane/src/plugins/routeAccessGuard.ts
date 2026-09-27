import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import type { AccessRule } from "./routeAccessManifest.js";
import { lookupRouteAccess, ROUTE_ACCESS_MANIFEST, routeAccessKey } from "./routeAccessManifest.js";

export interface RouteAccessGuardOptions {
  /**
   * Honor a manifest entry's `transitional` rules in addition to its durable
   * `access`. This exists ONLY for the temporary WAF-containment migration
   * window (e.g. letting the still-operator-scoped verifier POST decisions
   * until its registry entry is re-scoped to a service principal). It MUST be
   * false once the /v1 WAF block is retired. Wire it from an explicit env flag;
   * never default it on.
   */
  readonly allowTransitional?: boolean | undefined;
}

/**
 * The normalized route template as Fastify exposes it at onRequest time. Kept in
 * one place so the contract test can assert it is populated for every route; if
 * Fastify ever stops exposing it here, callers fail closed (see the guard).
 */
export function normalizedRouteTemplate(request: FastifyRequest): string | undefined {
  const url = request.routeOptions?.url;
  return typeof url === "string" && url.length > 0 ? url : undefined;
}

function ruleSatisfied(rule: AccessRule, request: FastifyRequest): boolean {
  switch (rule.kind) {
    case "public":
      return true;
    case "exchange_principal":
      // Fails closed until AUTH-1 provides org/agent identity + a pre-registered
      // proof-key thumbprint. A caller-supplied DPoP JWK proves only key
      // possession, never org/agent, so there is nothing safe to accept yet.
      return false;
    case "operator": {
      const ctx = request.operatorAuth;
      if (ctx === undefined || (ctx.principalKind ?? "operator") !== "operator") {
        return false;
      }
      return ctx.roles.includes("admin") || ctx.roles.includes(rule.role);
    }
    case "service": {
      const ctx = request.operatorAuth;
      if (ctx === undefined || (ctx.principalKind ?? "operator") !== "service") {
        return false;
      }
      return (ctx.serviceRoles ?? []).includes(rule.role);
    }
    default:
      return false;
  }
}

/**
 * Deny-by-default authorization for the control plane. Registers a second
 * `onRequest` hook (which MUST be registered AFTER the operator-auth annotation
 * plugin, so `request.operatorAuth` is already populated) that authorizes the
 * request against the route-access manifest BEFORE body parsing/validation, so
 * an unauthenticated caller cannot make the server do schema/body work.
 *
 * Denial rules:
 *  - route not in the manifest (or template unresolved) -> 403 route_not_authorized
 *    (anti-omission: a newly added, unclassified route fails closed);
 *  - exchange_principal -> fails closed until AUTH-1;
 *  - no/invalid/misconfigured credential -> the annotation's 401/503;
 *  - authenticated but wrong role/principal-kind -> 403 operator_forbidden.
 */
export function registerRouteAccessGuard(
  app: FastifyInstance,
  options: RouteAccessGuardOptions = {},
): void {
  const allowTransitional = options.allowTransitional === true;

  app.addHook("onRequest", (request: FastifyRequest, reply: FastifyReply, done) => {
    const template = normalizedRouteTemplate(request);
    if (template === undefined) {
      reply.code(403).send({ error: "route_not_authorized" });
      return;
    }

    const entry = lookupRouteAccess(request.method, template);
    if (entry === undefined) {
      reply.code(403).send({ error: "route_not_authorized" });
      return;
    }

    const rules: readonly AccessRule[] =
      allowTransitional && entry.transitional !== undefined
        ? [...entry.access, ...entry.transitional.rules]
        : entry.access;

    if (rules.some((rule) => ruleSatisfied(rule, request))) {
      done();
      return;
    }

    // Not authorized. If the caller presented no/invalid credential (or auth is
    // not configured), surface the annotation's specific failure; otherwise it
    // is an authenticated role/principal-kind mismatch.
    if (request.operatorAuth === undefined && request.operatorAuthFailure !== undefined) {
      reply
        .code(request.operatorAuthFailure.statusCode)
        .send({ error: request.operatorAuthFailure.error });
      return;
    }

    reply.code(403).send({ error: "operator_forbidden" });
  });
}

/**
 * Fail fast at startup if the route-access manifest has drifted from the set of
 * actually registered routes: any registered route missing a manifest entry
 * (which the guard would silently deny at runtime), or any manifest entry with no
 * registered route (stale). Registers an `onRoute` collector, so this MUST be
 * called BEFORE the routes are registered; the comparison runs at `onReady`.
 * HEAD is framework-managed (Fastify auto-adds it for every GET) and is exempt;
 * OPTIONS is not auto-added, so an explicit OPTIONS route must be classified.
 * This turns the anti-omission property into a loud deploy-time
 * failure rather than a quiet per-route runtime denial.
 */
export function assertRouteAccessManifestCoverage(app: FastifyInstance): void {
  const registered = new Set<string>();
  app.addHook("onRoute", (route) => {
    const methods = Array.isArray(route.method) ? route.method : [route.method];
    for (const method of methods) {
      const upper = method.toUpperCase();
      // Fastify auto-adds a HEAD route for every GET; those are framework-managed
      // and intentionally unclassified. OPTIONS is NOT auto-added, so an explicitly
      // registered OPTIONS route must be classified (never exempt it) or it
      // reopens an omission class.
      if (upper === "HEAD") {
        continue;
      }
      registered.add(routeAccessKey(upper, route.url));
    }
  });
  app.addHook("onReady", (done) => {
    const manifestKeys = new Set(
      ROUTE_ACCESS_MANIFEST.map((entry) => routeAccessKey(entry.method, entry.template)),
    );
    const unclassified = [...registered].filter((key) => !manifestKeys.has(key)).sort();
    const stale = [...manifestKeys].filter((key) => !registered.has(key)).sort();
    if (unclassified.length > 0 || stale.length > 0) {
      done(
        new Error(
          `route-access manifest drift: unclassified routes (would be denied) [${unclassified.join(", ")}]; ` +
            `stale manifest entries (no such route) [${stale.join(", ")}]`,
        ),
      );
      return;
    }
    done();
  });
}
