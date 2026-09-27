import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createOperatorTokenRegistry,
  createControlPlaneRuntime,
  InMemoryControlPlaneStore,
  InMemoryKillSwitchController,
  type ControlPlaneStore,
} from "../src/index.js";
import { assertRouteAccessManifestCoverage } from "../src/plugins/routeAccessGuard.js";
import { requireOperatorRole } from "../src/plugins/operatorAuth.js";
import {
  lookupRouteAccess,
  ROUTE_ACCESS_MANIFEST,
} from "../src/plugins/routeAccessManifest.js";
import { InMemoryPersonaAuditController } from "../src/services/personaAudit.js";

type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
type AccessLabel =
  | "public"
  | "exchange_principal"
  | `operator:${string}`
  | `service:${string}`;

interface AuditRoute {
  readonly method: HttpMethod;
  readonly template: string;
  readonly access?: AccessLabel | undefined;
  readonly access_any_of?: readonly AccessLabel[] | undefined;
}

interface RouteAuthorizationAudit {
  readonly schema_version: string;
  readonly route_registration_count: number;
  readonly public_route_count: number;
  readonly protected_route_count: number;
  readonly public_routes: readonly AuditRoute[];
  readonly protected_routes: readonly AuditRoute[];
}

interface RouteProbe {
  readonly method: HttpMethod;
  readonly template: string;
  readonly url: string;
  readonly payload?: Readonly<Record<string, unknown>> | undefined;
  readonly access: readonly AccessLabel[];
}

const auditArtifactPath = fileURLToPath(
  new URL(
    "./fixtures/route-authorization-contract.json",
    import.meta.url,
  ),
);
const auditArtifact = JSON.parse(
  readFileSync(auditArtifactPath, "utf8"),
) as RouteAuthorizationAudit;

const BODY_METHODS = new Set<HttpMethod>(["POST", "PUT", "PATCH", "DELETE"]);
const SAMPLE_ROUTE_PARAMS: Readonly<Record<string, string>> = {
  id: "dec_auth_probe",
  tenantId: "ten_auth_probe",
  exportId: "bex_auth_probe",
  operatorActorId: "operator_auth_probe",
  notificationId: "arn_auth_probe",
  submissionId: "ais_auth_probe",
};

function accessLabels(route: AuditRoute): readonly AccessLabel[] {
  if (route.access_any_of !== undefined) {
    return route.access_any_of;
  }
  if (route.access !== undefined) {
    return [route.access];
  }
  throw new Error(
    `route ${route.method} ${route.template} has no access policy`,
  );
}

function materializeRouteTemplate(template: string): string {
  const path = template.replace(
    /:([A-Za-z][A-Za-z0-9]*)/g,
    (_match, name: string) => {
      const value = SAMPLE_ROUTE_PARAMS[name];
      if (value === undefined) {
        throw new Error(`route template has no test value for :${name}`);
      }
      return value;
    },
  );
  if (template === "/v1/decisions/:id/await") {
    return `${path}?timeout_ms=1`;
  }
  if (template === "/v1/decisions/stream") {
    return `${path}?once=true`;
  }
  return path;
}

function routeProbe(route: AuditRoute): RouteProbe {
  return {
    method: route.method,
    template: route.template,
    url: materializeRouteTemplate(route.template),
    ...(BODY_METHODS.has(route.method) ? { payload: {} } : {}),
    access: accessLabels(route),
  };
}

const PROTECTED_ROUTE_PROBES = auditArtifact.protected_routes.map(routeProbe);

const ADMIN_TOKEN = "test_platform_admin_token_123456";
const DECISION_OPERATOR_TOKEN = "test_decision_operator_token_123456";
const DECISION_SEARCH_TOKEN = "test_decision_search_token_123456";
const REPUTATION_TOKEN = "test_identity_reviewer_token_123456";
const SERVICE_INGEST_TOKEN = "test_service_ingest_token_123456";
const SERVICE_STATUS_TOKEN = "test_service_status_token_123456";

const OPERATOR_AUTH = {
  entries: [
    {
      actorId: "platform_admin",
      token: ADMIN_TOKEN,
      roles: ["admin"],
    },
    {
      actorId: "decision_operator",
      token: DECISION_OPERATOR_TOKEN,
      roles: ["decision_operator"],
    },
    {
      actorId: "decision_analyst",
      token: DECISION_SEARCH_TOKEN,
      roles: ["decision_search"],
    },
    {
      actorId: "identity_reviewer",
      token: REPUTATION_TOKEN,
      roles: ["operator_reputation"],
    },
    {
      actorId: "verifier_ingest",
      token: SERVICE_INGEST_TOKEN,
      principalKind: "service",
      serviceRoles: ["decision_ingest"],
    },
    {
      actorId: "verifier_status",
      token: SERVICE_STATUS_TOKEN,
      principalKind: "service",
      serviceRoles: ["decision_status"],
    },
  ],
  env: "",
} as const;

function bearerHeaders(token: string): Readonly<Record<string, string>> {
  return { authorization: ["Bearer", token].join(" ") };
}

const ADMIN_HEADERS = bearerHeaders(ADMIN_TOKEN);
const DECISION_OPERATOR_HEADERS = bearerHeaders(DECISION_OPERATOR_TOKEN);
const SEARCH_HEADERS = bearerHeaders(DECISION_SEARCH_TOKEN);
const REPUTATION_HEADERS = bearerHeaders(REPUTATION_TOKEN);
const SERVICE_INGEST_HEADERS = bearerHeaders(SERVICE_INGEST_TOKEN);
const SERVICE_STATUS_HEADERS = bearerHeaders(SERVICE_STATUS_TOKEN);

interface TestPrincipal {
  readonly label: string;
  readonly kind: "operator" | "service";
  readonly roles: readonly string[];
  readonly headers: Readonly<Record<string, string>>;
}

const TEST_PRINCIPALS: readonly TestPrincipal[] = [
  {
    label: "admin",
    kind: "operator",
    roles: ["admin"],
    headers: ADMIN_HEADERS,
  },
  {
    label: "decision_operator",
    kind: "operator",
    roles: ["decision_operator"],
    headers: DECISION_OPERATOR_HEADERS,
  },
  {
    label: "decision_search",
    kind: "operator",
    roles: ["decision_search"],
    headers: SEARCH_HEADERS,
  },
  {
    label: "operator_reputation",
    kind: "operator",
    roles: ["operator_reputation"],
    headers: REPUTATION_HEADERS,
  },
  {
    label: "service:decision_ingest",
    kind: "service",
    roles: ["decision_ingest"],
    headers: SERVICE_INGEST_HEADERS,
  },
  {
    label: "service:decision_status",
    kind: "service",
    roles: ["decision_status"],
    headers: SERVICE_STATUS_HEADERS,
  },
];

function accessLabelForManifestRule(rule: {
  readonly kind: string;
  readonly role?: string | undefined;
}): AccessLabel {
  return rule.role === undefined
    ? (rule.kind as AccessLabel)
    : (`${rule.kind}:${rule.role}` as AccessLabel);
}

function principalSatisfies(
  principal: TestPrincipal,
  access: readonly AccessLabel[],
): boolean {
  if (access.includes("public")) {
    return true;
  }
  if (access.includes("exchange_principal")) {
    return false;
  }
  if (principal.kind === "operator") {
    return (
      principal.roles.includes("admin") ||
      principal.roles.some((role) => access.includes(`operator:${role}`))
    );
  }
  return principal.roles.some((role) => access.includes(`service:${role}`));
}

function routeLabel(route: RouteProbe): string {
  return `${route.method} ${route.url}`;
}

function bodyObject(body: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(body) as unknown;
    return parsed !== null &&
      typeof parsed === "object" &&
      !Array.isArray(parsed)
      ? (parsed as Readonly<Record<string, unknown>>)
      : {};
  } catch {
    return {};
  }
}

function recordingProxy<T extends object>(
  namespace: string,
  target: T,
  calls: string[],
): T {
  return new Proxy(target, {
    get(value, property) {
      const member = Reflect.get(value, property, value) as unknown;
      if (typeof member !== "function") {
        return member;
      }
      return (...args: unknown[]) => {
        calls.push(`${namespace}.${String(property)}`);
        return Reflect.apply(member, value, args);
      };
    },
  });
}

function registerManifestProbeRoutes(
  app: FastifyInstance,
  omittedKey?: string,
): void {
  for (const entry of ROUTE_ACCESS_MANIFEST) {
    const key = `${entry.method} ${entry.template}`;
    if (key === omittedKey) {
      continue;
    }
    app.route({
      method: entry.method as HttpMethod,
      url: entry.template,
      handler: async () => ({ ok: true }),
    });
  }
}

async function startupFailure(
  app: FastifyInstance,
): Promise<Error | undefined> {
  try {
    await app.ready();
    return undefined;
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

describe.sequential("control-plane route authorization contract", () => {
  beforeEach(() => {
    vi.stubEnv("AIDENID_ROUTE_ACCESS_GUARD_ENABLED", "true");
    vi.stubEnv("AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL", "false");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("matches the machine-readable 50-route contract exactly", () => {
    const expected = [
      ...auditArtifact.public_routes,
      ...auditArtifact.protected_routes,
    ]
      .map((route) => ({
        key: `${route.method} ${route.template}`,
        access: [...accessLabels(route)],
      }))
      .sort((left, right) => left.key.localeCompare(right.key));
    const actual = ROUTE_ACCESS_MANIFEST.map((entry) => ({
      key: `${entry.method} ${entry.template}`,
      access: entry.access.map(accessLabelForManifestRule),
    })).sort((left, right) => left.key.localeCompare(right.key));

    expect(auditArtifact.schema_version).toBe(
      "aidenid.control-plane-route-authorization-audit.v2",
    );
    expect(auditArtifact.route_registration_count).toBe(50);
    expect(auditArtifact.public_route_count).toBe(7);
    expect(auditArtifact.protected_route_count).toBe(43);
    expect(ROUTE_ACCESS_MANIFEST).toHaveLength(50);
    expect(new Set(actual.map(({ key }) => key)).size).toBe(50);
    expect(actual).toEqual(expected);
    expect(
      PROTECTED_ROUTE_PROBES.map(
        ({ method, template }) => `${method} ${template}`,
      ),
    ).toEqual(
      auditArtifact.protected_routes.map(
        ({ method, template }) => `${method} ${template}`,
      ),
    );

    const ingest = lookupRouteAccess("POST", "/v1/decisions");
    expect(ingest?.access.map(accessLabelForManifestRule)).toEqual([
      "service:decision_ingest",
    ]);
    expect(ingest?.transitional).toMatchObject({
      rules: [{ kind: "operator", role: "decision_operator" }],
      reason: expect.stringMatching(/WAF.*before WAF retirement/i),
    });
    expect(
      ROUTE_ACCESS_MANIFEST.filter((entry) => entry.transitional !== undefined),
    ).toHaveLength(1);
    expect(lookupRouteAccess("GET", "/v1/unclassified")).toBeUndefined();
  });

  it("fails startup on unclassified, stale, and explicit OPTIONS routes", async () => {
    const exact = fastify();
    assertRouteAccessManifestCoverage(exact);
    registerManifestProbeRoutes(exact);
    await exact.ready();
    await exact.close();

    const unclassified = fastify();
    assertRouteAccessManifestCoverage(unclassified);
    registerManifestProbeRoutes(unclassified);
    unclassified.get("/v1/unclassified-auth-probe", async () => ({ ok: true }));
    expect((await startupFailure(unclassified))?.message).toMatch(
      /unclassified routes.*GET \/v1\/unclassified-auth-probe/i,
    );
    await unclassified.close().catch(() => undefined);

    const stale = fastify();
    assertRouteAccessManifestCoverage(stale);
    registerManifestProbeRoutes(stale, "GET /healthz");
    expect((await startupFailure(stale))?.message).toMatch(
      /stale manifest entries.*GET \/healthz/i,
    );
    await stale.close().catch(() => undefined);

    const explicitOptions = fastify();
    assertRouteAccessManifestCoverage(explicitOptions);
    registerManifestProbeRoutes(explicitOptions);
    explicitOptions.options("/v1/unclassified-options", async () => ({
      ok: true,
    }));
    expect((await startupFailure(explicitOptions))?.message).toMatch(
      /unclassified routes.*OPTIONS \/v1\/unclassified-options/i,
    );
    await explicitOptions.close().catch(() => undefined);
  });

  it("denies every protected route before handler or state access", async () => {
    const serviceCalls: string[] = [];
    const store = recordingProxy(
      "store",
      new InMemoryControlPlaneStore(),
      serviceCalls,
    ) as ControlPlaneStore;
    const killSwitch = recordingProxy(
      "killSwitch",
      new InMemoryKillSwitchController(),
      serviceCalls,
    );
    const personaAudit = recordingProxy(
      "personaAudit",
      new InMemoryPersonaAuditController(),
      serviceCalls,
    );
    const runtime = await createControlPlaneRuntime({
      store,
      killSwitch,
      personaAudit,
      operatorAuth: OPERATOR_AUTH,
      decisionOutboxRetentionDays: 0,
    });

    try {
      const failures: string[] = [];
      for (const route of PROTECTED_ROUTE_PROBES) {
        const response = await runtime.app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload === undefined ? {} : { payload: route.payload }),
        });
        const responseBody = bodyObject(response.body);
        const error =
          typeof responseBody.error === "string" ? responseBody.error : "";
        if (response.statusCode !== 401 || !error.endsWith("auth_required")) {
          failures.push(
            `${routeLabel(route)} -> ${response.statusCode} ${error || "non-json-response"}`,
          );
        }
      }

      expect(PROTECTED_ROUTE_PROBES).toHaveLength(43);
      expect.soft(failures).toEqual([]);
      expect.soft(serviceCalls).toEqual([]);
      expect.soft(runtime.outboxStore.all()).toEqual([]);
    } finally {
      await runtime.app.close();
    }
  });

  it("rejects invalid credentials before protected-route validation", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: OPERATOR_AUTH,
      decisionOutboxRetentionDays: 0,
    });
    try {
      const response = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: bearerHeaders("invalid-but-present-operator-token"),
        payload: {},
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        error: "invalid_operator_token",
      });
      expect(await runtime.services.store.countTargets()).toBe(0);
      expect(runtime.outboxStore.all()).toEqual([]);
    } finally {
      await runtime.app.close();
    }
  });

  it("keeps public health, identity challenge, onboarding, and metadata routes public", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: OPERATOR_AUTH,
      decisionOutboxRetentionDays: 0,
    });
    const probes = [
      { method: "GET" as const, url: "/healthz", expectedStatus: 200 },
      { method: "GET" as const, url: "/readyz", expectedStatus: 200 },
      {
        method: "POST" as const,
        url: "/v1/identities",
        payload: {},
        expectedStatus: 400,
      },
      {
        method: "GET" as const,
        url: "/.well-known/oauth-protected-resource",
        expectedStatus: 200,
      },
      {
        method: "GET" as const,
        url: "/v1/mcp/protected-resource-metadata",
        expectedStatus: 200,
      },
      {
        method: "GET" as const,
        url: "/v1/mcp/front-door/roadmap",
        expectedStatus: 200,
      },
    ];

    try {
      for (const probe of probes) {
        const response = await runtime.app.inject({
          method: probe.method,
          url: probe.url,
          ...("payload" in probe ? { payload: probe.payload } : {}),
        });
        expect(response.statusCode, `${probe.method} ${probe.url}`).toBe(
          probe.expectedStatus,
        );
      }
      expect(probes).toHaveLength(6);
    } finally {
      await runtime.app.close();
    }
  });

  it("denies every authenticated principal that does not satisfy the route policy", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: OPERATOR_AUTH,
      decisionOutboxRetentionDays: 0,
    });

    try {
      const failures: string[] = [];
      let denialCount = 0;
      for (const route of PROTECTED_ROUTE_PROBES) {
        for (const principal of TEST_PRINCIPALS) {
          if (principalSatisfies(principal, route.access)) {
            continue;
          }
          denialCount += 1;
          const response = await runtime.app.inject({
            method: route.method,
            url: route.url,
            headers: principal.headers,
            ...(route.payload === undefined ? {} : { payload: route.payload }),
          });
          const responseBody = bodyObject(response.body);
          if (
            response.statusCode !== 403 ||
            responseBody.error !== "operator_forbidden"
          ) {
            failures.push(
              `${principal.label} -> ${routeLabel(route)} -> ${response.statusCode} ${String(responseBody.error ?? "non-json-response")}`,
            );
          }
        }
      }

      expect(denialCount).toBe(194);
      expect(failures).toEqual([]);
    } finally {
      await runtime.app.close();
    }
  });

  it("preserves least-privilege operator and service access", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: OPERATOR_AUTH,
      decisionOutboxRetentionDays: 0,
    });
    try {
      const admin = await runtime.app.inject({
        method: "GET",
        url: "/v1/kill-switch",
        headers: ADMIN_HEADERS,
      });
      expect(admin.statusCode).toBe(200);

      const search = await runtime.app.inject({
        method: "GET",
        url: "/v1/decisions/search?site_id=sit_auth_probe",
        headers: SEARCH_HEADERS,
      });
      expect(search.statusCode).toBe(200);
      expect(search.json()).toEqual({ decisions: [] });

      const ingest = await runtime.app.inject({
        method: "POST",
        url: "/v1/decisions",
        headers: SERVICE_INGEST_HEADERS,
        payload: {},
      });
      expect(ingest.statusCode).toBe(400);
      expect(ingest.json()).toMatchObject({ error: "invalid_decision_record" });

      const serviceStatus = await runtime.app.inject({
        method: "GET",
        url: "/v1/decisions/dec_auth_probe/await?timeout_ms=1",
        headers: SERVICE_STATUS_HEADERS,
      });
      expect(serviceStatus.statusCode).toBe(404);
      expect(serviceStatus.json()).toMatchObject({
        error: "decision_not_found",
      });

      const operatorStatus = await runtime.app.inject({
        method: "GET",
        url: "/v1/decisions/dec_auth_probe/await?timeout_ms=1",
        headers: SEARCH_HEADERS,
      });
      expect(operatorStatus.statusCode).toBe(404);
      expect(operatorStatus.json()).toMatchObject({
        error: "decision_not_found",
      });

      const operatorAction = await runtime.app.inject({
        method: "PATCH",
        url: "/v1/decisions/dec_auth_probe/operator-action",
        headers: DECISION_OPERATOR_HEADERS,
        payload: {},
      });
      expect(operatorAction.statusCode).toBe(400);
      expect(operatorAction.json()).toMatchObject({
        error: "invalid_operator_action",
      });

      const reputation = await runtime.app.inject({
        method: "GET",
        url: "/v1/operators/reputation",
        headers: REPUTATION_HEADERS,
      });
      expect(reputation.statusCode).toBe(400);
      expect(reputation.json()).toMatchObject({
        error: "invalid_operator_reputation_query",
      });
    } finally {
      await runtime.app.close();
    }
  });

  it("keeps the legacy ingest fallback explicit and off by default", async () => {
    const durableRuntime = await createControlPlaneRuntime({
      operatorAuth: OPERATOR_AUTH,
      decisionOutboxRetentionDays: 0,
    });
    try {
      const denied = await durableRuntime.app.inject({
        method: "POST",
        url: "/v1/decisions",
        headers: DECISION_OPERATOR_HEADERS,
        payload: {},
      });
      expect(denied.statusCode).toBe(403);
      expect(denied.json()).toMatchObject({ error: "operator_forbidden" });
    } finally {
      await durableRuntime.app.close();
    }

    vi.stubEnv("AIDENID_ROUTE_ACCESS_ALLOW_TRANSITIONAL", "true");
    const transitionalRuntime = await createControlPlaneRuntime({
      operatorAuth: OPERATOR_AUTH,
      decisionOutboxRetentionDays: 0,
    });
    try {
      const accepted = await transitionalRuntime.app.inject({
        method: "POST",
        url: "/v1/decisions",
        headers: DECISION_OPERATOR_HEADERS,
        payload: {},
      });
      expect(accepted.statusCode).toBe(400);
      expect(accepted.json()).toMatchObject({
        error: "invalid_decision_record",
      });
    } finally {
      await transitionalRuntime.app.close();
    }
  });

  it("fails unknown routes and missing auth configuration closed", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: OPERATOR_AUTH,
      decisionOutboxRetentionDays: 0,
    });
    try {
      const unknown = await runtime.app.inject({
        method: "GET",
        url: "/v1/unclassified-auth-probe",
        headers: ADMIN_HEADERS,
      });
      expect(unknown.statusCode).toBe(403);
      expect(unknown.json()).toMatchObject({ error: "route_not_authorized" });
    } finally {
      await runtime.app.close();
    }

    const unconfigured = await createControlPlaneRuntime({
      operatorAuth: { entries: [], env: "" },
      decisionOutboxRetentionDays: 0,
    });
    try {
      const denied = await unconfigured.app.inject({
        method: "GET",
        url: "/v1/decisions",
      });
      expect(denied.statusCode).toBe(503);
      expect(denied.json()).toMatchObject({
        error: "operator_auth_not_configured",
      });

      const health = await unconfigured.app.inject({
        method: "GET",
        url: "/healthz",
      });
      expect(health.statusCode).toBe(200);
    } finally {
      await unconfigured.app.close();
    }
  });

  it("loads service principal fields from both environment registry shapes", () => {
    const arrayToken = "test_env_service_array_token_123456";
    const arrayRegistry = createOperatorTokenRegistry({
      env: JSON.stringify([
        {
          actor_id: "verifier_array",
          token: arrayToken,
          principal_kind: "service",
          service_roles: ["decision_ingest", "decision_status"],
        },
      ]),
    });
    expect(arrayRegistry.authenticate(arrayToken)).toEqual({
      actorId: "verifier_array",
      roles: [],
      principalKind: "service",
      serviceRoles: ["decision_ingest", "decision_status"],
    });

    const objectToken = "test_env_service_object_token_123456";
    const objectRegistry = createOperatorTokenRegistry({
      env: JSON.stringify({
        verifier_object: {
          token: objectToken,
          principalKind: "service",
          serviceRoles: ["decision_ingest"],
        },
      }),
    });
    expect(objectRegistry.authenticate(objectToken)).toEqual({
      actorId: "verifier_object",
      roles: [],
      principalKind: "service",
      serviceRoles: ["decision_ingest"],
    });
  });

  it("rejects invalid and mixed-principal registry authority", () => {
    expect(() =>
      createOperatorTokenRegistry({
        entries: [
          {
            actorId: "mixed_service",
            token: "test_mixed_service_token_123456",
            principalKind: "service",
            roles: ["admin"],
            serviceRoles: ["decision_ingest"],
          },
        ],
      }),
    ).toThrow(/service principal.*operator roles/i);

    expect(() =>
      createOperatorTokenRegistry({
        entries: [
          {
            actorId: "mixed_operator",
            token: "test_mixed_operator_token_123456",
            principalKind: "operator",
            roles: ["decision_search"],
            serviceRoles: ["decision_status"],
          },
        ],
      }),
    ).toThrow(/operator principal.*service roles/i);

    expect(() =>
      createOperatorTokenRegistry({
        env: JSON.stringify([
          {
            actor_id: "invalid_kind",
            token: "test_invalid_kind_token_123456",
            principal_kind: "robot",
            service_roles: ["decision_ingest"],
          },
        ]),
      }),
    ).toThrow(/principal kind/i);
  });

  it("preserves legacy bare-string operator defaults without an override", () => {
    const legacyToken = "test_legacy_bare_string_token_123456";
    const registry = createOperatorTokenRegistry({
      env: JSON.stringify({ legacy_operator: legacyToken }),
    });

    expect(registry.authenticate(legacyToken)).toEqual({
      actorId: "legacy_operator",
      roles: ["decision_operator", "decision_search"],
      principalKind: "operator",
      serviceRoles: [],
    });
  });

  it("reclassifies a legacy bare-string token through the service-principal map", () => {
    const verifierToken = "test_legacy_verifier_service_token_123456";
    const registry = createOperatorTokenRegistry({
      env: JSON.stringify({ verifier_control_plane_api_key: verifierToken }),
      servicePrincipalOverrides: JSON.stringify({
        verifier_control_plane_api_key: {
          principal_kind: "service",
          service_roles: ["decision_ingest", "decision_status"],
        },
      }),
    });

    expect(registry.authenticate(verifierToken)).toEqual({
      actorId: "verifier_control_plane_api_key",
      roles: [],
      principalKind: "service",
      serviceRoles: ["decision_ingest", "decision_status"],
    });
  });

  it("rejects stale service-principal override actor keys", () => {
    expect(() =>
      createOperatorTokenRegistry({
        env: JSON.stringify({
          configured_actor: "test_configured_actor_token_123456",
        }),
        servicePrincipalOverrides: JSON.stringify({
          missing_actor: {
            principal_kind: "service",
            service_roles: ["decision_ingest"],
          },
        }),
      }),
    ).toThrow(/override references unknown actor: missing_actor/i);
  });

  it("rejects invalid service-principal override kinds and roles", () => {
    const env = JSON.stringify({
      verifier: "test_override_validation_token_123456",
    });

    expect(() =>
      createOperatorTokenRegistry({
        env,
        servicePrincipalOverrides: JSON.stringify({
          verifier: {
            principal_kind: "operator",
            service_roles: ["decision_ingest"],
          },
        }),
      }),
    ).toThrow(/must set principal_kind "service"/i);

    expect(() =>
      createOperatorTokenRegistry({
        env,
        servicePrincipalOverrides: JSON.stringify({
          verifier: {
            principal_kind: "service",
            service_roles: [],
          },
        }),
      }),
    ).toThrow(/must list at least one service role/i);

    expect(() =>
      createOperatorTokenRegistry({
        env,
        servicePrincipalOverrides: JSON.stringify({
          verifier: {
            principal_kind: "service",
            service_roles: ["admin"],
          },
        }),
      }),
    ).toThrow(/unsupported service role: admin/i);
  });

  it("rejects conflicting or redundant authority metadata on overridden entries", () => {
    const override = JSON.stringify({
      verifier: {
        principal_kind: "service",
        service_roles: ["decision_ingest"],
      },
    });

    expect(() =>
      createOperatorTokenRegistry({
        env: JSON.stringify({
          verifier: {
            token: "test_explicit_operator_metadata_token_123456",
            roles: ["decision_search"],
          },
        }),
        servicePrincipalOverrides: override,
      }),
    ).toThrow(/conflicts with explicit metadata for actor: verifier/i);

    expect(() =>
      createOperatorTokenRegistry({
        env: JSON.stringify({
          verifier: {
            token: "test_redundant_service_metadata_token_123456",
            principal_kind: "service",
            service_roles: ["decision_ingest"],
          },
        }),
        servicePrincipalOverrides: override,
      }),
    ).toThrow(/conflicts with explicit metadata for actor: verifier/i);
  });

  it("keeps requireOperatorRole fail-closed for a malformed service context", () => {
    const request = {
      operatorAuth: {
        actorId: "malformed_service",
        roles: ["admin"],
        principalKind: "service",
        serviceRoles: ["decision_ingest"],
      },
    } as unknown as FastifyRequest;
    const reply = {
      code: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
    } as unknown as FastifyReply;

    expect(
      requireOperatorRole(request, reply, "decision_search"),
    ).toBeUndefined();
    expect(reply.code).toHaveBeenCalledWith(403);
    expect(reply.send).toHaveBeenCalledWith({
      error: "operator_forbidden",
      required_role: "decision_search",
    });
  });

  it("wires the environment service-principal map through the full app", async () => {
    const verifierToken = "test_app_env_verifier_service_token_123456";
    vi.stubEnv(
      "AIDENID_OPERATOR_TOKENS",
      JSON.stringify({ verifier_control_plane_api_key: verifierToken }),
    );
    vi.stubEnv(
      "AIDENID_OPERATOR_SERVICE_PRINCIPALS",
      JSON.stringify({
        verifier_control_plane_api_key: {
          principal_kind: "service",
          service_roles: ["decision_ingest", "decision_status"],
        },
      }),
    );

    const runtime = await createControlPlaneRuntime({
      decisionOutboxRetentionDays: 0,
    });
    try {
      const ingest = await runtime.app.inject({
        method: "POST",
        url: "/v1/decisions",
        headers: bearerHeaders(verifierToken),
        payload: {},
      });
      expect(ingest.statusCode).toBe(400);
      expect(ingest.json()).toMatchObject({ error: "invalid_decision_record" });

      const operatorRead = await runtime.app.inject({
        method: "GET",
        url: "/v1/decisions",
        headers: bearerHeaders(verifierToken),
      });
      expect(operatorRead.statusCode).toBe(403);
      expect(operatorRead.json()).toMatchObject({
        error: "operator_forbidden",
      });
    } finally {
      await runtime.app.close();
    }
  });
});
