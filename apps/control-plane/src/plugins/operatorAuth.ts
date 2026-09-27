import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

export type OperatorRole = "admin" | "decision_operator" | "decision_search" | "operator_reputation";

/**
 * Non-operator service principals (e.g. the verifier). Kept separate from
 * OperatorRole so an ingest-only producer cannot read decision status, and a
 * status reader cannot ingest.
 */
export type ServiceRole = "decision_ingest" | "decision_status";

export type PrincipalKind = "operator" | "service";

export interface OperatorAuthContext {
  readonly actorId: string;
  readonly roles: readonly OperatorRole[];
  /** Site IDs this operator may administer. Absent means the legacy/unrestricted scope. */
  readonly sites?: readonly string[] | undefined;
  /** Principal class of the caller. Absent/undefined is treated as "operator" (tokens predating the service-principal registry). */
  readonly principalKind?: PrincipalKind | undefined;
  /** Service roles held when principalKind === "service"; empty/absent for operators. */
  readonly serviceRoles?: readonly ServiceRole[] | undefined;
}

export interface OperatorAuthTokenEntry {
  readonly actorId: string;
  readonly token: string;
  readonly roles?: readonly OperatorRole[] | undefined;
  /** Optional site scope for operator principals. Omitted preserves legacy unrestricted behavior. */
  readonly sites?: readonly string[] | undefined;
  readonly principalKind?: PrincipalKind | undefined;
  readonly serviceRoles?: readonly ServiceRole[] | undefined;
}

export interface RegisterOperatorAuthOptions {
  readonly entries?: readonly OperatorAuthTokenEntry[] | undefined;
  readonly env?: string | undefined;
  /**
   * Actor-keyed JSON (no token material) that reclassifies a LEGACY registry
   * entry (bare-string / no explicit authority) into a service principal, e.g.
   * {"verifier_control_plane_api_key":{"principal_kind":"service","service_roles":["decision_ingest","decision_status"]}}.
   */
  readonly servicePrincipalOverrides?: string | undefined;
}

interface OperatorAuthFailure {
  readonly statusCode: 401 | 503;
  readonly error: "operator_auth_required" | "invalid_operator_token" | "operator_auth_not_configured";
}

interface HashedOperatorTokenEntry {
  readonly tokenSha256: Buffer;
  readonly context: OperatorAuthContext;
}

declare module "fastify" {
  interface FastifyRequest {
    operatorAuth?: OperatorAuthContext | undefined;
    operatorAuthFailure?: OperatorAuthFailure | undefined;
  }
}

const DEFAULT_ROLES: readonly OperatorRole[] = ["decision_operator", "decision_search"];
const ALLOWED_ROLES: readonly OperatorRole[] = ["admin", "decision_operator", "decision_search", "operator_reputation"];
const ALLOWED_SERVICE_ROLES: readonly ServiceRole[] = ["decision_ingest", "decision_status"];

function normalizeServiceRoles(value: readonly ServiceRole[] | undefined): readonly ServiceRole[] {
  if (value === undefined) {
    return [];
  }
  for (const role of value) {
    if (!ALLOWED_SERVICE_ROLES.includes(role)) {
      throw new Error(`operator token registry entry has unknown service role: ${role}`);
    }
  }
  return [...value];
}

function parsePrincipalKind(value: unknown): PrincipalKind {
  if (value === undefined) {
    return "operator";
  }
  if (value === "operator" || value === "service") {
    return value;
  }
  throw new Error(`unsupported principal kind: ${String(value)}`);
}

function serviceRole(value: unknown): ServiceRole {
  if (typeof value === "string" && ALLOWED_SERVICE_ROLES.includes(value as ServiceRole)) {
    return value as ServiceRole;
  }
  throw new Error(`unsupported service role: ${String(value)}`);
}

function serviceRolesFromUnknown(value: unknown): readonly ServiceRole[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error("service roles must be a non-empty array");
  }
  return value.map(serviceRole);
}

function assertConsistentPrincipal(
  kind: PrincipalKind,
  operatorRoles: readonly OperatorRole[],
  serviceRoles: readonly ServiceRole[]
): void {
  if (kind === "service" && operatorRoles.length > 0) {
    throw new Error("service principal must not carry operator roles");
  }
  if (kind === "operator" && serviceRoles.length > 0) {
    throw new Error("operator principal must not carry service roles");
  }
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function role(value: unknown): OperatorRole {
  if (typeof value === "string" && ALLOWED_ROLES.includes(value as OperatorRole)) {
    return value as OperatorRole;
  }
  throw new Error(`unsupported operator role: ${String(value)}`);
}

function siteScope(value: unknown): readonly string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("operator site scope must be a non-empty array");
  }
  const normalized = value.map((entry) => {
    if (typeof entry !== "string") {
      throw new Error("operator site scope entries must be strings");
    }
    const siteId = entry.trim();
    if (!/^sit_[A-Za-z0-9_-]+$/.test(siteId)) {
      throw new Error(`operator site scope contains an invalid site id: ${siteId}`);
    }
    return siteId;
  });
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("operator site scope contains duplicate site ids");
  }
  return normalized;
}

function roles(value: unknown): readonly OperatorRole[] {
  if (value === undefined) {
    return DEFAULT_ROLES;
  }
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("operator roles must be a non-empty array");
  }
  return value.map(role);
}

function actorId(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("operator actor_id must be a string");
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    throw new Error("operator actor_id must be 1-128 characters");
  }
  return trimmed;
}

function token(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("operator token must be a string");
  }
  const trimmed = value.trim();
  if (trimmed.length < 16) {
    throw new Error("operator token must be at least 16 characters");
  }
  return trimmed;
}

/**
 * Parse an entry's authority fields WITHOUT eager defaults: an omitted field is
 * left undefined so a later service-principal override can tell a genuinely
 * legacy entry from one that was explicitly classified. Constructor defaults
 * apply the operator/DEFAULT_ROLES fallback for non-overridden entries.
 */
function parseEntryAuthority(record: Readonly<Record<string, unknown>>): {
  readonly roles?: readonly OperatorRole[] | undefined;
  readonly sites?: readonly string[] | undefined;
  readonly principalKind?: PrincipalKind | undefined;
  readonly serviceRoles?: readonly ServiceRole[] | undefined;
} {
  const kindValue = record.principal_kind ?? record.principalKind;
  const serviceRoleValue = record.service_roles ?? record.serviceRoles;
  return {
    roles: record.roles === undefined ? undefined : roles(record.roles),
    sites: siteScope(record.sites),
    principalKind: kindValue === undefined ? undefined : parsePrincipalKind(kindValue),
    serviceRoles: serviceRoleValue === undefined ? undefined : serviceRolesFromUnknown(serviceRoleValue)
  };
}

interface ServicePrincipalOverride {
  readonly principalKind: "service";
  readonly serviceRoles: readonly ServiceRole[];
}

/**
 * Parse the actor-keyed service-principal override map (no token material), e.g.
 * {"verifier_control_plane_api_key":{"principal_kind":"service","service_roles":["decision_ingest"]}}.
 * Used to reclassify a bare-string operator-tokens entry (whose value ECS field-
 * selects directly as the bearer, so it cannot itself become a JSON object) into
 * a scoped service principal.
 */
function parseServicePrincipalOverrides(raw: string | undefined): ReadonlyMap<string, ServicePrincipalOverride> {
  if (raw === undefined || raw.trim().length === 0) {
    return new Map();
  }
  const parsed = JSON.parse(raw) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("operator service-principal overrides must be a JSON object");
  }
  const overrides = new Map<string, ServicePrincipalOverride>();
  for (const [actor, value] of Object.entries(parsed as Readonly<Record<string, unknown>>)) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`service-principal override for ${actor} must be an object`);
    }
    const record = value as Readonly<Record<string, unknown>>;
    if (parsePrincipalKind(record.principal_kind ?? record.principalKind) !== "service") {
      throw new Error(`service-principal override for ${actor} must set principal_kind "service"`);
    }
    const serviceRoles = serviceRolesFromUnknown(record.service_roles ?? record.serviceRoles);
    if (serviceRoles.length === 0) {
      throw new Error(`service-principal override for ${actor} must list at least one service role`);
    }
    overrides.set(actorId(actor), { principalKind: "service", serviceRoles });
  }
  return overrides;
}

/**
 * Apply service-principal overrides to LEGACY entries only (no explicit
 * principalKind/roles/serviceRoles). Rejects overrides that reference an unknown
 * actor (stale key) or that collide with an entry's explicit metadata (ambiguous
 * dual source). Non-overridden entries pass through unchanged.
 */
function applyServicePrincipalOverrides(
  entries: readonly OperatorAuthTokenEntry[],
  raw: string | undefined
): readonly OperatorAuthTokenEntry[] {
  const overrides = parseServicePrincipalOverrides(raw);
  if (overrides.size === 0) {
    return entries;
  }
  const actors = new Set(entries.map((entry) => actorId(entry.actorId)));
  for (const actor of overrides.keys()) {
    if (!actors.has(actor)) {
      throw new Error(`service-principal override references unknown actor: ${actor}`);
    }
  }
  return entries.map((entry) => {
    const override = overrides.get(actorId(entry.actorId));
    if (override === undefined) {
      return entry;
    }
    if (entry.principalKind !== undefined || entry.roles !== undefined || entry.sites !== undefined || entry.serviceRoles !== undefined) {
      throw new Error(`service-principal override conflicts with explicit metadata for actor: ${entry.actorId}`);
    }
    return { ...entry, principalKind: override.principalKind, serviceRoles: override.serviceRoles };
  });
}

function parseEnvEntries(raw: string | undefined): readonly OperatorAuthTokenEntry[] {
  if (raw === undefined || raw.trim().length === 0) {
    return [];
  }
  const parsed = JSON.parse(raw) as unknown;
  if (Array.isArray(parsed)) {
    return parsed.map((entry) => {
      if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
        throw new Error("operator token registry array entries must be objects");
      }
      const record = entry as Readonly<Record<string, unknown>>;
      return {
        actorId: actorId(record.actor_id ?? record.actorId),
        token: token(record.token),
        ...parseEntryAuthority(record)
      };
    });
  }
  if (parsed !== null && typeof parsed === "object") {
    return Object.entries(parsed as Readonly<Record<string, unknown>>).map(([actor, value]) => {
      if (typeof value === "string") {
        // Bare-string form carries no explicit authority metadata, so it stays
        // reclassifiable by a service-principal override; the constructor defaults
        // it to an operator with DEFAULT_ROLES when not overridden.
        return { actorId: actorId(actor), token: token(value) };
      }
      if (value !== null && typeof value === "object" && !Array.isArray(value)) {
        const record = value as Readonly<Record<string, unknown>>;
        return {
          actorId: actorId(actor),
          token: token(record.token),
          ...parseEntryAuthority(record)
        };
      }
      throw new Error("operator token registry values must be strings or objects");
    });
  }
  throw new Error("operator token registry must be a JSON object or array");
}

function normalizeEntries(options: RegisterOperatorAuthOptions): readonly OperatorAuthTokenEntry[] {
  const explicit = options.entries ?? [];
  const merged = [...explicit, ...parseEnvEntries(options.env)];
  return applyServicePrincipalOverrides(merged, options.servicePrincipalOverrides);
}

export class OperatorTokenRegistry {
  readonly #entries: readonly HashedOperatorTokenEntry[];

  constructor(entries: readonly OperatorAuthTokenEntry[]) {
    const seenDigests = new Set<string>();
    this.#entries = entries.map((entry) => {
      const digest = sha256(token(entry.token));
      const digestHex = digest.toString("hex");
      if (seenDigests.has(digestHex)) {
        throw new Error("operator token registry contains duplicate token material");
      }
      seenDigests.add(digestHex);
      const kind = parsePrincipalKind(entry.principalKind);
      const entrySites = siteScope(entry.sites);
      const entryServiceRoles = normalizeServiceRoles(entry.serviceRoles);
      const entryOperatorRoles =
        entry.roles !== undefined ? roles(entry.roles) : kind === "operator" ? DEFAULT_ROLES : [];
      assertConsistentPrincipal(kind, entryOperatorRoles, entryServiceRoles);
      if (kind === "service" && entrySites !== undefined) {
        throw new Error("service principal must not carry operator site scopes");
      }
      return {
        tokenSha256: digest,
        context: {
          actorId: actorId(entry.actorId),
          roles: entryOperatorRoles,
          ...(entrySites === undefined ? {} : { sites: entrySites }),
          principalKind: kind,
          serviceRoles: entryServiceRoles
        }
      };
    });
  }

  get configured(): boolean {
    return this.#entries.length > 0;
  }

  authenticate(candidateToken: string): OperatorAuthContext | undefined {
    const candidate = sha256(candidateToken);
    for (const entry of this.#entries) {
      if (timingSafeEqual(candidate, entry.tokenSha256)) {
        return entry.context;
      }
    }
    return undefined;
  }
}

export function createOperatorTokenRegistry(options: RegisterOperatorAuthOptions = {}): OperatorTokenRegistry {
  return new OperatorTokenRegistry(normalizeEntries(options));
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function bearerToken(value: string | string[] | undefined): string | undefined {
  const header = firstHeader(value);
  if (header === undefined) {
    return undefined;
  }
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1]?.trim();
}

function explicitOperatorToken(value: string | string[] | undefined): string | undefined {
  const header = firstHeader(value);
  return header === undefined || header.trim().length === 0 ? undefined : header.trim();
}

function extractOperatorToken(request: FastifyRequest): string | undefined {
  return (
    bearerToken(request.headers.authorization) ??
    explicitOperatorToken(request.headers["x-aidenid-operator-token"] as string | string[] | undefined)
  );
}

export async function registerOperatorAuthPlugin(app: FastifyInstance, options: RegisterOperatorAuthOptions = {}): Promise<void> {
  const registry = createOperatorTokenRegistry(options);
  app.decorateRequest("operatorAuth");
  app.decorateRequest("operatorAuthFailure");
  app.addHook("onRequest", (request, _reply, done) => {
    request.operatorAuth = undefined;
    request.operatorAuthFailure = undefined;
    if (!registry.configured) {
      request.operatorAuthFailure = { statusCode: 503, error: "operator_auth_not_configured" };
      done();
      return;
    }
    const candidateToken = extractOperatorToken(request);
    if (candidateToken === undefined) {
      request.operatorAuthFailure = { statusCode: 401, error: "operator_auth_required" };
      done();
      return;
    }
    const context = registry.authenticate(candidateToken);
    if (context === undefined) {
      request.operatorAuthFailure = { statusCode: 401, error: "invalid_operator_token" };
      done();
      return;
    }
    request.operatorAuth = context;
    done();
  });
}

/**
 * Handler-level ANY-OF check for a route the manifest classifies as reachable by
 * EITHER a service principal or an operator, e.g. GET /v1/decisions/:id/await
 * (`service:decision_status` for the verifier, `operator:decision_search` for a
 * human/dashboard caller).
 *
 * This exists because requireOperatorRole deliberately rejects every service
 * principal, so using it on an any-of route silently strips the service half of
 * the policy: correct today only because the live verifier credential is still an
 * operator, and broken the moment that credential is re-scoped to the service
 * principal the migration requires. Handler checks on any-of routes must express
 * the same policy the guard does, or the two enforcing surfaces disagree.
 */
export function requireOperatorOrServiceRole(
  request: FastifyRequest,
  reply: FastifyReply,
  operatorRole: OperatorRole,
  serviceRole: ServiceRole
): OperatorAuthContext | undefined {
  const context = request.operatorAuth;
  if (context === undefined) {
    const failure = request.operatorAuthFailure ?? { statusCode: 401, error: "operator_auth_required" };
    reply.code(failure.statusCode).send({ error: failure.error });
    return undefined;
  }
  if ((context.principalKind ?? "operator") === "service") {
    // Service principals are authorized ONLY by their explicit service roles; they
    // never inherit operator authority (no admin escape hatch here on purpose).
    if ((context.serviceRoles ?? []).includes(serviceRole)) {
      return context;
    }
    reply.code(403).send({ error: "operator_forbidden", required_role: operatorRole });
    return undefined;
  }
  if (context.roles.includes("admin") || context.roles.includes(operatorRole)) {
    return context;
  }
  reply.code(403).send({ error: "operator_forbidden", required_role: operatorRole });
  return undefined;
}

export function requireOperatorRole(
  request: FastifyRequest,
  reply: FastifyReply,
  requiredRole: OperatorRole
): OperatorAuthContext | undefined {
  const context = request.operatorAuth;
  if (context === undefined) {
    const failure = request.operatorAuthFailure ?? { statusCode: 401, error: "operator_auth_required" };
    reply.code(failure.statusCode).send({ error: failure.error });
    return undefined;
  }
  if ((context.principalKind ?? "operator") !== "operator") {
    // A service principal must never satisfy an operator role, even if it somehow
    // carries one. Mirrors the deny-by-default guard so every enforcing surface agrees.
    reply.code(403).send({ error: "operator_forbidden", required_role: requiredRole });
    return undefined;
  }
  if (!context.roles.includes("admin") && !context.roles.includes(requiredRole)) {
    reply.code(403).send({ error: "operator_forbidden", required_role: requiredRole });
    return undefined;
  }
  return context;
}

/** Site-scope check applied after the route has resolved the authoritative site ID. */
export function operatorCanAccessSite(context: OperatorAuthContext, siteId: string): boolean {
  return context.sites === undefined || context.sites.includes(siteId);
}
