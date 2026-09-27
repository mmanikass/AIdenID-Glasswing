import {
  authorizeDashboardOperatorHeaders,
  type DashboardOperatorAuthFailureCode
} from "./dashboardApi.js";
import {
  buildOperatorReputationListUrl,
  dashboardSiteId,
  isValidSiteId,
  type OperatorRegistryEnvironment,
  type OperatorReputationView
} from "./dashboardOperatorRegistry.js";

export interface OperatorRegistryServerEnvironment
  extends OperatorRegistryEnvironment {
  readonly AIDENID_OPERATOR_TOKEN?: string | undefined;
  readonly AIDENID_DASHBOARD_CONTROL_PLANE_TIMEOUT_MS?: string | undefined;
}

export type OperatorRegistryFetchOutcome =
  | {
      readonly status: "live";
      readonly operators: readonly OperatorReputationView[];
    }
  | {
      readonly status: "control_plane_unconfigured";
    }
  | {
      readonly status: "operator_token_missing";
    }
  | {
      readonly status: "fetch_failed";
      readonly httpStatus?: number;
      readonly message: string;
    }
  | {
      readonly status: DashboardOperatorAuthFailureCode;
    };

const DEFAULT_FETCH_TIMEOUT_MS = 5_000;
const MIN_FETCH_TIMEOUT_MS = 250;
const MAX_FETCH_TIMEOUT_MS = 30_000;

function timeoutMs(env: OperatorRegistryServerEnvironment): number {
  const raw = env.AIDENID_DASHBOARD_CONTROL_PLANE_TIMEOUT_MS;
  if (raw === undefined) {
    return DEFAULT_FETCH_TIMEOUT_MS;
  }
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    return DEFAULT_FETCH_TIMEOUT_MS;
  }
  return Math.min(MAX_FETCH_TIMEOUT_MS, Math.max(MIN_FETCH_TIMEOUT_MS, parsed));
}

interface ParsedListBody {
  readonly operators: readonly OperatorReputationView[];
}

function parseList(value: unknown): ParsedListBody | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const operatorsRaw = (value as { operators?: unknown }).operators;
  if (!Array.isArray(operatorsRaw)) {
    return undefined;
  }
  const operators = operatorsRaw.filter(
    (entry): entry is OperatorReputationView =>
      entry !== null &&
      typeof entry === "object" &&
      typeof (entry as OperatorReputationView).operator_actor_id === "string"
  );
  return { operators };
}

export interface FetchOperatorRegistryOptions {
  readonly fetchImpl?: typeof fetch | undefined;
}

export async function fetchOperatorRegistry(
  env: OperatorRegistryServerEnvironment,
  options: FetchOperatorRegistryOptions = {}
): Promise<OperatorRegistryFetchOutcome> {
  const controlPlaneUrl = env.AIDENID_CONTROL_PLANE_URL?.trim();
  if (controlPlaneUrl === undefined || controlPlaneUrl.length === 0) {
    return { status: "control_plane_unconfigured" };
  }
  const operatorToken = env.AIDENID_OPERATOR_TOKEN?.trim();
  if (operatorToken === undefined || operatorToken.length === 0) {
    return { status: "operator_token_missing" };
  }
  const siteId = dashboardSiteId(env);
  if (!isValidSiteId(siteId)) {
    return { status: "fetch_failed", message: "AIDENID_DASHBOARD_SITE_ID must match /^sit_[A-Za-z0-9_-]+$/" };
  }

  const targetUrl = buildOperatorReputationListUrl(controlPlaneUrl, siteId);
  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs(env));

  try {
    const response = await fetchImpl(targetUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${operatorToken}`
      },
      cache: "no-store",
      signal: controller.signal
    });
    if (!response.ok) {
      return {
        status: "fetch_failed",
        httpStatus: response.status,
        message: `control plane returned HTTP ${response.status}`
      };
    }
    const body = (await response.json()) as unknown;
    const parsed = parseList(body);
    if (parsed === undefined) {
      return { status: "fetch_failed", message: "control plane returned an unexpected payload shape" };
    }
    return { status: "live", operators: parsed.operators };
  } catch (error) {
    return {
      status: "fetch_failed",
      message: error instanceof Error ? error.message : "control plane request failed"
    };
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchAuthorizedOperatorRegistry(
  headers: Pick<Headers, "get">,
  env: OperatorRegistryServerEnvironment,
  options: FetchOperatorRegistryOptions = {}
): Promise<OperatorRegistryFetchOutcome> {
  const auth = authorizeDashboardOperatorHeaders(headers, env);
  if (!auth.ok) {
    return { status: auth.error };
  }
  return fetchOperatorRegistry(env, options);
}
