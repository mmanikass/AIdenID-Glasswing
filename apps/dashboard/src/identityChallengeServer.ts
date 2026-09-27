import {
  authorizeDashboardOperatorHeaders,
  type DashboardOperatorAuthFailureCode
} from "./dashboardApi.js";
import { dashboardSiteId, isValidSiteId, type OperatorRegistryEnvironment } from "./dashboardOperatorRegistry.js";
import {
  buildAgentIdentitySubmissionListUrl,
  parseAgentIdentitySubmissionList,
  type AgentIdentitySubmissionView
} from "./dashboardIdentityChallenges.js";

export interface IdentityChallengeServerEnvironment extends OperatorRegistryEnvironment {
  readonly AIDENID_OPERATOR_TOKEN?: string | undefined;
  readonly AIDENID_DASHBOARD_CONTROL_PLANE_TIMEOUT_MS?: string | undefined;
}

export type IdentityChallengeFetchOutcome =
  | {
      readonly status: "live";
      readonly submissions: readonly AgentIdentitySubmissionView[];
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

function timeoutMs(env: IdentityChallengeServerEnvironment): number {
  const raw = env.AIDENID_DASHBOARD_CONTROL_PLANE_TIMEOUT_MS;
  if (raw === undefined) {
    return DEFAULT_FETCH_TIMEOUT_MS;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isNaN(parsed) ? DEFAULT_FETCH_TIMEOUT_MS : Math.min(MAX_FETCH_TIMEOUT_MS, Math.max(MIN_FETCH_TIMEOUT_MS, parsed));
}

export interface FetchIdentityChallengesOptions {
  readonly fetchImpl?: typeof fetch | undefined;
}

export async function fetchIdentityChallengeSubmissions(
  env: IdentityChallengeServerEnvironment,
  options: FetchIdentityChallengesOptions = {}
): Promise<IdentityChallengeFetchOutcome> {
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

  const targetUrl = buildAgentIdentitySubmissionListUrl(controlPlaneUrl, siteId, {
    status: "pending_review",
    limit: 100
  });
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
    const submissions = parseAgentIdentitySubmissionList((await response.json()) as unknown);
    if (submissions === undefined) {
      return { status: "fetch_failed", message: "control plane returned an unexpected payload shape" };
    }
    return { status: "live", submissions };
  } catch (error) {
    return {
      status: "fetch_failed",
      message: error instanceof Error ? error.message : "control plane request failed"
    };
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchAuthorizedIdentityChallengeSubmissions(
  headers: Pick<Headers, "get">,
  env: IdentityChallengeServerEnvironment,
  options: FetchIdentityChallengesOptions = {}
): Promise<IdentityChallengeFetchOutcome> {
  const auth = authorizeDashboardOperatorHeaders(headers, env);
  if (!auth.ok) {
    return { status: auth.error };
  }
  return fetchIdentityChallengeSubmissions(env, options);
}
