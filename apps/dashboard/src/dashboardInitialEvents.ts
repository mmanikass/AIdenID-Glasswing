import {
  dashboardControlPlaneTimeoutMs,
  fetchDashboardControlPlaneWithTimeout,
  type DashboardApiEnvironment,
} from "./dashboardApi.js";
import {
  dashboardDecisionEventFromPayload,
  type DashboardDecisionEvent,
} from "./dashboardLiveModel.js";
import { buildDecisionSearchProxyRequest } from "./decisionStream.js";

export interface DashboardInitialEventsEnvironment
  extends DashboardApiEnvironment {
  readonly AIDENID_CONTROL_PLANE_API_KEY?: string | undefined;
  readonly AIDENID_CONTROL_PLANE_URL?: string | undefined;
  readonly AIDENID_DASHBOARD_LIVE_INITIAL_LIMIT?: string | undefined;
}

const DEFAULT_INITIAL_EVENT_LIMIT = 50;
const MIN_INITIAL_EVENT_LIMIT = 1;
const MAX_INITIAL_EVENT_LIMIT = 250;

function liveInitialLimit(
  env: DashboardInitialEventsEnvironment,
): number {
  const raw = env.AIDENID_DASHBOARD_LIVE_INITIAL_LIMIT;
  if (raw === undefined || raw.trim().length === 0) {
    return DEFAULT_INITIAL_EVENT_LIMIT;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_INITIAL_EVENT_LIMIT;
  }
  return Math.min(
    MAX_INITIAL_EVENT_LIMIT,
    Math.max(MIN_INITIAL_EVENT_LIMIT, Math.trunc(parsed)),
  );
}

function decisionPayloadsFromBody(body: unknown): readonly unknown[] {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return [];
  }
  const source = body as Readonly<Record<string, unknown>>;
  return Array.isArray(source.decisions) ? source.decisions : [];
}

export async function fetchInitialDashboardDecisionEvents(
  env: DashboardInitialEventsEnvironment,
): Promise<readonly DashboardDecisionEvent[]> {
  const proxy = buildDecisionSearchProxyRequest({
    requestUrl: `https://dashboard.aidenid.local/api/decisions/search?limit=${liveInitialLimit(env)}`,
    controlPlaneUrl: env.AIDENID_CONTROL_PLANE_URL,
    operatorToken: env.AIDENID_OPERATOR_TOKEN ?? env.AIDENID_CONTROL_PLANE_API_KEY,
  });
  if (proxy === undefined) {
    return [];
  }

  try {
    const response = await fetchDashboardControlPlaneWithTimeout(proxy.url, {
      headers: proxy.headers,
      cache: "no-store",
      timeoutMs: dashboardControlPlaneTimeoutMs(env),
    });
    if (!response.ok) {
      return [];
    }
    const body = (await response.json()) as unknown;
    return decisionPayloadsFromBody(body)
      .map((payload) => dashboardDecisionEventFromPayload(payload))
      .filter((event): event is DashboardDecisionEvent => event !== undefined);
  } catch {
    return [];
  }
}
