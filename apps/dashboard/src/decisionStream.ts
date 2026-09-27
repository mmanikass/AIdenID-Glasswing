export interface DecisionStreamProxyRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
}

export interface DecisionStreamProxyOptions {
  readonly requestUrl: string;
  readonly controlPlaneUrl?: string | undefined;
  readonly operatorToken?: string | undefined;
  readonly serverSiteId?: string | undefined;
  readonly lastEventId?: string | null | undefined;
}

export interface DecisionSearchProxyRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
}

export interface DecisionSearchProxyOptions {
  readonly requestUrl: string;
  readonly controlPlaneUrl?: string | undefined;
  readonly operatorToken?: string | undefined;
}

export interface DecisionOperatorActionProxyRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export interface DecisionOperatorActionProxyOptions {
  readonly controlPlaneUrl?: string | undefined;
  readonly operatorToken?: string | undefined;
  readonly decisionId: string;
  readonly operatorAction: string;
  readonly operatorReason?: string | undefined;
}

function controlPlaneBaseUrl(controlPlaneUrl: string | undefined): string | undefined {
  if (controlPlaneUrl === undefined || controlPlaneUrl.trim().length === 0) {
    return undefined;
  }
  return controlPlaneUrl.endsWith("/") ? controlPlaneUrl : `${controlPlaneUrl}/`;
}

export function buildDecisionStreamProxyRequest(options: DecisionStreamProxyOptions): DecisionStreamProxyRequest | undefined {
  const base = controlPlaneBaseUrl(options.controlPlaneUrl);
  if (base === undefined) {
    return undefined;
  }

  const upstream = new URL("v1/decisions/stream", base);
  const incoming = new URL(options.requestUrl);
  incoming.searchParams.forEach((value, key) => {
    // The site scope is server-owned: never forward a browser-supplied site_id.
    if (key === "site_id") {
      return;
    }
    upstream.searchParams.append(key, value);
  });
  if (options.serverSiteId !== undefined && options.serverSiteId.trim().length > 0) {
    upstream.searchParams.set("site_id", options.serverSiteId);
  }

  return {
    url: upstream.toString(),
    headers: {
      Accept: "text/event-stream",
      ...(options.lastEventId === undefined || options.lastEventId === null || options.lastEventId.trim().length === 0
        ? {}
        : { "Last-Event-ID": options.lastEventId }),
      ...(options.operatorToken === undefined || options.operatorToken.trim().length === 0
        ? {}
        : { Authorization: `Bearer ${options.operatorToken}` })
    }
  };
}

export function buildDecisionSearchProxyRequest(options: DecisionSearchProxyOptions): DecisionSearchProxyRequest | undefined {
  const base = controlPlaneBaseUrl(options.controlPlaneUrl);
  if (base === undefined) {
    return undefined;
  }

  const upstream = new URL("v1/decisions/search", base);
  const incoming = new URL(options.requestUrl);
  incoming.searchParams.forEach((value, key) => {
    upstream.searchParams.append(key, value);
  });

  return {
    url: upstream.toString(),
    headers: {
      Accept: "application/json",
      ...(options.operatorToken === undefined || options.operatorToken.trim().length === 0
        ? {}
        : { Authorization: `Bearer ${options.operatorToken}` })
    }
  };
}

export function buildDecisionOperatorActionProxyRequest(
  options: DecisionOperatorActionProxyOptions
): DecisionOperatorActionProxyRequest | undefined {
  const base = controlPlaneBaseUrl(options.controlPlaneUrl);
  if (base === undefined) {
    return undefined;
  }

  return {
    url: new URL(`v1/decisions/${encodeURIComponent(options.decisionId)}/operator-action`, base).toString(),
    headers: {
      "Content-Type": "application/json",
      ...(options.operatorToken === undefined || options.operatorToken.trim().length === 0
        ? {}
        : { Authorization: `Bearer ${options.operatorToken}` })
    },
    body: JSON.stringify({
      operator_action: options.operatorAction,
      ...(options.operatorReason === undefined || options.operatorReason.trim().length === 0 ? {} : { operator_reason: options.operatorReason })
    })
  };
}
