"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Ban,
  Check,
  Clock,
  DollarSign,
  Gauge,
  LockKeyhole,
  Search,
  Shield,
  SlidersHorizontal,
  type LucideIcon,
} from "lucide-react";

import {
  dashboardDecisionEventFromPayload,
  dashboardStreamErrorFromPayload,
  filterDecisionEvents,
  providerReputationFromEvents,
  trafficClassificationFromEvents,
  type DashboardDecisionEvent,
  type OperatorAction,
  type ProviderReputationSummary,
} from "../dashboardLiveModel.js";
import {
  LiveOperatorActionCircuitBreaker,
  fetchLiveOperatorAction,
} from "../dashboardLiveActions.js";
import { ActorBadge } from "./ActorBadge.js";
import { DecisionPill } from "./DecisionPill.js";

type EventWithData = Event & { readonly data?: unknown };
type InputWithValue = { readonly value: string };

const OPERATOR_ACTIONS: readonly {
  readonly action: OperatorAction;
  readonly label: string;
  readonly Icon: LucideIcon;
}[] = [
  { action: "allow", label: "Allow", Icon: Check },
  { action: "throttle", label: "Throttle", Icon: Gauge },
  { action: "queue", label: "Queue", Icon: Clock },
  { action: "sandbox", label: "Sandbox", Icon: Shield },
  { action: "deny", label: "Deny", Icon: Ban },
  { action: "quarantine", label: "Quarantine", Icon: LockKeyhole },
  { action: "price_required", label: "Price", Icon: DollarSign },
];

function decisionPayloadFromActionResponse(payload: unknown): unknown {
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    return undefined;
  }
  const source = payload as Readonly<Record<string, unknown>>;
  return source.decision ?? payload;
}

function operatorActionEndpoint(decisionId: string): string {
  return `/api/decisions/${encodeURIComponent(decisionId)}/operator-action`;
}

function cascadeLayerLabel(layer: string): string {
  return layer
    .split("_")
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join(" ");
}

export function LiveStream({
  events,
}: {
  readonly events: readonly DashboardDecisionEvent[];
}) {
  const [liveEvents, setLiveEvents] =
    useState<readonly DashboardDecisionEvent[]>(events);
  const [selectedId, setSelectedId] = useState<string | undefined>(
    events[0]?.id,
  );
  const [query, setQuery] = useState("");
  const [streamStatus, setStreamStatus] = useState<
    "connecting" | "live" | "reconnecting"
  >("connecting");
  const [streamError, setStreamError] = useState<string | undefined>();
  const [pendingAction, setPendingAction] = useState<
    OperatorAction | undefined
  >();
  const [actionError, setActionError] = useState<string | undefined>();
  const operatorActionCircuit = useRef(new LiveOperatorActionCircuitBreaker());
  const filteredEvents = useMemo(
    () => filterDecisionEvents(liveEvents, query),
    [liveEvents, query],
  );
  const selected =
    liveEvents.find((event) => event.id === selectedId) ??
    filteredEvents[0] ??
    liveEvents[0];
  const streamNotice =
    streamError ??
    (streamStatus === "connecting"
      ? "Connecting to live decision stream..."
      : streamStatus === "reconnecting"
        ? "Decision stream reconnecting..."
        : undefined);
  const showLlmBrand = useMemo(
    () => filteredEvents.some((event) => event.llmBrand !== undefined),
    [filteredEvents],
  );
  const showPurpose = useMemo(
    () => filteredEvents.some((event) => event.purpose !== undefined),
    [filteredEvents],
  );
  const trafficClassification = useMemo(
    () => trafficClassificationFromEvents(liveEvents),
    [liveEvents],
  );
  const providerReputation = useMemo(
    () => providerReputationFromEvents(liveEvents),
    [liveEvents],
  );

  const reviewProvider = (provider: ProviderReputationSummary) => {
    setQuery(provider.providerId);
    if (provider.latestDecisionId !== undefined) {
      setSelectedId(provider.latestDecisionId);
    }
  };

  const applyOperatorAction = async (action: OperatorAction) => {
    if (selected === undefined) {
      return;
    }
    setPendingAction(action);
    setActionError(undefined);
    const updatedAt = new Date().toISOString();
    try {
      const response = await fetchLiveOperatorAction(
        operatorActionEndpoint(selected.id),
        {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            operator_action: action,
            operator_reason: "live_demo_override",
          }),
        },
        { circuitBreaker: operatorActionCircuit.current },
      );
      if (!response.ok) {
        throw new Error(`operator action failed with HTTP ${response.status}`);
      }
      const payload = (await response.json()) as unknown;
      const parsed = dashboardDecisionEventFromPayload(
        decisionPayloadFromActionResponse(payload),
      );
      setLiveEvents((current) =>
        parsed === undefined
          ? current.map((event) =>
              event.id === selected.id
                ? {
                    ...event,
                    operatorAction: action,
                    operatorActionReason: "live_demo_override",
                    operatorActionAt: updatedAt,
                  }
                : event,
            )
          : [
              parsed,
              ...current.filter((event) => event.id !== parsed.id),
            ].slice(0, 100),
      );
      setSelectedId(selected.id);
    } catch (error) {
      setActionError(
        error instanceof Error ? error.message : "operator action failed",
      );
    } finally {
      setPendingAction(undefined);
    }
  };

  useEffect(() => {
    const source = new EventSource("/api/decisions/stream");
    const handleEvent = (message: Event) => {
      let parsedPayload: unknown;
      const data = (message as EventWithData).data;
      try {
        parsedPayload = JSON.parse(
          typeof data === "string" ? data : "",
        ) as unknown;
      } catch {
        return;
      }
      const parsed = dashboardDecisionEventFromPayload(parsedPayload);
      if (parsed === undefined) {
        return;
      }
      setStreamError(undefined);
      setLiveEvents((current) =>
        [parsed, ...current.filter((event) => event.id !== parsed.id)].slice(
          0,
          100,
        ),
      );
      setSelectedId((current) => current ?? parsed.id);
    };
    const handleStreamError = (message: Event) => {
      let parsedPayload: unknown;
      const data = (message as EventWithData).data;
      try {
        parsedPayload = JSON.parse(
          typeof data === "string" ? data : "",
        ) as unknown;
      } catch {
        parsedPayload = undefined;
      }
      const parsed = dashboardStreamErrorFromPayload(parsedPayload);
      setStreamStatus("reconnecting");
      setStreamError(
        parsed === undefined
          ? "Decision stream unavailable."
          : `${parsed.error}${parsed.status === undefined ? "" : ` (${parsed.status})`}`,
      );
    };
    source.onopen = () => {
      setStreamStatus("live");
      setStreamError(undefined);
    };
    source.onerror = () => {
      setStreamStatus("reconnecting");
      setStreamError((current) => current ?? "Decision stream disconnected. Reconnecting...");
    };
    for (const eventName of [
      "message",
      "decision",
      "recorded",
      "pending",
      "resolved",
      "updated",
    ]) {
      source.addEventListener(eventName, handleEvent);
    }
    source.addEventListener("stream_error", handleStreamError);
    return () => {
      for (const eventName of [
        "message",
        "decision",
        "recorded",
        "pending",
        "resolved",
        "updated",
      ]) {
        source.removeEventListener(eventName, handleEvent);
      }
      source.removeEventListener("stream_error", handleStreamError);
      source.close();
    };
  }, []);

  return (
    <section className="panel live-panel" aria-labelledby="live-stream-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Decision stream</p>
          <h2 id="live-stream-heading">Live traffic</h2>
        </div>
        <div className="stream-tools">
          <span className={`stream-status ${streamStatus}`} role="status">
            {streamStatus}
          </span>
          <button
            className="icon-button"
            type="button"
            aria-label="Stream filters"
          >
            <SlidersHorizontal size={18} />
          </button>
        </div>
      </div>
      <label className="search-box">
        <Search size={16} />
        <input
          aria-label="Search traffic"
          placeholder="request, route, actor, decision"
          value={query}
          onChange={(event) =>
            setQuery((event.currentTarget as unknown as InputWithValue).value)
          }
        />
      </label>
      {streamNotice === undefined ? null : (
        <p
          className={streamError === undefined ? "stream-notice" : "stream-error"}
          role="status"
        >
          {streamNotice}
        </p>
      )}
      <div className="actor-mix-grid" aria-label="Traffic classification">
        {trafficClassification.map((bucket) => (
          <div
            className={`actor-mix-card actor-mix-${bucket.key}`}
            key={bucket.key}
          >
            <span>{bucket.label}</span>
            <strong>{bucket.count}</strong>
            <small>{bucket.percentage}%</small>
          </div>
        ))}
      </div>
      {providerReputation.length === 0 ? null : (
        <div className="provider-reputation-grid" aria-label="Provider reputation">
          {providerReputation.map((provider) => (
            <div
              className={`provider-reputation-card provider-reputation-${provider.risk}`}
              key={provider.providerId}
            >
              <div className="provider-reputation-heading">
                <span>{provider.displayName}</span>
                <strong>
                  {provider.latestScore === undefined
                    ? "n/a"
                    : provider.latestScore}
                </strong>
              </div>
              <div className="provider-reputation-meta">
                <span>{provider.eventCount} requests</span>
                <span>{provider.latestRouteTemplate ?? "no route"}</span>
              </div>
              <div className="provider-reputation-evidence">
                <span>{provider.latestStatus ?? "unknown"}</span>
                <span>{provider.latestReason ?? "no reputation evidence"}</span>
              </div>
              <div className="provider-reputation-action">
                <DecisionPill decision={provider.recommendedAction} />
                <button
                  className="provider-review-button"
                  type="button"
                  onClick={() => reviewProvider(provider)}
                >
                  <Search size={14} />
                  <span>Review</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      <div
        className="table-wrap"
        role="log"
        aria-live="polite"
        aria-relevant="additions text"
        aria-label="Live decision events"
      >
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Route</th>
              <th>Actor class</th>
              {showLlmBrand ? <th>LLM brand</th> : null}
              {showPurpose ? <th>Purpose</th> : null}
              <th>Decision</th>
              <th>Operator</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((event) => (
              <tr key={event.id}>
                <td>
                  <button
                    className="stream-row-button"
                    type="button"
                    onClick={() => setSelectedId(event.id)}
                  >
                    {new Date(event.occurredAt).toLocaleTimeString("en-US", {
                      hour12: false,
                    })}
                  </button>
                </td>
                <td className="mono">{event.routeTemplate}</td>
                <td>
                  <ActorBadge actorClass={event.actorClass} />
                </td>
                {showLlmBrand ? (
                  <td className="mono">{event.llmBrand ?? "none"}</td>
                ) : null}
                {showPurpose ? (
                  <td className="mono">{event.purpose ?? "none"}</td>
                ) : null}
                <td>
                  <DecisionPill decision={event.decision} />
                </td>
                <td>
                  {event.operatorAction === undefined ? (
                    "none"
                  ) : (
                    <DecisionPill decision={event.operatorAction} />
                  )}
                </td>
                <td>{event.latencyMs.toFixed(1)}ms</td>
              </tr>
            ))}
            {filteredEvents.length === 0 ? (
              <tr>
                <td
                  className="empty-table-cell"
                  colSpan={6 + (showLlmBrand ? 1 : 0) + (showPurpose ? 1 : 0)}
                >
                  Waiting for live control-plane decisions
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      {selected === undefined ? null : (
        <aside className="detail-drawer" aria-label="Actor detail">
          <div>
            <span className="drawer-label">Request</span>
            <strong>{selected.requestId}</strong>
          </div>
          <div>
            <span className="drawer-label">Reasons</span>
            <strong>
              {selected.reasonCodes.length === 0
                ? "none"
                : selected.reasonCodes.join(", ")}
            </strong>
          </div>
          <div>
            <span className="drawer-label">Method</span>
            <strong>{selected.method}</strong>
          </div>
          <div>
            <span className="drawer-label">Operator action</span>
            <strong>
              {selected.operatorAction === undefined
                ? "none"
                : selected.operatorAction}
            </strong>
          </div>
          <div>
            <span className="drawer-label">Operator effect</span>
            <strong>
              {selected.operatorActionEffectiveDecision ??
                selected.operatorAction ??
                "none"}
            </strong>
          </div>
          <div>
            <span className="drawer-label">Issuer</span>
            <strong>{selected.issuer ?? "unknown"}</strong>
          </div>
          {selected.llmBrand === undefined ? null : (
            <div>
              <span className="drawer-label">LLM brand</span>
              <strong>{selected.llmBrand}</strong>
            </div>
          )}
          {selected.purpose === undefined ? null : (
            <div>
              <span className="drawer-label">Purpose</span>
              <strong>{selected.purpose}</strong>
            </div>
          )}
          {selected.cascadeTrace === undefined ? null : (
            <div className="cascade-trace-panel">
              <span className="drawer-label">Cascade trace</span>
              <div className="cascade-trace-list">
                {selected.cascadeTrace.map((entry) => (
                  <div
                    className={`cascade-trace-row cascade-trace-${entry.status}`}
                    key={`${entry.ordinal}-${entry.layer}`}
                  >
                    <span className="cascade-trace-index">{entry.ordinal}</span>
                    <strong>{cascadeLayerLabel(entry.layer)}</strong>
                    <span className="cascade-trace-status">{entry.status}</span>
                    <span className="cascade-trace-reason">{entry.reason}</span>
                    <span className="cascade-trace-latency">
                      {(entry.latencyUs / 1_000).toFixed(2)}ms
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="operator-action-panel">
            <span className="drawer-label">Actions</span>
            <div
              className="operator-actions"
              role="group"
              aria-label="Operator actions"
            >
              {OPERATOR_ACTIONS.map(({ action, label, Icon }) => (
                <button
                  key={action}
                  className="operator-action-button"
                  type="button"
                  disabled={pendingAction !== undefined}
                  aria-label={`Set operator action to ${label}`}
                  onClick={() => void applyOperatorAction(action)}
                >
                  <Icon size={14} />
                  <span>{pendingAction === action ? "Saving" : label}</span>
                </button>
              ))}
            </div>
            {actionError === undefined ? null : (
              <strong className="operator-action-error">{actionError}</strong>
            )}
          </div>
        </aside>
      )}
    </section>
  );
}
