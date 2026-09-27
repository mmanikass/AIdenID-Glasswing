import { CascadeTelemetryPanel } from "../components/CascadeTelemetryPanel.js";
import { LiveStream } from "../components/LiveStream.js";
import { PersonaAuditPanel } from "../components/PersonaAuditPanel.js";
import { PolicyCopilotPanel } from "../components/PolicyCopilotPanel.js";
import { PolicyEditor } from "../components/PolicyEditor.js";
import { PriceRequiredBillingPanel } from "../components/PriceRequiredBillingPanel.js";
import { RevocationCenter } from "../components/RevocationCenter.js";
import { RouteAnalytics } from "../components/RouteAnalytics.js";
import { UsageMeter } from "../components/UsageMeter.js";
import {
  sampleDecisionEvents,
  sampleCascadeTelemetry,
  samplePersonaAuditIncidents,
  samplePolicyCopilotSuggestions,
  samplePolicyYaml,
  sampleRevocations,
} from "../dashboardData.js";
import { fetchInitialDashboardDecisionEvents } from "../dashboardInitialEvents.js";
import {
  priceRequiredBillingFromEvents,
  routeMetricsFromEvents,
  type CascadeTelemetrySummary,
} from "../dashboardModel.js";
import {
  dashboardRuntimeStatusFromEnv,
  type DashboardRuntimeMode,
} from "../dashboardStatus.js";

export const dynamic = "force-dynamic";

function runtimeLabel(mode: DashboardRuntimeMode): string {
  if (mode === "live_control_plane") {
    return "Live control plane";
  }
  if (mode === "live_control_plane_required") {
    return "Live required";
  }
  return "Seeded demo";
}

function dataProvenanceMessage(
  fallbackDataEnabled: boolean,
  mode: DashboardRuntimeMode,
): string {
  if (fallbackDataEnabled) {
    return "Seeded sample data. Use for UI walkthroughs only, not live traffic proof.";
  }
  if (mode === "live_control_plane_required") {
    return "Live evidence mode is required, but no control plane is configured. Seeded decision samples are disabled.";
  }
  return "Live evidence mode. Seeded decision samples are disabled.";
}

const emptyCascadeTelemetry = {
  generatedAt: "1970-01-01T00:00:00.000Z",
  decisions: 0,
  concurrency: 0,
  seed: 0,
  mode: "live_control_plane_waiting",
  shortCircuiting: false,
  sloBudgetMs: 200,
  sloStatus: "within_budget",
  overall: {
    count: 0,
    minMs: 0,
    avgMs: 0,
    p50Ms: 0,
    p95Ms: 0,
    p99Ms: 0,
    maxMs: 0,
  },
  layers: [],
  slowestLayer: undefined,
} satisfies CascadeTelemetrySummary;

export default async function DashboardPage() {
  const runtimeStatus = dashboardRuntimeStatusFromEnv(process.env);
  const initialEvents = runtimeStatus.fallbackDataEnabled
    ? sampleDecisionEvents
    : await fetchInitialDashboardDecisionEvents(process.env);
  const metrics = routeMetricsFromEvents(initialEvents);
  const priceRequiredBilling =
    priceRequiredBillingFromEvents(initialEvents);
  const decisions = initialEvents.length;
  const p95LatencyMs =
    initialEvents.length === 0
      ? 0
      : Math.max(...initialEvents.map((event) => event.latencyMs));
  const cascadeTelemetry = runtimeStatus.fallbackDataEnabled
    ? sampleCascadeTelemetry
    : emptyCascadeTelemetry;
  const revocations = runtimeStatus.fallbackDataEnabled ? sampleRevocations : [];
  const personaAuditIncidents = runtimeStatus.fallbackDataEnabled
    ? samplePersonaAuditIncidents
    : [];
  const policyCopilotSuggestions = runtimeStatus.fallbackDataEnabled
    ? samplePolicyCopilotSuggestions
    : [];

  return (
    <main className="dashboard-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">AIdenID</p>
          <h1>Clearance Dashboard</h1>
          <p className={`runtime-pill runtime-${runtimeStatus.mode}`}>
            {runtimeLabel(runtimeStatus.mode)}
          </p>
        </div>
        <UsageMeter decisions={decisions} p95LatencyMs={p95LatencyMs} />
      </header>
      <div
        className={`data-provenance-banner data-provenance-${runtimeStatus.mode}`}
      >
        {dataProvenanceMessage(
          runtimeStatus.fallbackDataEnabled,
          runtimeStatus.mode,
        )}
      </div>
      <div className="dashboard-grid">
        <LiveStream events={initialEvents} />
        <div className="side-stack">
          <CascadeTelemetryPanel telemetry={cascadeTelemetry} />
          <RouteAnalytics metrics={metrics} />
          <PriceRequiredBillingPanel rows={priceRequiredBilling} />
          <RevocationCenter revocations={revocations} />
          <PersonaAuditPanel incidents={personaAuditIncidents} />
        </div>
        <PolicyEditor policyText={samplePolicyYaml} />
        <PolicyCopilotPanel suggestions={policyCopilotSuggestions} />
      </div>
    </main>
  );
}
