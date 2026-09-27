import { Gauge, Layers3 } from "lucide-react";

import type { CascadeTelemetrySummary } from "../dashboardModel.js";

function formatMs(value: number): string {
  return `${Math.round(value)}ms`;
}

function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function CascadeTelemetryPanel({ telemetry }: { readonly telemetry: CascadeTelemetrySummary }) {
  const generatedDate = new Date(telemetry.generatedAt).toISOString().slice(0, 10);
  const budgetLabel = telemetry.sloStatus === "within_budget" ? "Within budget" : "Over budget";

  return (
    <section className="panel cascade-panel" aria-labelledby="cascade-telemetry-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Cascade</p>
          <h2 id="cascade-telemetry-heading">Telemetry</h2>
        </div>
        <Layers3 size={20} aria-hidden="true" />
      </div>
      <div className="cascade-summary-grid" aria-label="Cascade latency summary">
        <div>
          <span>p50</span>
          <strong>{formatMs(telemetry.overall.p50Ms)}</strong>
        </div>
        <div>
          <span>p95</span>
          <strong>{formatMs(telemetry.overall.p95Ms)}</strong>
        </div>
        <div>
          <span>p99</span>
          <strong>{formatMs(telemetry.overall.p99Ms)}</strong>
        </div>
      </div>
      <div className={`cascade-budget cascade-budget-${telemetry.sloStatus}`}>
        <div>
          <Gauge size={18} aria-hidden="true" />
          <strong>{budgetLabel}</strong>
        </div>
        <span>
          {formatMs(telemetry.overall.p95Ms)} p95 / {formatMs(telemetry.sloBudgetMs)} SLO
        </span>
      </div>
      <div className="cascade-meta">
        <span>{telemetry.decisions.toLocaleString("en-US")} decisions</span>
        <span>{telemetry.concurrency} concurrency</span>
        <span>{generatedDate}</span>
      </div>
      <div className="metric-list cascade-layer-list">
        {telemetry.layers.map((layer) => (
          <div className="cascade-layer-row" key={layer.name}>
            <div className="cascade-layer-main">
              <strong>{layer.label}</strong>
              <span>{layer.description}</span>
              <meter
                min={0}
                max={100}
                value={Math.min(100, Math.round(layer.p95Share * 100))}
                aria-label={`${layer.label} p95 contribution`}
              />
            </div>
            <div className="cascade-layer-stats">
              <span>{formatMs(layer.p95Ms)} p95</span>
              <span>{formatMs(layer.p99Ms)} p99</span>
              <span>{formatPercent(layer.p95Share)} share</span>
            </div>
          </div>
        ))}
      </div>
      {telemetry.slowestLayer === undefined ? null : (
        <p className="cascade-footnote">
          Slowest layer: <strong>{telemetry.slowestLayer.label}</strong> at {formatMs(telemetry.slowestLayer.p95Ms)} p95.
        </p>
      )}
    </section>
  );
}
