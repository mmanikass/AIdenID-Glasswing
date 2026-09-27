import { BarChart3 } from "lucide-react";

import type { RouteMetric } from "../dashboardModel.js";

export function RouteAnalytics({ metrics }: { readonly metrics: readonly RouteMetric[] }) {
  return (
    <section className="panel analytics-panel" aria-labelledby="route-analytics-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Routes</p>
          <h2 id="route-analytics-heading">Analytics</h2>
        </div>
        <BarChart3 size={20} aria-hidden="true" />
      </div>
      <div className="metric-list">
        {metrics.map((metric) => (
          <div className="metric-row" key={metric.routeTemplate}>
            <div>
              <strong className="mono">{metric.routeTemplate}</strong>
              <span>{metric.count} decisions</span>
            </div>
            <div>
              <span>{metric.p95LatencyMs.toFixed(1)}ms p95</span>
              <span>{(metric.denyRate * 100).toFixed(1)}% guarded</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
