import { ShieldCheck } from "lucide-react";

import type { CounterfactualImpact } from "../dashboardModel.js";

export function CounterfactualPanel({ impacts }: { readonly impacts: readonly CounterfactualImpact[] }) {
  return (
    <section className="panel counterfactual-panel" aria-labelledby="counterfactual-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Observe to enforce</p>
          <h2 id="counterfactual-heading">Counterfactual impact</h2>
        </div>
        <ShieldCheck size={20} aria-hidden="true" />
      </div>
      <div className="metric-list">
        {impacts.map((impact) => (
          <div className="metric-row" key={impact.routeTemplate}>
            <div>
              <strong className="mono">{impact.routeTemplate}</strong>
              <span>{impact.sampleCount} sampled decisions</span>
            </div>
            <div>
              <span>{impact.newlyBlockedIfEnforced} new blocks</span>
              <span>{(impact.blockRate * 100).toFixed(1)}% would guard</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
