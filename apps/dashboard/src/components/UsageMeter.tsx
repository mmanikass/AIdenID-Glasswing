import { Activity, Gauge } from "lucide-react";

export function UsageMeter({ decisions, p95LatencyMs }: { readonly decisions: number; readonly p95LatencyMs: number }) {
  return (
    <section className="usage-strip" aria-label="Usage meter">
      <div>
        <Activity size={18} aria-hidden="true" />
        <span>{decisions.toLocaleString("en-US")} decisions</span>
      </div>
      <div>
        <Gauge size={18} aria-hidden="true" />
        <span>{p95LatencyMs.toFixed(1)}ms p95</span>
      </div>
    </section>
  );
}
