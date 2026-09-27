"use client";

export default function DashboardError({
  error,
  reset,
}: {
  readonly error: Error & { readonly digest?: string };
  readonly reset: () => void;
}) {
  return (
    <main className="dashboard-shell">
      <section className="panel dashboard-error-panel" role="alert">
        <p className="eyebrow">Dashboard error</p>
        <h1>Live dashboard unavailable</h1>
        <p>
          The live evidence view could not render. Retry the request or use the
          dashboard status endpoint while the control plane recovers.
        </p>
        {error.digest === undefined ? null : (
          <p className="mono">digest: {error.digest}</p>
        )}
        <button className="action-button primary" type="button" onClick={reset}>
          Retry
        </button>
      </section>
    </main>
  );
}
