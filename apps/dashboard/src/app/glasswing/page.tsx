import { GlasswingConsole } from "../../components/glasswing/GlasswingConsole.js";
import { dashboardRuntimeStatusFromEnv } from "../../dashboardStatus.js";

export const dynamic = "force-dynamic";

function provenance(): { readonly label: string; readonly className: string } {
  const status = dashboardRuntimeStatusFromEnv(process.env);
  if (status.mode === "live_control_plane") {
    return { label: "Live: every outcome below is recorded by the control plane and the protected site.", className: "data-provenance-banner data-provenance-live_control_plane" };
  }
  return { label: "No live control plane configured: this console cannot act. Start it with pnpm dev.", className: "data-provenance-banner data-provenance-sample_data" };
}

function siteOrigin(): string | undefined {
  const raw = process.env.AIDENID_PROTECTED_SITE_URL?.trim();
  if (!raw) return undefined;
  try {
    return new URL(raw).origin;
  } catch {
    return undefined;
  }
}

export default function GlasswingPage() {
  const banner = provenance();
  const siteUrl = siteOrigin();
  return (
    <main className="dashboard-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">AIdenID Glasswing</p>
          <h1>Operations console</h1>
          <p className="status-hint">
            Mint an agent, assign it scoped work, watch each signed request get one deterministic decision, escalate only ambiguous actions, revoke and see the next request refused.
            {siteUrl ? ` Protected site: ${siteUrl}.` : ""}
          </p>
        </div>
        <a className="text-link-button" href="/">
          Decision stream and receipts
        </a>
      </header>
      <p className={banner.className}>{banner.label}</p>
      <GlasswingConsole />
    </main>
  );
}
