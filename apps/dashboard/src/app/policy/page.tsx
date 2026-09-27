import { PolicyDiffPreview } from "../../components/PolicyDiffPreview.js";
import { samplePolicyYaml } from "../../dashboardData.js";

export default function PolicyPage() {
  return (
    <main className="dashboard-shell policy-page">
      <header className="topbar">
        <div>
          <p className="eyebrow">AIdenID</p>
          <h1>Policy Preview</h1>
        </div>
        <a className="text-link-button" href="/">
          Live dashboard
        </a>
      </header>
      <PolicyDiffPreview currentPolicyYaml={samplePolicyYaml} />
    </main>
  );
}
