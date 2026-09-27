import { CheckCircle2, FileDiff, ShieldCheck } from "lucide-react";
import type { PolicyCopilotSuggestion } from "@aidenid/policy-engine";

export function PolicyCopilotPanel({ suggestions }: { readonly suggestions: readonly PolicyCopilotSuggestion[] }) {
  const suggestion = suggestions[0];

  return (
    <section className="panel copilot-panel" aria-labelledby="policy-copilot-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Policy Copilot</p>
          <h2 id="policy-copilot-heading">Review Queue</h2>
        </div>
        <div className="button-row">
          <button className="icon-button" type="button" aria-label="Preview proposed policy diff">
            <FileDiff size={18} />
          </button>
          <button className="icon-button primary" type="button" aria-label="Approve policy suggestion">
            <CheckCircle2 size={18} />
          </button>
        </div>
      </div>
      {suggestion === undefined ? (
        <div className="empty-state">No pending suggestions</div>
      ) : (
        <div className="copilot-card">
          <div className="copilot-title">
            <ShieldCheck size={18} />
            <div>
              <span>{suggestion.label}</span>
              <strong>{suggestion.approvalStatus}</strong>
            </div>
          </div>
          <p>{suggestion.rationale}</p>
          <dl className="copilot-meta">
            <div>
              <dt>Model</dt>
              <dd>{suggestion.metadata.model}</dd>
            </div>
            <div>
              <dt>Tool</dt>
              <dd>{suggestion.metadata.tool}</dd>
            </div>
            <div>
              <dt>Prompt</dt>
              <dd>{suggestion.metadata.promptDigestSha256.slice(0, 12)}</dd>
            </div>
            <div>
              <dt>Diff</dt>
              <dd>{suggestion.outputDiff.operations.length} ops</dd>
            </div>
          </dl>
        </div>
      )}
    </section>
  );
}
