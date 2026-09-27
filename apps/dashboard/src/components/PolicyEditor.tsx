import { CheckCircle2, FileDiff, Save } from "lucide-react";

import { validatePolicyText } from "../dashboardModel.js";

export function PolicyEditor({ policyText }: { readonly policyText: string }) {
  const validation = validatePolicyText(policyText);

  return (
    <section className="panel policy-panel" aria-labelledby="policy-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Policy</p>
          <h2 id="policy-heading">Editor</h2>
        </div>
        <div className="button-row">
          <button className="icon-button" type="button" aria-label="Preview diff">
            <FileDiff size={18} />
          </button>
          <button className="icon-button primary" type="button" aria-label="Save policy">
            <Save size={18} />
          </button>
        </div>
      </div>
      <textarea aria-label="Policy YAML" spellCheck={false} defaultValue={policyText} />
      <div className={validation.ok ? "validation ok" : "validation error"}>
        <CheckCircle2 size={16} />
        <span>{validation.ok ? `${validation.routeCount} routes valid` : validation.errors[0]}</span>
      </div>
    </section>
  );
}
