import { ClipboardList, ExternalLink } from "lucide-react";

import type { PersonaAuditIncident } from "../dashboardModel.js";

export function PersonaAuditPanel({ incidents }: { readonly incidents: readonly PersonaAuditIncident[] }) {
  return (
    <section className="panel persona-panel" aria-labelledby="persona-audit-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Persona Audit</p>
          <h2 id="persona-audit-heading">Incidents</h2>
        </div>
        <button className="icon-button" type="button" aria-label="Open audit workspace">
          <ExternalLink size={18} />
        </button>
      </div>
      <div className="incident-list">
        {incidents.map((incident) => (
          <article className="incident-row" key={incident.id}>
            <div className="incident-title">
              <ClipboardList size={17} />
              <div>
                <strong>{incident.title}</strong>
                <span>{incident.triggerType}</span>
              </div>
            </div>
            <p>{incident.summary}</p>
            <div className="incident-meta">
              <span>{incident.severity}</span>
              <span>{incident.status}</span>
              <span>{incident.tool}</span>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
