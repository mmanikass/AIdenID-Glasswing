import type { ActorClass } from "../dashboardModel.js";

const ACTOR_LABELS: Record<ActorClass, string> = {
  verified_agent: "verified_agent",
  signed_agent: "signed_agent",
  likely_human: "likely_human",
  suspicious_automation: "suspicious_automation",
  unknown: "unknown"
};

export function ActorBadge({ actorClass }: { readonly actorClass: ActorClass }) {
  return (
    <span className={`actor-badge actor-${actorClass}`}>
      <span aria-hidden="true" className="actor-dot" />
      {ACTOR_LABELS[actorClass]}
    </span>
  );
}
