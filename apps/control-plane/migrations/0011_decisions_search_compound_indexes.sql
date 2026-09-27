CREATE INDEX IF NOT EXISTS idx_decisions_decision_actor_search
  ON decisions(site_id, decision, actor_class, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_decisions_route_decision_actor_search
  ON decisions(site_id, route_template, decision, actor_class, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_decisions_issuer_decision_search
  ON decisions(site_id, issuer, decision, occurred_at DESC)
  WHERE issuer IS NOT NULL;
