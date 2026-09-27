CREATE INDEX IF NOT EXISTS idx_decisions_decision_search
  ON decisions(site_id, decision, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_decisions_issuer_search
  ON decisions(site_id, issuer, occurred_at DESC)
  WHERE issuer IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_decisions_actor_class_search
  ON decisions(site_id, actor_class, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_decisions_route_search
  ON decisions(site_id, route_template, occurred_at DESC);
