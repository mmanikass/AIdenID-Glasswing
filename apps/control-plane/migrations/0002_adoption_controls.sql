ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS recommended_decision text,
  ADD COLUMN IF NOT EXISTS latency_us integer,
  ADD COLUMN IF NOT EXISTS subject_handle text,
  ADD COLUMN IF NOT EXISTS suspicion_score double precision;

CREATE TABLE IF NOT EXISTS tenant_quotas (
  tenant_id text PRIMARY KEY,
  monthly_decision_limit integer NOT NULL,
  stored_decision_limit integer NOT NULL,
  target_limit integer NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS privacy_erasure_requests (
  id text PRIMARY KEY,
  site_id text NOT NULL,
  subject_handle text NOT NULL,
  reason text NOT NULL,
  actor_id text NOT NULL,
  erased_decision_count integer NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  url text NOT NULL,
  event_types jsonb NOT NULL,
  signing_secret_ref text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, url)
);

CREATE INDEX IF NOT EXISTS idx_decisions_subject_erase ON decisions(site_id, subject_handle) WHERE subject_handle IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_decisions_counterfactual ON decisions(site_id, route_template, recommended_decision, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_privacy_erasure_site_time ON privacy_erasure_requests(site_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_tenant ON webhook_endpoints(tenant_id, updated_at DESC);
