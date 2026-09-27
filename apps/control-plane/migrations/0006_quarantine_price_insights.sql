ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS issuer text,
  ADD COLUMN IF NOT EXISTS price_usd numeric,
  ADD COLUMN IF NOT EXISTS operator_action_effective_decision text,
  ADD COLUMN IF NOT EXISTS operator_action_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS operator_action_effects jsonb;

CREATE TABLE IF NOT EXISTS quarantine_pins (
  id text PRIMARY KEY,
  decision_id text NOT NULL UNIQUE REFERENCES decisions(id) ON DELETE CASCADE,
  site_id text NOT NULL,
  actor_class text NOT NULL,
  issuer text,
  subject_handle text,
  request_id text NOT NULL,
  operator_actor_id text NOT NULL,
  reason text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_decisions_price_required_issuer
  ON decisions(site_id, issuer, occurred_at DESC)
  WHERE decision = 'price_required' OR operator_action = 'price_required';

CREATE INDEX IF NOT EXISTS idx_quarantine_pins_site_expires
  ON quarantine_pins(site_id, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_quarantine_pins_subject_expires
  ON quarantine_pins(site_id, subject_handle, expires_at DESC)
  WHERE subject_handle IS NOT NULL;
