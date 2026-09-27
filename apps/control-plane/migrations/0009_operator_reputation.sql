CREATE TABLE IF NOT EXISTS operator_reputation (
  id text PRIMARY KEY,
  site_id text NOT NULL,
  operator_actor_id text NOT NULL,
  display_name text,
  trust_tier text NOT NULL CHECK (trust_tier IN ('unknown', 'trusted', 'restricted')),
  status text NOT NULL CHECK (status IN ('active', 'watchlist', 'suspended')),
  reputation_score integer NOT NULL CHECK (reputation_score >= 0 AND reputation_score <= 100),
  notes text,
  last_reviewed_at timestamptz,
  updated_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (site_id, operator_actor_id)
);

CREATE INDEX IF NOT EXISTS idx_operator_reputation_site_status
  ON operator_reputation(site_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_operator_reputation_site_trust
  ON operator_reputation(site_id, trust_tier, updated_at DESC);
