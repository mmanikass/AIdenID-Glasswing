CREATE TABLE targets (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  site_id text NOT NULL UNIQUE,
  name text NOT NULL,
  origin text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE delegation_grants (
  id text PRIMARY KEY,
  target_id text NOT NULL REFERENCES targets(id),
  site_id text NOT NULL REFERENCES targets(site_id),
  subject text NOT NULL,
  chain_id text NOT NULL,
  resource text NOT NULL,
  permissions jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE issued_sessions (
  id text PRIMARY KEY,
  grant_id text NOT NULL REFERENCES delegation_grants(id),
  chain_id text NOT NULL,
  site_id text NOT NULL,
  token_hash_sha256 text NOT NULL,
  proof_jkt text NOT NULL,
  revocation_epoch integer NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE TABLE revocation_epochs (
  chain_id text PRIMARY KEY,
  epoch integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE revocations (
  id text PRIMARY KEY,
  chain_id text NOT NULL,
  epoch integer NOT NULL,
  reason text NOT NULL,
  actor_id text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE decisions (
  id text PRIMARY KEY,
  site_id text NOT NULL,
  request_id text NOT NULL,
  actor_class text NOT NULL,
  decision text NOT NULL,
  route_template text NOT NULL,
  method text NOT NULL,
  occurred_at timestamptz NOT NULL
);

CREATE TABLE outbox_events (
  id text PRIMARY KEY,
  type text NOT NULL,
  payload jsonb NOT NULL,
  occurred_at timestamptz NOT NULL,
  published_at timestamptz,
  attempts integer NOT NULL DEFAULT 0
);

CREATE INDEX idx_targets_tenant ON targets(tenant_id);
CREATE INDEX idx_grants_site_chain ON delegation_grants(site_id, chain_id);
CREATE INDEX idx_grants_active ON delegation_grants(site_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_grant ON issued_sessions(grant_id, issued_at DESC);
CREATE INDEX idx_revocations_chain_epoch ON revocations(chain_id, epoch DESC);
CREATE INDEX idx_decisions_site_time ON decisions(site_id, occurred_at DESC);
CREATE INDEX idx_decisions_route_actor ON decisions(site_id, route_template, actor_class, decision);
CREATE INDEX idx_outbox_pending ON outbox_events(occurred_at) WHERE published_at IS NULL;
