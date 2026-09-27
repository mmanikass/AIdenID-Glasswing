CREATE TABLE IF NOT EXISTS agent_identity_submissions (
  id text PRIMARY KEY,
  site_id text NOT NULL CHECK (site_id ~ '^sit_[A-Za-z0-9_-]{1,124}$'),
  request_id text CHECK (request_id IS NULL OR length(request_id) BETWEEN 1 AND 128),
  purpose text NOT NULL CHECK (
    purpose IN (
      'research',
      'commercial_crawl',
      'ai_training',
      'monitoring_uptime',
      'accessibility',
      'archival',
      'search_indexing',
      'competitive_intelligence',
      'fraud_detection',
      'other'
    )
  ),
  purpose_rationale text CHECK (purpose_rationale IS NULL OR length(purpose_rationale) BETWEEN 1 AND 1024),
  provider_name text NOT NULL CHECK (length(provider_name) BETWEEN 1 AND 128),
  operator_actor_id text CHECK (operator_actor_id IS NULL OR operator_actor_id ~ '^[A-Za-z0-9:_-]{1,128}$'),
  contact_url text NOT NULL CHECK (length(contact_url) BETWEEN 1 AND 2048),
  jwks_url text CHECK (jwks_url IS NULL OR length(jwks_url) BETWEEN 1 AND 2048),
  delegation_authority_jwk_thumbprint_sha256 text CHECK (
    delegation_authority_jwk_thumbprint_sha256 IS NULL
    OR delegation_authority_jwk_thumbprint_sha256 ~ '^[a-f0-9]{64}$'
  ),
  cascade_attestation jsonb NOT NULL CHECK (
    cascade_attestation = '["crypto_identity","delegation_authorization","fingerprint_sidecar","operator_reputation"]'::jsonb
  ),
  declaration text CHECK (declaration IS NULL OR length(declaration) BETWEEN 1 AND 1024),
  submitter_hash_sha256 text NOT NULL CHECK (submitter_hash_sha256 ~ '^[a-f0-9]{64}$'),
  submission_digest_sha256 text NOT NULL CHECK (submission_digest_sha256 ~ '^[a-f0-9]{64}$'),
  operator_claim_hash_sha256 text NOT NULL CHECK (operator_claim_hash_sha256 ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status IN ('pending_review', 'approved', 'rejected')),
  submitted_at timestamptz NOT NULL DEFAULT now(),
  CHECK (purpose <> 'other' OR purpose_rationale IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_agent_identity_submissions_site_status
  ON agent_identity_submissions(site_id, status, submitted_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_identity_submissions_operator
  ON agent_identity_submissions(site_id, operator_actor_id, submitted_at DESC)
  WHERE operator_actor_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_identity_submissions_submitter
  ON agent_identity_submissions(site_id, submitter_hash_sha256, submitted_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_identity_submissions_digest
  ON agent_identity_submissions(site_id, submission_digest_sha256, submitted_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_identity_submissions_operator_claim
  ON agent_identity_submissions(site_id, operator_claim_hash_sha256, submitted_at DESC);
