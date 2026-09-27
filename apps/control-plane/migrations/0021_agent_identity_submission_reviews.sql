ALTER TABLE agent_identity_submissions
  ADD COLUMN IF NOT EXISTS reviewed_at timestamptz,
  ADD COLUMN IF NOT EXISTS review_decision text CHECK (review_decision IS NULL OR review_decision IN ('approve', 'reject')),
  ADD COLUMN IF NOT EXISTS reviewer_identity_hash_sha256 text CHECK (
    reviewer_identity_hash_sha256 IS NULL OR reviewer_identity_hash_sha256 ~ '^[a-f0-9]{64}$'
  ),
  ADD COLUMN IF NOT EXISTS review_reason text CHECK (review_reason IS NULL OR length(review_reason) BETWEEN 1 AND 1024),
  ADD COLUMN IF NOT EXISTS approved_operator_actor_id text CHECK (
    approved_operator_actor_id IS NULL OR approved_operator_actor_id ~ '^[A-Za-z0-9:_-]{1,128}$'
  ),
  ADD COLUMN IF NOT EXISTS operator_reputation_id text CHECK (
    operator_reputation_id IS NULL OR operator_reputation_id ~ '^opr_[A-Za-z0-9_-]+$'
  ),
  ADD COLUMN IF NOT EXISTS assigned_trust_tier text CHECK (
    assigned_trust_tier IS NULL OR assigned_trust_tier IN ('restricted', 'trusted')
  ),
  ADD COLUMN IF NOT EXISTS assigned_operator_status text CHECK (
    assigned_operator_status IS NULL OR assigned_operator_status IN ('active', 'watchlist')
  ),
  ADD COLUMN IF NOT EXISTS assigned_reputation_score integer CHECK (
    assigned_reputation_score IS NULL OR assigned_reputation_score BETWEEN 0 AND 100
  );

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_identity_submissions_review_state'
  ) THEN
    ALTER TABLE agent_identity_submissions
      ADD CONSTRAINT agent_identity_submissions_review_state CHECK (
        (
          status = 'pending_review'
          AND reviewed_at IS NULL
          AND review_decision IS NULL
          AND reviewer_identity_hash_sha256 IS NULL
          AND review_reason IS NULL
          AND approved_operator_actor_id IS NULL
          AND operator_reputation_id IS NULL
          AND assigned_trust_tier IS NULL
          AND assigned_operator_status IS NULL
          AND assigned_reputation_score IS NULL
        )
        OR (
          status = 'approved'
          AND reviewed_at IS NOT NULL
          AND review_decision = 'approve'
          AND reviewer_identity_hash_sha256 IS NOT NULL
          AND approved_operator_actor_id IS NOT NULL
          AND operator_reputation_id IS NOT NULL
          AND assigned_trust_tier IS NOT NULL
          AND assigned_operator_status IS NOT NULL
          AND assigned_reputation_score IS NOT NULL
        )
        OR (
          status = 'rejected'
          AND reviewed_at IS NOT NULL
          AND review_decision = 'reject'
          AND reviewer_identity_hash_sha256 IS NOT NULL
          AND review_reason IS NOT NULL
          AND approved_operator_actor_id IS NULL
          AND operator_reputation_id IS NULL
          AND assigned_trust_tier IS NULL
          AND assigned_operator_status IS NULL
          AND assigned_reputation_score IS NULL
        )
      ) NOT VALID;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_agent_identity_submissions_reviewed_at
  ON agent_identity_submissions(site_id, reviewed_at DESC)
  WHERE reviewed_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_identity_submissions_operator_reputation
  ON agent_identity_submissions(site_id, operator_reputation_id, reviewed_at DESC)
  WHERE operator_reputation_id IS NOT NULL;
