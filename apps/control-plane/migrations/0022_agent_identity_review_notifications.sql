CREATE TABLE IF NOT EXISTS agent_identity_review_notifications (
  id text PRIMARY KEY CHECK (id ~ '^arn_[A-Za-z0-9_-]+$'),
  site_id text NOT NULL CHECK (site_id ~ '^sit_[A-Za-z0-9_-]{1,124}$'),
  submission_id text NOT NULL REFERENCES agent_identity_submissions(id) ON DELETE CASCADE,
  review_decision text NOT NULL CHECK (review_decision IN ('approve', 'reject')),
  provider_name text NOT NULL CHECK (length(provider_name) BETWEEN 1 AND 128),
  operator_actor_id text CHECK (operator_actor_id IS NULL OR operator_actor_id ~ '^[A-Za-z0-9:_-]{1,128}$'),
  contact_url text NOT NULL CHECK (length(contact_url) BETWEEN 1 AND 2048),
  reviewer_identity_hash_sha256 text NOT NULL CHECK (reviewer_identity_hash_sha256 ~ '^[a-f0-9]{64}$'),
  review_reason text CHECK (review_reason IS NULL OR length(review_reason) BETWEEN 1 AND 1024),
  status text NOT NULL DEFAULT 'unread' CHECK (status IN ('unread', 'read')),
  created_at timestamptz NOT NULL DEFAULT now(),
  read_at timestamptz,
  UNIQUE (submission_id, review_decision),
  CHECK (
    (status = 'unread' AND read_at IS NULL)
    OR (status = 'read' AND read_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_agent_identity_review_notifications_site_status
  ON agent_identity_review_notifications(site_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_identity_review_notifications_submission
  ON agent_identity_review_notifications(submission_id, review_decision);
