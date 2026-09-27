ALTER TABLE agent_identity_submissions
  ADD COLUMN IF NOT EXISTS requested_access_duration_seconds integer NOT NULL DEFAULT 3600
    CHECK (requested_access_duration_seconds BETWEEN 60 AND 7776000);

ALTER TABLE agent_identity_submissions
  ADD COLUMN IF NOT EXISTS requested_access_expires_at timestamptz;

UPDATE agent_identity_submissions
SET requested_access_expires_at = submitted_at + make_interval(secs => requested_access_duration_seconds)
WHERE requested_access_expires_at IS NULL;

ALTER TABLE agent_identity_submissions
  ALTER COLUMN requested_access_expires_at SET NOT NULL;
