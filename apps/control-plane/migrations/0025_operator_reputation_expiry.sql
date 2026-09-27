ALTER TABLE operator_reputation
  ADD COLUMN IF NOT EXISTS expires_at timestamptz;

ALTER TABLE operator_reputation
  DROP CONSTRAINT IF EXISTS operator_reputation_status_check;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'operator_reputation_status_valid'
  ) THEN
    ALTER TABLE operator_reputation
      ADD CONSTRAINT operator_reputation_status_valid CHECK (
        status IN ('active', 'watchlist', 'suspended', 'expired')
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'operator_reputation_expires_after_created_at'
  ) THEN
    ALTER TABLE operator_reputation
      ADD CONSTRAINT operator_reputation_expires_after_created_at CHECK (
        expires_at IS NULL OR expires_at > created_at
      ) NOT VALID;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_operator_reputation_site_expires_at
  ON operator_reputation(site_id, expires_at)
  WHERE expires_at IS NOT NULL;
