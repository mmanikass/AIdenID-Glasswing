ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS purpose text;

ALTER TABLE decisions
  DROP CONSTRAINT IF EXISTS decisions_purpose_format;

ALTER TABLE decisions
  ADD CONSTRAINT decisions_purpose_format
  CHECK (purpose IS NULL OR purpose ~ '^[a-z][a-z0-9_-]{0,63}$');

CREATE INDEX IF NOT EXISTS idx_decisions_site_purpose_occurred
  ON decisions(site_id, purpose, occurred_at DESC)
  WHERE purpose IS NOT NULL;
