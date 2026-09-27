ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb;
