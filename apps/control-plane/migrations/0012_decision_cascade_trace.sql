ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS cascade_trace jsonb;

CREATE INDEX IF NOT EXISTS idx_decisions_cascade_trace_gin
  ON decisions USING gin (cascade_trace)
  WHERE cascade_trace IS NOT NULL;
