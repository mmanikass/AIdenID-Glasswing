ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS operator_action text,
  ADD COLUMN IF NOT EXISTS operator_action_actor_id text,
  ADD COLUMN IF NOT EXISTS operator_action_reason text,
  ADD COLUMN IF NOT EXISTS operator_action_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_decisions_operator_action_at
  ON decisions(operator_action_at DESC)
  WHERE operator_action IS NOT NULL;
