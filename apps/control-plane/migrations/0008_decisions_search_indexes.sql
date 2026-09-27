CREATE INDEX IF NOT EXISTS idx_decisions_operator_search
  ON decisions(site_id, operator_action_actor_id, decision, occurred_at DESC)
  WHERE operator_action_actor_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_decisions_subject_search
  ON decisions(site_id, subject_handle, occurred_at DESC)
  WHERE subject_handle IS NOT NULL;
