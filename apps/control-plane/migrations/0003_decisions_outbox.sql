CREATE TABLE IF NOT EXISTS decision_outbox (
  seq bigserial PRIMARY KEY,
  decision_id text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  event_type text NOT NULL CHECK (event_type IN ('recorded', 'pending', 'resolved', 'updated')),
  payload jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decision_outbox_seq ON decision_outbox(seq);
CREATE INDEX IF NOT EXISTS idx_decision_outbox_retention ON decision_outbox(occurred_at);
CREATE INDEX IF NOT EXISTS idx_decision_outbox_decision ON decision_outbox(decision_id, seq DESC);
