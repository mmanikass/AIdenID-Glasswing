CREATE UNIQUE INDEX IF NOT EXISTS idx_decision_receipt_keys_one_active_per_issuer
  ON decision_receipt_keys (issuer)
  WHERE state = 'active';
