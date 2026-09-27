ALTER TABLE decision_outbox
  ADD COLUMN IF NOT EXISTS previous_hash text,
  ADD COLUMN IF NOT EXISTS entry_hash text;

ALTER TABLE decision_outbox
  DROP CONSTRAINT IF EXISTS decision_outbox_previous_hash_format,
  DROP CONSTRAINT IF EXISTS decision_outbox_entry_hash_format;

ALTER TABLE decision_outbox
  ADD CONSTRAINT decision_outbox_previous_hash_format CHECK (previous_hash IS NULL OR previous_hash ~ '^[a-f0-9]{64}$'),
  ADD CONSTRAINT decision_outbox_entry_hash_format CHECK (entry_hash IS NULL OR entry_hash ~ '^[a-f0-9]{64}$');

CREATE UNIQUE INDEX IF NOT EXISTS idx_decision_outbox_entry_hash
  ON decision_outbox(entry_hash)
  WHERE entry_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_decision_outbox_previous_hash
  ON decision_outbox(previous_hash)
  WHERE previous_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS decision_receipt_keys (
  kid text PRIMARY KEY,
  issuer text NOT NULL,
  alg text NOT NULL CHECK (alg = 'EdDSA'),
  public_jwk jsonb NOT NULL,
  jwk_thumbprint_sha256 text NOT NULL CHECK (jwk_thumbprint_sha256 ~ '^[a-f0-9]{64}$'),
  state text NOT NULL CHECK (state IN ('active', 'retiring', 'retired')),
  activated_at timestamptz NOT NULL,
  retire_after timestamptz,
  retired_at timestamptz,
  rotation_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (retire_after IS NULL OR retire_after >= activated_at),
  CHECK (retired_at IS NULL OR retired_at >= activated_at)
);

CREATE INDEX IF NOT EXISTS idx_decision_receipt_keys_state
  ON decision_receipt_keys(state, activated_at DESC);

CREATE INDEX IF NOT EXISTS idx_decision_receipt_keys_rotation_due
  ON decision_receipt_keys(retire_after)
  WHERE state IN ('active', 'retiring') AND retire_after IS NOT NULL;
