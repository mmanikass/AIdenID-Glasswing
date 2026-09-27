ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS tenant_id text,
  ADD COLUMN IF NOT EXISTS receipt_jws text,
  ADD COLUMN IF NOT EXISTS receipt_key_id text,
  ADD COLUMN IF NOT EXISTS receipt_public_jwk jsonb,
  ADD COLUMN IF NOT EXISTS receipt_payload_sha256 text,
  ADD COLUMN IF NOT EXISTS receipt_jws_sha256 text,
  ADD COLUMN IF NOT EXISTS transparency_leaf_hash text,
  ADD COLUMN IF NOT EXISTS transparency_leaf_index bigint,
  ADD COLUMN IF NOT EXISTS transparency_checkpoint jsonb,
  ADD COLUMN IF NOT EXISTS transparency_inclusion_proof jsonb;

CREATE INDEX IF NOT EXISTS idx_decisions_tenant_time
  ON decisions(tenant_id, occurred_at DESC)
  WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_decisions_receipt_key
  ON decisions(receipt_key_id, occurred_at DESC)
  WHERE receipt_key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_decisions_transparency_leaf
  ON decisions(transparency_leaf_hash)
  WHERE transparency_leaf_hash IS NOT NULL;
