ALTER TABLE billing_exports
  ADD COLUMN IF NOT EXISTS provider_receipt_id text,
  ADD COLUMN IF NOT EXISTS provider_receipt_status text,
  ADD COLUMN IF NOT EXISTS provider_receipt_payload_sha256 text,
  ADD COLUMN IF NOT EXISTS provider_receipt_recorded_at timestamptz;

ALTER TABLE billing_exports
  DROP CONSTRAINT IF EXISTS billing_exports_provider_receipt_payload_sha256_format;

ALTER TABLE billing_exports
  ADD CONSTRAINT billing_exports_provider_receipt_payload_sha256_format
  CHECK (
    provider_receipt_payload_sha256 IS NULL
    OR provider_receipt_payload_sha256 ~ '^[a-f0-9]{64}$'
  );

CREATE INDEX IF NOT EXISTS idx_billing_exports_provider_receipt
  ON billing_exports(provider, provider_receipt_id)
  WHERE provider_receipt_id IS NOT NULL;
