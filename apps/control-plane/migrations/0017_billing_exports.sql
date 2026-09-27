CREATE TABLE IF NOT EXISTS billing_exports (
  id text PRIMARY KEY,
  rollup_id text NOT NULL REFERENCES billing_period_rollups(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  period_start timestamptz NOT NULL,
  period_end timestamptz NOT NULL,
  provider text NOT NULL CHECK (provider IN ('stripe_meter_event', 'quickbooks_invoice')),
  destination_ref text NOT NULL,
  idempotency_key text NOT NULL,
  payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
  payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'prepared' CHECK (status IN ('prepared', 'delivered')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  CHECK (period_start < period_end),
  CHECK (status <> 'delivered' OR delivered_at IS NOT NULL),
  UNIQUE (provider, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_billing_exports_tenant_period
  ON billing_exports(tenant_id, period_start DESC, period_end DESC);

CREATE INDEX IF NOT EXISTS idx_billing_exports_rollup
  ON billing_exports(rollup_id);

