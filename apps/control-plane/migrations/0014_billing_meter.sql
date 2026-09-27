CREATE TABLE IF NOT EXISTS tenant_pricing_plans (
  tenant_id text PRIMARY KEY,
  plan_tier text NOT NULL,
  currency text NOT NULL DEFAULT 'USD' CHECK (currency = 'USD'),
  unit_price_usd numeric NOT NULL CHECK (unit_price_usd >= 0),
  included_monthly_cleared_decisions integer NOT NULL DEFAULT 0 CHECK (included_monthly_cleared_decisions >= 0),
  effective_from timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS billing_period_rollups (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  period_start timestamptz NOT NULL,
  period_end timestamptz NOT NULL,
  plan_tier text NOT NULL,
  currency text NOT NULL DEFAULT 'USD' CHECK (currency = 'USD'),
  unit_price_usd numeric NOT NULL CHECK (unit_price_usd >= 0),
  included_cleared_decisions integer NOT NULL CHECK (included_cleared_decisions >= 0),
  cleared_decision_count integer NOT NULL CHECK (cleared_decision_count >= 0),
  billable_cleared_decision_count integer NOT NULL CHECK (billable_cleared_decision_count >= 0),
  overage_cleared_decision_count integer NOT NULL CHECK (overage_cleared_decision_count >= 0),
  estimated_cost_usd numeric NOT NULL CHECK (estimated_cost_usd >= 0),
  price_required_gross_usd numeric NOT NULL DEFAULT 0 CHECK (price_required_gross_usd >= 0),
  invoice_line_item_id text NOT NULL,
  export_idempotency_key text NOT NULL,
  generated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (period_start < period_end),
  UNIQUE (tenant_id, period_start, period_end),
  UNIQUE (export_idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_decisions_tenant_billing_period
  ON decisions(tenant_id, occurred_at DESC)
  WHERE tenant_id IS NOT NULL AND decision <> 'deny';

CREATE INDEX IF NOT EXISTS idx_decisions_tenant_price_period
  ON decisions(tenant_id, occurred_at DESC)
  WHERE tenant_id IS NOT NULL AND price_usd IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_billing_period_rollups_tenant_period
  ON billing_period_rollups(tenant_id, period_start DESC, period_end DESC);

CREATE INDEX IF NOT EXISTS idx_billing_period_rollups_invoice_line
  ON billing_period_rollups(invoice_line_item_id);
