ALTER TABLE operator_reputation
  ADD COLUMN IF NOT EXISTS default_action text NOT NULL DEFAULT 'allow' CHECK (
    default_action IN ('allow', 'throttle', 'queue', 'sandbox', 'deny', 'price_required')
  ),
  ADD COLUMN IF NOT EXISTS default_scope_routes jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS default_scope_redirect_path text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'operator_reputation_default_scope_routes_array'
  ) THEN
    ALTER TABLE operator_reputation
      ADD CONSTRAINT operator_reputation_default_scope_routes_array CHECK (
        jsonb_typeof(default_scope_routes) = 'array'
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'operator_reputation_default_scope_routes_bounded'
  ) THEN
    ALTER TABLE operator_reputation
      ADD CONSTRAINT operator_reputation_default_scope_routes_bounded CHECK (
        jsonb_array_length(default_scope_routes) <= 32
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'operator_reputation_default_scope_redirect_path_local'
  ) THEN
    ALTER TABLE operator_reputation
      ADD CONSTRAINT operator_reputation_default_scope_redirect_path_local CHECK (
        default_scope_redirect_path IS NULL
        OR default_scope_redirect_path ~ '^/[A-Za-z0-9._~!$&''()*+,;=:@/%-]*$'
      ) NOT VALID;
  END IF;
END $$;
