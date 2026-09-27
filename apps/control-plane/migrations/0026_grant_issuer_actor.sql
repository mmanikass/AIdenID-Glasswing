-- Bind grant issuance to the authenticated operator that performed it.
--
-- A grant mints the delegation authority the session exchange later verifies, so it is the
-- record that most needs an attributable issuer. Revocations and kill-switch changes have
-- carried an actor_id for some time; grants have not.
--
-- NULLABLE on purpose, and NOT backfilled. Rows written before this column existed genuinely
-- have no attributable issuer, and NULL states that honestly. Backfilling them with a
-- placeholder or a guessed operator would manufacture evidence of who issued an authority
-- record — strictly worse than recording that we do not know.
ALTER TABLE delegation_grants
  ADD COLUMN IF NOT EXISTS issuer_actor_id TEXT;

-- Attribution queries ("what did this operator issue?") are the reason the column exists,
-- and they are the queries an incident responder runs under time pressure.
CREATE INDEX IF NOT EXISTS delegation_grants_issuer_actor_id_idx
  ON delegation_grants (issuer_actor_id)
  WHERE issuer_actor_id IS NOT NULL;
