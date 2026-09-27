ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS llm_brand text;

CREATE INDEX IF NOT EXISTS idx_decisions_llm_brand
  ON decisions(site_id, llm_brand, occurred_at DESC)
  WHERE llm_brand IS NOT NULL;
