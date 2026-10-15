-- Quota counters only. No submitted source, prompts, API keys, or model output.
CREATE TABLE IF NOT EXISTS review_limits (
  bucket TEXT PRIMARY KEY,
  used INTEGER NOT NULL CHECK (used >= 0),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS review_limits_expiry ON review_limits(expires_at);
