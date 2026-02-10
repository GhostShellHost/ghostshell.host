-- GhostShell D1 migration
-- Single-use purchase token tracking for purchase-first handoff flow

CREATE TABLE IF NOT EXISTS purchase_tokens (
  token TEXT PRIMARY KEY,
  stripe_session_id TEXT UNIQUE NOT NULL,
  stripe_payment_intent TEXT,
  email_hash TEXT,
  created_at_utc TEXT NOT NULL,
  used_at_utc TEXT,
  used_cert_id TEXT
);
