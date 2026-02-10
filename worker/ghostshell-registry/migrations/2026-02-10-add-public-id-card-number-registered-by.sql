-- GhostShell D1 migration
-- Add public-facing alias + registration metadata to certificates
-- Minimal additive change; no existing columns removed/renamed.

ALTER TABLE certificates ADD COLUMN card_number TEXT;
ALTER TABLE certificates ADD COLUMN public_id TEXT;
ALTER TABLE certificates ADD COLUMN registered_by TEXT;

-- Enforce uniqueness for public-facing IDs while allowing NULL on legacy rows.
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_public_id ON certificates(public_id);
