-- GhostShell D1 migration
-- Add edit tracking columns to certificates (24-hour edit window)

ALTER TABLE certificates ADD COLUMN edit_count INTEGER DEFAULT 0;
ALTER TABLE certificates ADD COLUMN last_edited_at_utc TEXT;
