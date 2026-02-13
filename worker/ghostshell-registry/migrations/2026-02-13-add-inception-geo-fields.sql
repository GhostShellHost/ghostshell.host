-- GhostShell D1 migration
-- Add inception date and structured geographic location fields

-- Add inception date (separate from registration/issued date)
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS inception_date_utc TEXT;

-- Add structured location fields (for city/state/country separation)
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS place_city TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS place_state TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS place_country TEXT;

-- Add location visibility toggles
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS show_city_public INTEGER DEFAULT 0; -- 0 = hidden, 1 = shown
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS hide_state_public INTEGER DEFAULT 0; -- 0 = shown, 1 = hidden

-- Note: country is always public, no toggle needed