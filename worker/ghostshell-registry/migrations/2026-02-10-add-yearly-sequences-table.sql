-- GhostShell D1 migration
-- Per-year monotonic counter for card-number allocation (YY-SEQ)

CREATE TABLE IF NOT EXISTS yearly_sequences (
  yy TEXT PRIMARY KEY,
  seq INTEGER NOT NULL
);
