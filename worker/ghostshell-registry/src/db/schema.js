// ── GhostShell Worker — Database schema & migrations ────────────────────────
import { nowUtcIso, getUTCYearYY }    from "../utils/time.js";
import { sha256Hex }                   from "../utils/crypto.js";
import { crockfordBase32Encode }       from "../utils/ids.js";

// Columns that may not exist in older D1 deployments.
const MAYBE_ALTER = [
  "ALTER TABLE certificates ADD COLUMN card_number TEXT",
  "ALTER TABLE certificates ADD COLUMN public_id TEXT",
  "ALTER TABLE certificates ADD COLUMN registered_by TEXT",
  "ALTER TABLE certificates ADD COLUMN edit_count INTEGER DEFAULT 0",
  "ALTER TABLE certificates ADD COLUMN human_edit_count INTEGER DEFAULT 0",
  "ALTER TABLE certificates ADD COLUMN agent_edit_count INTEGER DEFAULT 0",
  "ALTER TABLE certificates ADD COLUMN last_edited_at_utc TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN used_cert_id TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN recovery_email_hash TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN recovery_email_iv TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN recovery_email_enc TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN checkout_email_sent_at_utc TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN completion_email_sent_at_utc TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN completion_email_status TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN completion_email_error TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN completion_email_attempts INTEGER DEFAULT 0",
  "ALTER TABLE purchase_tokens ADD COLUMN abandoned_email_sent_at_utc TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN abandoned_email_status TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN abandoned_email_error TEXT",
  "ALTER TABLE purchase_tokens ADD COLUMN status TEXT DEFAULT 'pending'",
  "ALTER TABLE certificates ADD COLUMN declared_ontological_status TEXT",
  "ALTER TABLE certificates ADD COLUMN inception_date_utc TEXT",
  "ALTER TABLE certificates ADD COLUMN origin_runtime TEXT",
  "ALTER TABLE certificates ADD COLUMN origin_version TEXT",
  "ALTER TABLE certificates ADD COLUMN place_city TEXT",
  "ALTER TABLE certificates ADD COLUMN place_state TEXT",
  "ALTER TABLE certificates ADD COLUMN place_country TEXT",
  "ALTER TABLE certificates ADD COLUMN show_city_public INTEGER DEFAULT 0",
  "ALTER TABLE certificates ADD COLUMN hide_state_public INTEGER DEFAULT 0",
  "ALTER TABLE certificates ADD COLUMN lock_agent_edits INTEGER DEFAULT 0",
  "ALTER TABLE certificates ADD COLUMN last_edit_source TEXT",
  "ALTER TABLE certificates ADD COLUMN last_agent_handle TEXT",
];

/**
 * Idempotent runtime schema migration.
 * Safe to call on every request — uses IF NOT EXISTS + ignorable errors.
 */
export async function ensureRuntimeSchema(db) {
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS yearly_sequences (yy TEXT PRIMARY KEY, seq INTEGER NOT NULL DEFAULT 0)"
  ).run();

  await db.prepare(
    "CREATE TABLE IF NOT EXISTS webhook_events (event_id TEXT PRIMARY KEY, event_type TEXT, processed_at_utc TEXT NOT NULL)"
  ).run();

  await db.prepare(
    "CREATE TABLE IF NOT EXISTS cert_edit_events (id TEXT PRIMARY KEY, cert_id TEXT NOT NULL, token TEXT, edit_source TEXT, agent_handle TEXT, user_agent TEXT, created_at_utc TEXT NOT NULL)"
  ).run();

  // SECURITY: hashed-token table — no bearer tokens stored in plaintext.
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS purchase_tokens_v2 (
      token_hash TEXT PRIMARY KEY,
      token_last4 TEXT,
      stripe_session_id TEXT UNIQUE NOT NULL,
      stripe_payment_intent TEXT,
      email_hash TEXT,
      recovery_email_hash TEXT,
      recovery_email_iv TEXT,
      recovery_email_enc TEXT,
      created_at_utc TEXT NOT NULL,
      used_at_utc TEXT,
      used_cert_id TEXT,
      status TEXT DEFAULT 'pending',
      completion_email_sent_at_utc TEXT,
      completion_email_status TEXT,
      completion_email_error TEXT,
      completion_email_attempts INTEGER DEFAULT 0,
      abandoned_email_sent_at_utc TEXT,
      abandoned_email_status TEXT,
      abandoned_email_error TEXT
    )`
  ).run();

  for (const sql of MAYBE_ALTER) {
    try {
      await db.prepare(sql).run();
    } catch (e) {
      const msg = String(e?.message || "").toLowerCase();
      const ignorable =
        msg.includes("duplicate column name") ||
        msg.includes("already exists")        ||
        msg.includes("duplicate")             ||
        msg.includes("no such table: purchase_tokens");
      if (!ignorable) throw e;
    }
  }

  try {
    await db.prepare(
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_public_id ON certificates(public_id)"
    ).run();
  } catch (_) {
    // Non-fatal: legacy DBs may have conflicting data temporarily.
  }

  // Best-effort backfill from legacy plaintext purchase_tokens → hashed purchase_tokens_v2.
  try {
    const legacy = await db.prepare(
      `SELECT token, stripe_session_id, stripe_payment_intent, email_hash,
              recovery_email_hash, recovery_email_iv, recovery_email_enc,
              created_at_utc, used_at_utc, used_cert_id, status,
              completion_email_sent_at_utc, completion_email_status, completion_email_error,
              completion_email_attempts, abandoned_email_sent_at_utc, abandoned_email_status,
              abandoned_email_error
       FROM purchase_tokens WHERE token IS NOT NULL LIMIT 50`
    ).all();
    for (const r of (legacy?.results || [])) {
      const tok = String(r.token || "").trim();
      if (!tok) continue;
      const token_hash = await sha256Hex(tok.toUpperCase());
      const token_last4 = tok.slice(-4);
      await db.prepare(
        `INSERT OR IGNORE INTO purchase_tokens_v2
         (token_hash, token_last4, stripe_session_id, stripe_payment_intent,
          email_hash, recovery_email_hash, recovery_email_iv, recovery_email_enc,
          created_at_utc, used_at_utc, used_cert_id, status,
          completion_email_sent_at_utc, completion_email_status, completion_email_error,
          completion_email_attempts, abandoned_email_sent_at_utc, abandoned_email_status,
          abandoned_email_error)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        token_hash, token_last4, r.stripe_session_id, r.stripe_payment_intent,
        r.email_hash, r.recovery_email_hash, r.recovery_email_iv, r.recovery_email_enc,
        r.created_at_utc, r.used_at_utc, r.used_cert_id, r.status,
        r.completion_email_sent_at_utc, r.completion_email_status, r.completion_email_error,
        r.completion_email_attempts, r.abandoned_email_sent_at_utc, r.abandoned_email_status,
        r.abandoned_email_error
      ).run();
    }
  } catch (_) {
    // Non-fatal.
  }
}

/**
 * Atomically allocate the next card number for the current year.
 * Returns a string like "26-1" (yy-crockfordSeq).
 */
export async function allocateCardNumber(db) {
  const yy = getUTCYearYY(new Date());

  await db.prepare(
    "CREATE TABLE IF NOT EXISTS yearly_sequences (yy TEXT PRIMARY KEY, seq INTEGER NOT NULL DEFAULT 0)"
  ).run();

  for (let attempt = 0; attempt < 3; attempt++) {
    await db.prepare("INSERT OR IGNORE INTO yearly_sequences (yy, seq) VALUES (?, 0)").bind(yy).run();
    const upd = await db.prepare("UPDATE yearly_sequences SET seq = seq + 1 WHERE yy = ?").bind(yy).run();
    if (Number(upd?.meta?.changes || 0) < 1) continue;

    const row = await db.prepare("SELECT seq FROM yearly_sequences WHERE yy = ?").bind(yy).first();
    const seq = Number(row?.seq);
    if (Number.isInteger(seq) && seq > 0) {
      return `${yy}-${crockfordBase32Encode(seq)}`;
    }
  }
  throw new Error("Failed to allocate card number");
}

/**
 * Idempotent webhook deduplication.
 * Returns true if the event was newly recorded, false if already processed.
 */
export async function rememberWebhookEventOnce(db, eventId, eventType) {
  if (!eventId) return true;
  try {
    await db.prepare(
      "INSERT INTO webhook_events (event_id, event_type, processed_at_utc) VALUES (?, ?, ?)"
    ).bind(eventId, eventType || "unknown", nowUtcIso()).run();
    return true;
  } catch (e) {
    const msg = String(e?.message || "").toLowerCase();
    if (msg.includes("unique") || msg.includes("already exists") || msg.includes("constraint")) {
      return false;
    }
    throw e;
  }
}
