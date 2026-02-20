// ── GhostShell Worker — Database queries ─────────────────────────────────────
import { ensureRuntimeSchema } from "./schema.js";
import { sha256Hex }           from "../utils/crypto.js";

/** Hash a raw purchase token for DB lookup. */
export async function tokenHashHex(token) {
  return sha256Hex(String(token || "").trim().toUpperCase());
}

const PUBLIC_SELECT =
  "SELECT cert_id, public_id, issued_at_utc, inception_date_utc, origin_runtime, origin_version, " +
  "agent_name, place_city, place_state, place_country, show_city_public, hide_state_public, " +
  "cognitive_core_family, cognitive_core_exact, creator_label, declared_ontological_status, " +
  "public_fingerprint, status, edit_count, human_edit_count, agent_edit_count FROM certificates WHERE ";

/** Fetch the public-facing row for a certificate by cert_id or public_id. */
export async function fetchPublicRowById(id, env) {
  let row = await env.DB.prepare(`${PUBLIC_SELECT}cert_id = ?`).bind(id).first();
  if (!row) {
    const found = await env.DB.prepare(`${PUBLIC_SELECT}public_id = ?`).bind(id).all();
    const results = found?.results || [];
    if (results.length === 1) row = results[0];
  }
  return row || null;
}

const PRIVATE_SELECT =
  "SELECT cert_id, public_id, issued_at_utc, inception_date_utc, " +
  "agent_name, place_city, place_state, place_country, show_city_public, hide_state_public, " +
  "cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, parent_record_status, " +
  "declared_ontological_status, public_fingerprint, status, edit_count, human_edit_count, agent_edit_count, " +
  "last_edited_at_utc, download_token_hash, lock_agent_edits, last_edit_source, last_agent_handle " +
  "FROM certificates WHERE cert_id = ?";

/** Fetch the private certificate and its token row. */
export async function fetchCertByPurchaseToken(token, env) {
  await ensureRuntimeSchema(env.DB);
  const tok = (token || "").toString().trim().toUpperCase();
  const tokenRow = await env.DB.prepare(
    "SELECT created_at_utc, used_at_utc, used_cert_id, recovery_email_iv, recovery_email_enc " +
    "FROM purchase_tokens_v2 WHERE token_hash = ?"
  ).bind(await tokenHashHex(tok)).first();

  if (!tokenRow) return { tokenRow: null, cert: null };
  if (!tokenRow.used_cert_id) return { tokenRow, cert: null };

  const cert = await env.DB.prepare(PRIVATE_SELECT).bind(tokenRow.used_cert_id).first();
  return { tokenRow, cert: cert || null };
}

/**
 * Resolve and validate a parent record reference.
 * Supports: full token URL, raw GSTK token, or GS-BC public ID.
 * Returns { value, status } | { error }
 */
export async function resolveParentRecordValue(rawInput, env) {
  const raw = (rawInput || "").toString().trim();
  if (!raw) return { value: null, status: null };

  const findById = async (candidate) => {
    const row = await env.DB.prepare(
      "SELECT public_id, cert_id FROM certificates WHERE public_id = ? OR cert_id = ? LIMIT 1"
    ).bind(candidate, candidate).first();
    return row ? (row.public_id || row.cert_id) : null;
  };

  // Full link with token proof (preferred): /register?token=GSTK-…
  if (/^https?:\/\//i.test(raw)) {
    try {
      const u     = new URL(raw);
      const token = (u.searchParams.get("token") || "").trim();
      if (token && /^GSTK-[A-Za-z0-9_-]+$/i.test(token)) {
        const tRow = await env.DB.prepare(
          "SELECT used_cert_id FROM purchase_tokens_v2 WHERE token_hash = ? LIMIT 1"
        ).bind(await tokenHashHex(token)).first();
        if (!tRow?.used_cert_id) return { value: null, status: "block" };
        const cert = await env.DB.prepare(
          "SELECT public_id, cert_id FROM certificates WHERE cert_id = ? LIMIT 1"
        ).bind(tRow.used_cert_id).first();
        if (!cert) return { error: "Parent token references a missing certificate." };
        return { value: cert.public_id || cert.cert_id, status: "verified" };
      }
    } catch (_) {
      return { error: "Parent record format is invalid. Use token link, GSTK token, or GS-BC public ID." };
    }
  }

  // Raw GSTK token
  if (/^GSTK-[A-Za-z0-9_-]+$/i.test(raw)) {
    const tRow = await env.DB.prepare(
      "SELECT used_cert_id FROM purchase_tokens_v2 WHERE token_hash = ? LIMIT 1"
    ).bind(await tokenHashHex(raw)).first();
    if (!tRow?.used_cert_id) return { error: "Parent token is invalid or has not been used to issue a certificate yet." };
    const cert = await env.DB.prepare(
      "SELECT public_id, cert_id FROM certificates WHERE cert_id = ? LIMIT 1"
    ).bind(tRow.used_cert_id).first();
    if (!cert) return { error: "Parent token references a missing certificate." };
    return { value: cert.public_id || cert.cert_id, status: "verified" };
  }

  // GS-BC public ID (claimed only, no proof)
  if (/^GS-BC-[A-Za-z0-9_-]+$/i.test(raw)) {
    const resolved = await findById(raw);
    if (!resolved) return { error: "Parent public record ID not found in registry." };
    return { value: resolved, status: "claimed" };
  }

  return { error: "Parent record format is invalid. Use token link, GSTK token, or GS-BC public ID." };
}
