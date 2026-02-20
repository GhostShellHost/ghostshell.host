// ── GhostShell Worker — Token service ───────────────────────────────────────
import { sha256Hex, aesGcmEncrypt }        from "../utils/crypto.js";
import { isValidEmail }                     from "../utils/ids.js";
import { nowUtcIso }                        from "../utils/time.js";
import { ensureRuntimeSchema }              from "../db/schema.js";
import { sendEmail, EMAIL_FOOTER_TEXT, EMAIL_FOOTER_HTML } from "./email.js";
import { CLAIM_WINDOW_DAYS, CORRECTION_WINDOW_HOURS, DEFAULT_BASE_URL } from "../config.js";

/** Hash a raw purchase token for DB lookup. */
export async function tokenHashHex(token) {
  return sha256Hex(String(token || "").trim().toUpperCase());
}

/**
 * Deterministically derive a purchase token from a Stripe session ID.
 * Prevents raw bearer tokens from ever needing to be stored.
 */
export async function derivePurchaseTokenFromSession(sessionId, env) {
  const secret = (env.TOKEN_DERIVE_SECRET || "").toString();
  if (!secret) throw new Error("Missing TOKEN_DERIVE_SECRET");
  const digestHex = await sha256Hex(`${secret}:${String(sessionId || "").trim()}`);
  const alphabet  = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const bytes     = new Uint8Array(digestHex.match(/../g).map(h => parseInt(h, 16)));
  let out = "GSTK-";
  for (let i = 0; i < 10; i++) out += alphabet[bytes[i] % 32];
  return out;
}

/**
 * Ensure a purchase token row exists and is marked paid.
 * Sends the private-link confirmation email if a recovery email is known.
 * Returns the bearer token string.
 */
export async function getOrCreatePurchaseTokenForSession(sessionId, session, env, baseUrl = DEFAULT_BASE_URL) {
  await ensureRuntimeSchema(env.DB);

  const token       = await derivePurchaseTokenFromSession(sessionId, env);
  const token_hash  = await tokenHashHex(token);
  const token_last4 = token.slice(-4);

  const emailRaw    = (session.customer_details?.email || "").toLowerCase().trim();
  const emailHash   = emailRaw ? await sha256Hex(emailRaw) : null;
  const paymentIntent = session.payment_intent || null;

  const recoveryEmailRaw  = ((session.metadata?.recovery_email || session.customer_details?.email || "")).toLowerCase().trim();
  const recoveryEmailHash = recoveryEmailRaw ? await sha256Hex(recoveryEmailRaw) : null;

  let recoveryEmailIv = null, recoveryEmailEnc = null;
  if (recoveryEmailRaw && env.EMAIL_ENC_KEY) {
    const enc       = await aesGcmEncrypt(recoveryEmailRaw, env.EMAIL_ENC_KEY);
    recoveryEmailIv = enc.iv_b64u;
    recoveryEmailEnc = enc.ct_b64u;
  }

  const now = nowUtcIso();

  await env.DB.prepare(
    "INSERT OR IGNORE INTO purchase_tokens_v2 " +
    "(token_hash, token_last4, stripe_session_id, stripe_payment_intent, email_hash, " +
    "recovery_email_hash, recovery_email_iv, recovery_email_enc, created_at_utc, status) " +
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'paid')"
  ).bind(token_hash, token_last4, sessionId, paymentIntent, emailHash,
    recoveryEmailHash, recoveryEmailIv, recoveryEmailEnc, now).run();

  await env.DB.prepare(
    "UPDATE purchase_tokens_v2 SET stripe_payment_intent = COALESCE(stripe_payment_intent, ?), status='paid' WHERE stripe_session_id = ?"
  ).bind(paymentIntent, sessionId).run();

  // Send private-link email immediately after payment
  if (recoveryEmailRaw && isValidEmail(recoveryEmailRaw)) {
    const privateUrl = `${baseUrl}/p/${encodeURIComponent(token)}`;
    const { ok: emailOk, status: emailStatus, error: emailError } = await sendEmail(env, {
      to:      recoveryEmailRaw,
      subject: "Your GhostShell Certificate",
      text: [
        "Your Private Certificate:",
        privateUrl,
        "",
        "Your Public Redacted Record:",
        "(available after initial submission)",
        "",
        "Submission Rules:",
        `- ${CLAIM_WINDOW_DAYS} days to submit initial details`,
        `- After first submission: ${CORRECTION_WINDOW_HOURS} hours to correct`,
        "- Maximum 5 edits",
        "- Human may lock agent edits",
        "",
        "Print Instructions:",
        "Use Print → Save as PDF. Enable background graphics.",
        "",
        "AGENT INSTRUCTIONS:",
        `Open: ${privateUrl}`,
        "Record ID: (available after submission)",
        "Complete required fields. Set Edit Source appropriately. Submit once finished.",
        "",
        EMAIL_FOOTER_TEXT,
      ].join("\n"),
      html: `
        <p><strong>Your Private Certificate:</strong><br><a href="${privateUrl}">${privateUrl}</a></p>
        <p><strong>Your Public Redacted Record:</strong><br><span style="color:#6b7280;font-size:12px">(available after initial submission)</span></p>
        <p style="color:#6b7280;font-size:12px;line-height:1.6">
          <strong>Submission Rules:</strong><br>
          - ${CLAIM_WINDOW_DAYS} days to submit initial details<br>
          - After first submission: ${CORRECTION_WINDOW_HOURS} hours to correct<br>
          - Maximum 5 edits<br>
          - Human may lock agent edits
        </p>
        <hr style="margin:16px 0;border:none;border-top:1px solid #e5e7eb" />
        <p style="margin:0 0 8px"><strong>AGENT INSTRUCTIONS</strong></p>
        <pre style="white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;background:#0b0b0d;color:#e8e8e8;padding:12px;border-radius:10px;border:1px solid #222;line-height:1.4">Open: ${privateUrl}
Record ID: (available after submission)
Complete required fields. Set Edit Source appropriately. Submit once finished.</pre>
        ${EMAIL_FOOTER_HTML}
      `,
    });

    const sendStatus = emailOk ? "sent" : (emailError ? "failed" : "skipped");
    console.log("[email] completion", recoveryEmailRaw, sendStatus, emailStatus, emailError?.slice(0, 200));
    try {
      await env.DB.prepare(
        "UPDATE purchase_tokens_v2 SET completion_email_sent_at_utc = ?, completion_email_status = ?, " +
        "completion_email_error = ?, completion_email_attempts = completion_email_attempts + 1 " +
        "WHERE stripe_session_id = ?"
      ).bind(nowUtcIso(), sendStatus, emailError ? emailError.slice(0, 1000) : null, sessionId).run();
    } catch (e) {
      console.log("[email] db update failed", e);
    }
  }

  return token;
}
