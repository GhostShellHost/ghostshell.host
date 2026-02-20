// ── GhostShell Worker — Ops endpoints ─────────────────────────────────────────
import { json }                        from "../../utils/response.js";
import { sha256Hex, aesGcmDecrypt }    from "../../utils/crypto.js";
import { nowUtcIso }                   from "../../utils/time.js";
import { isValidEmail, makePurchaseToken, b64url } from "../../utils/ids.js";
import { sendEmail, EMAIL_FOOTER_TEXT, EMAIL_FOOTER_HTML } from "../../services/email.js";
import { ensureRuntimeSchema }         from "../../db/schema.js";
import { tokenHashHex }                from "../../db/queries.js";

export async function opsEmailSummary(request, env) {
  const url = new URL(request.url);
  const opsKey = url.searchParams.get("key") || "";
  if (env.OPS_SECRET && opsKey !== env.OPS_SECRET) {
    return new Response("Unauthorized", { status: 401 });
  }

  await ensureRuntimeSchema(env.DB);

  const since24h = new Date(Date.now() - 86400 * 1000).toISOString();

  const [totalTokens, sentOk, sentFailed, skipped, pendingForm, abandonedSent, abandonedFailed] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens_v2 WHERE created_at_utc > ?").bind(since24h).first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens_v2 WHERE completion_email_status = 'sent'").first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens_v2 WHERE completion_email_status = 'failed'").first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens_v2 WHERE completion_email_status IS NULL").first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens_v2 WHERE used_at_utc IS NULL AND created_at_utc > ?").bind(since24h).first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens_v2 WHERE abandoned_email_status = 'sent'").first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens_v2 WHERE abandoned_email_status = 'failed'").first(),
  ]);

  const failedRows = await env.DB.prepare(
    "SELECT stripe_session_id, completion_email_error, completion_email_attempts, created_at_utc FROM purchase_tokens_v2 WHERE completion_email_status = 'failed' ORDER BY created_at_utc DESC LIMIT 5"
  ).all();

  return json({
    since_24h: since24h,
    new_checkouts: totalTokens?.n ?? 0,
    completion_email: {
      sent: sentOk?.n ?? 0,
      failed: sentFailed?.n ?? 0,
      pending: skipped?.n ?? 0,
    },
    abandoned_email: {
      sent: abandonedSent?.n ?? 0,
      failed: abandonedFailed?.n ?? 0,
    },
    pending_form_completion: pendingForm?.n ?? 0,
    recent_failures: failedRows?.results ?? [],
  }, 200);
}

export async function adminRotateToken(request, env) {
  const secret = (env.ADMIN_ROTATE_SECRET || "").toString();
  if (!secret) return new Response("Not found", { status: 404 });

  const got = request.headers.get("x-admin-secret") || "";
  if (got !== secret) return new Response("Forbidden", { status: 403 });

  await ensureRuntimeSchema(env.DB);

  let bodyText = "";
  try { bodyText = await request.text(); } catch (_) {}
  let recordId = "";
  try {
    const j = bodyText ? JSON.parse(bodyText) : {};
    recordId = (j.recordId || j.record_id || "").toString().trim();
  } catch (_) {
    try {
      const fd = await request.formData();
      recordId = (fd.get("recordId") || fd.get("record_id") || "").toString().trim();
    } catch (_) {}
  }

  if (!recordId) return json({ ok: false, error: "recordId_required" }, 400);
  const rid = recordId.toUpperCase();

  const cert = await env.DB.prepare(
    "SELECT cert_id, public_id FROM certificates WHERE public_id = ? OR cert_id = ? LIMIT 1"
  ).bind(rid, rid).first();
  if (!cert?.cert_id) return json({ ok: false, error: "record_not_found" }, 404);

  const pt = await env.DB.prepare(
    "SELECT token_hash, recovery_email_iv, recovery_email_enc FROM purchase_tokens_v2 WHERE used_cert_id = ? LIMIT 1"
  ).bind(cert.cert_id).first();
  if (!pt?.token_hash) return json({ ok: false, error: "token_not_found" }, 404);

  const oldHash = pt.token_hash.toString().trim();
  const newToken = makePurchaseToken();
  const newHash = await tokenHashHex(newToken);
  const newLast4 = newToken.slice(-4);

  await env.DB.prepare(
    "UPDATE purchase_tokens_v2 SET token_hash = ?, token_last4 = ? WHERE token_hash = ?"
  ).bind(newHash, newLast4, oldHash).run();

  await env.DB.prepare(
    "UPDATE certificates SET download_token_hash = ? WHERE cert_id = ?"
  ).bind(await sha256Hex(newToken), cert.cert_id).run();

  try {
    let recoveryEmail = "";
    if (pt?.recovery_email_iv && pt?.recovery_email_enc && env.EMAIL_ENC_KEY) {
      recoveryEmail = await aesGcmDecrypt(pt.recovery_email_iv, pt.recovery_email_enc, env.EMAIL_ENC_KEY);
    }

    const baseUrl = (env.BASE_URL || "https://ghostshell.host").replace(/\/$/, "");
    const privateUrl = `${baseUrl}/p/${encodeURIComponent(newToken)}`;
    const publicUrl  = `${baseUrl}/r/${encodeURIComponent(cert.public_id || cert.cert_id)}`;

    if (recoveryEmail && isValidEmail(recoveryEmail)) {
      await sendEmail(env, {
        to: recoveryEmail,
        subject: "Your GhostShell Certificate (new private link)",
        text: [
          "This is a support-issued token rotation for your private certificate link.",
          "",
          `Your Private Certificate: ${privateUrl}`,
          `Your Public Redacted Record: ${publicUrl}`,
          "",
          EMAIL_FOOTER_TEXT,
        ].join("\n"),
        html: `
          <p><strong>This is a support-issued token rotation for your private certificate link.</strong></p>
          <p><strong>Your Private Certificate:</strong><br><a href="${privateUrl}">${privateUrl}</a></p>
          <p><strong>Your Public Redacted Record:</strong><br><a href="${publicUrl}">${publicUrl}</a></p>
          ${EMAIL_FOOTER_HTML}
        `,
      });
    }
  } catch (e) {
    console.log("[admin] rotate-token email failed", String(e?.message || e));
  }

  try {
    const id = "EVT-" + b64url(crypto.getRandomValues(new Uint8Array(12)));
    await env.DB.prepare(
      "INSERT INTO cert_edit_events (id, cert_id, token, edit_source, agent_handle, user_agent, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, cert.cert_id, null, "support", null, request.headers.get("user-agent") || "", nowUtcIso()).run();
  } catch (_) {}

  return json({ ok: true, recordId: cert.public_id || cert.cert_id, token: newToken }, 200);
}
