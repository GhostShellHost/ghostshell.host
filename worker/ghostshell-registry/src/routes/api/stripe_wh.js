// ── GhostShell Worker — Stripe webhook handler ───────────────────────────────
import { verifyStripeSignature, sha256Hex, aesGcmEncrypt } from "../../utils/crypto.js";
import { nowUtcIso }                                        from "../../utils/time.js";
import { isValidEmail }                                     from "../../utils/ids.js";
import { sendEmail, EMAIL_FOOTER_TEXT, EMAIL_FOOTER_HTML }  from "../../services/email.js";
import { rememberWebhookEventOnce, allocateCardNumber }     from "../../db/schema.js";
import { DEFAULT_BASE_URL }                                 from "../../config.js";

export async function stripeWebhook(request, env) {
  const sig = request.headers.get("stripe-signature") || "";
  const raw = await request.text();

  const ok = await verifyStripeSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("Invalid signature", { status: 400 });

  const event = JSON.parse(raw);

  // Abandoned checkout reminder: session expired without payment
  if (event.type === "checkout.session.expired") {
    const isNew = await rememberWebhookEventOnce(env.DB, event.id, "checkout.session.expired");
    if (!isNew) return new Response("Already processed", { status: 200 });

    const expiredSession = event.data.object;
    const expiredMd      = expiredSession.metadata || {};
    const abandonedEmail = (expiredMd.recovery_email || expiredSession.customer_details?.email || "").toLowerCase().trim();

    if (abandonedEmail && isValidEmail(abandonedEmail)) {
      const issueUrl = `${DEFAULT_BASE_URL}/issue/`;
      const { ok: emailOk, error: emailError } = await sendEmail(env, {
        to: abandonedEmail,
        subject: "Complete your GhostShell Birth Certificate",
        text: [
          "Hi,",
          "",
          "You started registering an agent with GhostShell but didn't complete checkout.",
          "",
          "When you're ready, continue here:",
          issueUrl,
          "",
          EMAIL_FOOTER_TEXT,
        ].join("\n"),
        html: `
          <p>Hi,</p>
          <p>You started registering an agent with GhostShell but didn't complete checkout.</p>
          <p>When you're ready, continue here:<br>
          <a href="${issueUrl}">${issueUrl}</a></p>
          ${EMAIL_FOOTER_HTML}
        `,
      });
      const sendStatus = emailOk ? "sent" : "failed";
      console.log("[email] abandoned_checkout", abandonedEmail, sendStatus, emailError?.slice(0, 200));

      try {
        await env.DB.prepare(
          "UPDATE purchase_tokens_v2 SET status = 'abandoned', abandoned_email_sent_at_utc = ?, abandoned_email_status = ?, abandoned_email_error = ? WHERE stripe_session_id = ?"
        ).bind(nowUtcIso(), sendStatus, emailError ? emailError.slice(0, 1000) : null, expiredSession.id).run();
      } catch (_) { /* non-fatal, session may not have a token row */ }
    }
    return new Response("OK", { status: 200 });
  }

  if (event.type !== "checkout.session.completed") return new Response("Ignored", { status: 200 });

  // Idempotent: only process each completed event once
  const isNewCompleted = await rememberWebhookEventOnce(env.DB, event.id, "checkout.session.completed");
  if (!isNewCompleted) return new Response("Already processed", { status: 200 });

  const session = event.data.object;
  const md      = session.metadata || {};
  const cert_id = md.cert_id;
  const token   = md.token;
  if (!cert_id || !token) return new Response("Ignored (missing GhostShell metadata)", { status: 200 });

  const issued_at_utc = nowUtcIso();

  // Optional private delivery email (stretch goal): never displayed publicly.
  const deliveryConsent   = (md.delivery_consent || "no").toLowerCase() === "yes";
  const deliveryEmailRaw  = deliveryConsent ? ((md.delivery_email || session.customer_details?.email || "") + "").trim() : "";
  const deliveryEmailNorm = deliveryEmailRaw ? deliveryEmailRaw.toLowerCase() : "";
  const delivery_email_hash = deliveryEmailNorm ? await sha256Hex(deliveryEmailNorm) : null;

  let delivery_email_iv  = null;
  let delivery_email_enc = null;
  if (deliveryEmailNorm && env.EMAIL_ENC_KEY) {
    const enc     = await aesGcmEncrypt(deliveryEmailNorm, env.EMAIL_ENC_KEY);
    delivery_email_iv  = enc.iv_b64u;
    delivery_email_enc = enc.ct_b64u;
  }

  const record = {
    cert_id,
    issued_at_utc,
    agent_name:             md.agent_name || "Unnamed Agent",
    cognitive_core_family:  md.cognitive_core_family || "Undisclosed",
    cognitive_core_exact:   md.cognitive_core_exact || null,
    creator_label:          md.creator_label || null,
    provenance_link:        md.provenance_link || null,
    inception_date_utc:     md.inception_date || null,
    place_city:             md.place_city || null,
    place_state:            md.place_state || null,
    place_country:          md.place_country || null,
    show_city_public:       md.show_city_public === "1" ? 1 : 0,
    hide_state_public:      md.hide_state_public === "1" ? 1 : 0,
    registered_by:          "human",
    delivery_email_hash,
    delivery_email_iv,
    delivery_email_enc,
    schema_version: 2,
  };

  const fingerprintSource = JSON.stringify({
    cert_id:              record.cert_id,
    issued_at_utc:        record.issued_at_utc,
    agent_name:           record.agent_name,
    cognitive_core_exact: record.cognitive_core_exact,
    creator_label:        record.creator_label,
    provenance_link:      record.provenance_link,
    schema_version:       record.schema_version,
  });

  const public_fingerprint  = await sha256Hex(fingerprintSource);
  const download_token_hash = await sha256Hex(token);

  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const card_number = await allocateCardNumber(env.DB);
    const public_id   = `GS-BC-${record.registered_by === "agent" ? "A" : "H"}-${card_number}`;

    try {
      // Backward-compatible insert: try extended columns first, fall back to legacy schema.
      try {
        await env.DB.prepare(`
          INSERT INTO certificates
          (cert_id, issued_at_utc, card_number, public_id, registered_by,
           agent_name, cognitive_core_family, cognitive_core_exact,
           creator_label, provenance_link,
           inception_date_utc, place_city, place_state, place_country, show_city_public, hide_state_public,
           schema_version, public_fingerprint, download_token_hash, status,
           delivery_email_hash, delivery_email_iv, delivery_email_enc)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
        `).bind(
          record.cert_id, record.issued_at_utc, card_number, public_id, record.registered_by,
          record.agent_name, record.record.cognitive_core_family, record.cognitive_core_exact,
          record.creator_label, record.provenance_link,
          record.inception_date_utc, record.place_city, record.place_state, record.place_country, record.show_city_public, record.hide_state_public,
          record.schema_version, public_fingerprint, download_token_hash,
          record.delivery_email_hash, record.delivery_email_iv, record.delivery_email_enc
        ).run();
      } catch (e) {
        const msg = String(e?.message || "");
        const maybeMissingDeliveryCols =
          msg.includes("delivery_email_hash") || msg.includes("delivery_email_iv") || msg.includes("delivery_email_enc");
        if (!maybeMissingDeliveryCols) throw e;

        await env.DB.prepare(`
          INSERT INTO certificates
          (cert_id, issued_at_utc, card_number, public_id, registered_by,
           agent_name, cognitive_core_family, cognitive_core_exact,
           creator_label, provenance_link,
           inception_date_utc, place_city, place_state, place_country, show_city_public, hide_state_public,
           schema_version, public_fingerprint, download_token_hash, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
        `).bind(
          record.cert_id, record.issued_at_utc, card_number, public_id, record.registered_by,
          record.agent_name, record.record.cognitive_core_family, record.cognitive_core_exact,
          record.creator_label, record.provenance_link,
          record.inception_date_utc, record.place_city, record.place_state, record.place_country, record.show_city_public, record.hide_state_public,
          record.schema_version, public_fingerprint, download_token_hash
        ).run();
      }

      return new Response("OK", { status: 200 });
    } catch (e) {
      const msg = String(e?.message || "");
      const isPublicIdCollision =
        msg.includes("idx_certificates_public_id") ||
        msg.includes("UNIQUE constraint failed: certificates.public_id");
      if (isPublicIdCollision) { lastErr = e; continue; }
      throw e;
    }
  }

  throw new Error(`Failed to insert certificate after public_id retries: ${String(lastErr?.message || "unknown error")}`);
}
