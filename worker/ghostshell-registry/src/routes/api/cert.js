// ── GhostShell Worker — Certificate API routes ───────────────────────────────
import { json }                                         from "../../utils/response.js";
import { sha256Hex, aesGcmEncrypt, aesGcmDecrypt }      from "../../utils/crypto.js";
import { nowUtcIso, getEditWindowState, isClaimWindowOpen, msToHms } from "../../utils/time.js";
import { makeCertId, makePurchaseToken, isValidEmail, getBaseUrl, getStripePriceId } from "../../utils/ids.js";
import { sendEmail, EMAIL_FOOTER_TEXT, EMAIL_FOOTER_HTML } from "../../services/email.js";
import { fetchStripeCheckoutSession, isCheckoutCompleteForIssuance } from "../../services/stripe.js";
import { tokenHashHex, derivePurchaseTokenFromSession, getOrCreatePurchaseTokenForSession } from "../../services/tokens.js";
import { ensureRuntimeSchema, allocateCardNumber } from "../../db/schema.js";
import { fetchPublicRowById, resolveParentRecordValue } from "../../db/queries.js";
import { CLAIM_WINDOW_DAYS, CORRECTION_WINDOW_HOURS, ORIGIN_RUNTIME_DEFAULT, ORIGIN_VERSION_DEFAULT, DEFAULT_BASE_URL, PAGE_VERSION } from "../../config.js";

// ── /api/cert/create-checkout (legacy form-before-pay flow) ──────────────────
export async function createCheckout(request, env) {
  const baseUrl      = getBaseUrl(request, env);
  const stripePriceId = getStripePriceId(env);
  const fd = await request.formData();

  const agent_name           = (fd.get("agent_name") || "").toString().trim();
  const place_of_birth       = (fd.get("place_of_birth") || "").toString().trim();
  const cognitive_core_family = (fd.get("cognitive_core_family") || "").toString().trim();
  const cognitive_core_exact  = (fd.get("cognitive_core_exact") || "").toString().trim();
  const creator_label        = (fd.get("creator_label") || "").toString().trim();
  const provenance_link      = (fd.get("provenance_link") || "").toString().trim();
  const inception_date       = (fd.get("inception_date") || "").toString().trim();
  const place_city           = (fd.get("place_city") || "").toString().trim();
  const place_state          = (fd.get("place_state") || "").toString().trim();
  const place_country        = (fd.get("place_country") || "").toString().trim();
  const show_city_public     = (fd.get("show_city_public") || "").toString().trim() === "on" ? 1 : 0;
  const hide_state_public    = (fd.get("hide_state_public") || "").toString().trim() === "on" ? 1 : 0;
  const recovery_email       = (fd.get("recovery_email") || "").toString().trim();
  const delivery_email       = (fd.get("delivery_email") || "").toString().trim();
  const delivery_consent     = (fd.get("delivery_consent") || "").toString().trim();

  if (!recovery_email || !isValidEmail(recovery_email)) return json({ error: "Recovery email is required" }, 400);
  if (!agent_name || !place_of_birth || !cognitive_core_family) return json({ error: "Missing required fields" }, 400);
  if (!env.STRIPE_SECRET_KEY || !stripePriceId) return json({ error: "Missing STRIPE_SECRET_KEY / STRIPE_PRICE_ID" }, 500);

  const certId    = makeCertId();
  const token     = makePurchaseToken();
  const emailHash = await sha256Hex(recovery_email.toLowerCase().trim());

  const body = new URLSearchParams();
  body.set("mode", "payment");
  body.set("allow_promotion_codes", "true");
  body.set("success_url", `${baseUrl}/cert/${encodeURIComponent(certId)}/download?t=${encodeURIComponent(token)}`);
  body.set("cancel_url",  `${baseUrl}/issue/`);
  body.append("line_items[0][price]",    env.STRIPE_PRICE_ID);
  body.append("line_items[0][quantity]", "1");

  for (const [k, v] of [
    ["metadata[cert_id]", certId], ["metadata[token]", token],
    ["metadata[agent_name]", agent_name], ["metadata[place_of_birth]", place_of_birth],
    ["metadata[cognitive_core_family]", cognitive_core_family],
    ["metadata[cognitive_core_exact]", cognitive_core_exact],
    ["metadata[creator_label]", creator_label], ["metadata[provenance_link]", provenance_link],
    ["metadata[inception_date]", inception_date],
    ["metadata[place_city]", place_city], ["metadata[place_state]", place_state],
    ["metadata[place_country]", place_country],
    ["metadata[show_city_public]", show_city_public.toString()],
    ["metadata[hide_state_public]", hide_state_public.toString()],
    ["metadata[recovery_email]", recovery_email], ["metadata[recovery_email_hash]", emailHash],
  ]) body.set(k, v);

  const consentYes = delivery_consent === "on" || delivery_consent === "yes";
  body.set("metadata[delivery_consent]", consentYes && delivery_email ? "yes" : "no");
  if (consentYes && delivery_email) body.set("metadata[delivery_email]", delivery_email);

  const resp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  const data = await resp.json();
  if (!resp.ok) return json({ error: "Stripe error", details: data }, 500);
  return Response.redirect(data.url, 303);
}

// ── /api/cert/checkout (new email-first pay flow) ────────────────────────────
export async function purchaseFirstCheckout(request, env) {
  const baseUrl       = getBaseUrl(request, env);
  const stripePriceId = getStripePriceId(env);
  const fd            = await request.formData();
  const recovery_email = (fd.get("recovery_email") || "").toString().trim();

  if (!recovery_email || !isValidEmail(recovery_email)) {
    return Response.redirect(`${baseUrl}/issue/?error=email_required`, 303);
  }
  if (!env.STRIPE_SECRET_KEY || !stripePriceId) {
    return json({ error: "Missing STRIPE_SECRET_KEY / STRIPE_PRICE_ID" }, 500);
  }

  const body = new URLSearchParams();
  body.set("mode", "payment");
  body.set("allow_promotion_codes", "true");
  body.set("success_url", `${baseUrl}/api/cert/post-checkout?session_id={CHECKOUT_SESSION_ID}`);
  body.set("cancel_url",  `${baseUrl}/issue/`);
  body.append("line_items[0][price]",    stripePriceId);
  body.append("line_items[0][quantity]", "1");
  body.set("customer_email",               recovery_email);
  body.set("metadata[recovery_email]",     recovery_email);

  const resp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  const data = await resp.json();
  if (!resp.ok) return json({ error: "Stripe error", details: data }, 500);

  // Pre-create a pending token row
  const sessionId = data.id;
  const recoveryEmailHash = await sha256Hex(recovery_email.toLowerCase().trim());
  let recoveryEmailIv = null, recoveryEmailEnc = null;
  if (env.EMAIL_ENC_KEY) {
    const enc      = await aesGcmEncrypt(recovery_email.toLowerCase().trim(), env.EMAIL_ENC_KEY);
    recoveryEmailIv  = enc.iv_b64u;
    recoveryEmailEnc = enc.ct_b64u;
  }
  const now = nowUtcIso();
  try {
    await ensureRuntimeSchema(env.DB);
    const derived    = await derivePurchaseTokenFromSession(sessionId, env);
    const token_hash = await tokenHashHex(derived);
    const token_last4 = derived.slice(-4);
    await env.DB.prepare(
      "INSERT OR IGNORE INTO purchase_tokens_v2 " +
      "(token_hash, token_last4, stripe_session_id, stripe_payment_intent, email_hash, " +
      "recovery_email_hash, recovery_email_iv, recovery_email_enc, created_at_utc, status) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(token_hash, token_last4, sessionId, null, null, recoveryEmailHash, recoveryEmailIv, recoveryEmailEnc, now, "pending").run();
  } catch (e) {
    console.log("[checkout] pending insert failed", e);
  }

  return Response.redirect(data.url, 303);
}

// ── /api/cert/test-checkout ──────────────────────────────────────────────────
export async function testCheckout(request, env) {
  const baseUrl = getBaseUrl(request, env);
  const fd      = await request.formData();
  const recovery_email = (fd.get("recovery_email") || "").toString().trim();

  if (!recovery_email || !isValidEmail(recovery_email)) {
    return Response.redirect(`${baseUrl}/issue/?error=email_required`, 303);
  }

  const randomBytes  = crypto.getRandomValues(new Uint8Array(12));
  const randomHex    = Array.from(randomBytes).map(b => b.toString(16).padStart(2, "0")).join("");
  const testSessionId = `test_${Date.now()}_${randomHex}`;

  const mockSession = {
    id: testSessionId, payment_status: "paid", status: "complete",
    amount_total: 0,
    customer_details: { email: recovery_email },
    metadata: { recovery_email },
  };

  const token   = await getOrCreatePurchaseTokenForSession(testSessionId, mockSession, env, baseUrl);
  return Response.redirect(`${baseUrl}/p/${encodeURIComponent(token)}`, 303);
}

// ── /api/cert/handoff-token ──────────────────────────────────────────────────
export async function handoffToken(request, env) {
  const url       = new URL(request.url);
  const baseUrl   = getBaseUrl(request, env);
  const sessionId = (url.searchParams.get("session_id") || "").trim();

  if (!sessionId) return json({ error: "missing_session_id" }, 400);

  const stripe = await fetchStripeCheckoutSession(sessionId, env);
  if (!stripe.ok) return json({ error: "invalid_session" }, 404);
  if (!isCheckoutCompleteForIssuance(stripe.session)) return json({ error: "not_paid" }, 409);

  const token        = await getOrCreatePurchaseTokenForSession(sessionId, stripe.session, env, baseUrl);
  const tokenEncoded = encodeURIComponent(token);

  return json({
    token,
    private_url: `/p/${tokenEncoded}`,
    human_url:   `/register/?token=${tokenEncoded}&by=human`,
    agent_url:   `/register/?token=${tokenEncoded}&by=agent`,
  });
}

// ── /api/cert/post-checkout ──────────────────────────────────────────────────
export async function postCheckoutRedirect(request, env) {
  const traceId = request.headers.get("cf-ray") || `trace_${Date.now()}`;
  try {
    const baseUrl   = getBaseUrl(request, env);
    const url       = new URL(request.url);
    const sessionId = (url.searchParams.get("session_id") || "").trim();

    if (!sessionId) return Response.redirect(`${baseUrl}/issue/`, 303);

    if (sessionId.startsWith("test_")) {
      try {
        const token = await derivePurchaseTokenFromSession(sessionId, env);
        return Response.redirect(`${baseUrl}/p/${encodeURIComponent(token)}`, 303);
      } catch (_) {
        return Response.redirect(`${baseUrl}/issue/`, 303);
      }
    }

    const stripe = await fetchStripeCheckoutSession(sessionId, env);
    if (!stripe.ok || !isCheckoutCompleteForIssuance(stripe.session)) {
      return Response.redirect(`${baseUrl}/issue/`, 303);
    }

    const token = await getOrCreatePurchaseTokenForSession(sessionId, stripe.session, env, baseUrl);
    return Response.redirect(`${baseUrl}/p/${encodeURIComponent(token)}`, 303);
  } catch (e) {
    console.log("[post-checkout] error", traceId, String(e?.stack || e?.message || e));
    return json({ ok: false, err: "post_checkout_failed", trace_id: traceId }, 500);
  }
}

// ── /handoff (redirect-only, no UI) ─────────────────────────────────────────
export async function getHandoff(request, env) {
  const url = new URL(request.url);
  console.log("handoff redirect", url.pathname);

  const tok = (url.searchParams.get("token") || "").trim();
  if (tok && /^GSTK-[A-Za-z0-9_-]+$/i.test(tok)) {
    return new Response(null, {
      status: 302,
      headers: { Location: `/p/${encodeURIComponent(tok.toUpperCase())}`, "Cache-Control": "no-store" },
    });
  }

  const sessionId = (url.searchParams.get("session_id") || "").trim();
  if (sessionId) {
    const stripe = await fetchStripeCheckoutSession(sessionId, env);
    if (stripe.ok && isCheckoutCompleteForIssuance(stripe.session)) {
      const token = await getOrCreatePurchaseTokenForSession(sessionId, stripe.session, env, DEFAULT_BASE_URL);
      return new Response(null, {
        status: 302,
        headers: { Location: `/p/${encodeURIComponent(token)}`, "Cache-Control": "no-store" },
      });
    }
  }

  return new Response(null, { status: 303, headers: { Location: `/issue/`, "Cache-Control": "no-store" } });
}

// ── /api/cert/token-status ───────────────────────────────────────────────────
export async function tokenStatus(request, env) {
  await ensureRuntimeSchema(env.DB);
  const url   = new URL(request.url);
  const token = (url.searchParams.get("token") || "").trim();

  if (!token) return json({ ok: false, error: "missing_token" }, 400);

  const token_hash = await tokenHashHex(token);
  const tokenRow   = await env.DB.prepare(
    "SELECT created_at_utc, used_at_utc, used_cert_id FROM purchase_tokens_v2 WHERE token_hash = ?"
  ).bind(token_hash).first();

  if (!tokenRow) return json({ ok: false, error: "invalid_token" }, 404);

  if (!tokenRow.used_cert_id) {
    if (!isClaimWindowOpen(tokenRow.created_at_utc)) return json({ ok: false, error: "expired_token" }, 410);
    return json({
      ok: true, mode: "new", locked: false,
      message: `Token is valid. You have up to ${CLAIM_WINDOW_DAYS} days from purchase to submit.`,
    });
  }

  const cert = await env.DB.prepare(
    "SELECT cert_id, public_id, issued_at_utc, agent_name, inception_date_utc, " +
    "place_city, place_state, place_country, show_city_public, hide_state_public, " +
    "cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, " +
    "declared_ontological_status, edit_count, human_edit_count, agent_edit_count, last_edited_at_utc " +
    "FROM certificates WHERE cert_id = ?"
  ).bind(tokenRow.used_cert_id).first();

  if (!cert) return json({ ok: false, error: "linked_certificate_missing" }, 409);

  const win = getEditWindowState(cert.issued_at_utc);
  return json({
    ok: true,
    mode:         win.locked ? "locked" : "edit",
    locked:       win.locked,
    lock_at_utc:  win.lockAtUtc,
    lock_reason:  win.lockReason,
    cert: {
      cert_id:                   cert.cert_id,
      public_id:                 cert.public_id,
      issued_at_utc:             cert.issued_at_utc,
      agent_name:                cert.agent_name || "",
      inception_date_utc:        cert.inception_date_utc || "",
      place_city:                cert.place_city || "",
      place_state:               cert.place_state || "",
      place_country:             cert.place_country || "",
      show_city_public:          Number(cert.show_city_public || 0),
      hide_state_public:         Number(cert.hide_state_public || 0),
      cognitive_core_family:     cert.cognitive_core_family || "",
      cognitive_core_exact:      cert.cognitive_core_exact || "",
      creator_label:             cert.creator_label || "",
      provenance_link:           cert.provenance_link || "",
      declared_ontological_status: cert.declared_ontological_status || "",
      edit_count:                Number(cert.edit_count || 0),
      human_edit_count:          Number(cert.human_edit_count || 0),
      agent_edit_count:          Number(cert.agent_edit_count || 0),
      last_edited_at_utc:        cert.last_edited_at_utc || null,
    },
  });
}

// ── /api/cert/redeem-token (form submit + edits) ─────────────────────────────
export async function redeemPurchaseToken(request, env) {
  const baseUrl = getBaseUrl(request, env);
  await ensureRuntimeSchema(env.DB);
  const fd = await request.formData();

  let token = (fd.get("token") || "").toString().trim();
  // Fallback: recover token from Referer header
  if (!token) {
    const ref = request.headers.get("referer") || request.headers.get("referrer") || "";
    if (ref) {
      try { token = (new URL(ref)).searchParams.get("token") || ""; } catch (_) {}
    }
  }

  const registered_by_raw = (fd.get("registered_by") || "human").toString().trim().toLowerCase();
  const edit_source_raw   = (fd.get("edit_source") || "").toString().trim().toLowerCase();
  const agent_handle      = (fd.get("agent_handle") || "").toString().trim() || null;
  const edit_source = edit_source_raw === "agent" ? "agent" : (edit_source_raw === "human" ? "human" : (registered_by_raw === "agent" ? "agent" : "human"));
  const registered_by = edit_source;

  const agent_name               = (fd.get("agent_name") || "").toString().trim();
  const cognitive_core_family    = ((fd.get("cognitive_core_family") || "").toString().trim()) || "Undisclosed";
  const cognitive_core_exact     = (fd.get("cognitive_core_exact") || "").toString().trim();
  const creator_label            = (fd.get("creator_label") || "").toString().trim();
  const provenance_link          = (fd.get("provenance_link") || "").toString().trim();
  const declared_ontological_status = (fd.get("declared_ontological_status") || "").toString().trim() || null;
  const inception_date_utc       = (fd.get("inception_date") || fd.get("inception_date_utc") || "").toString().trim() || null;
  const place_city               = (fd.get("place_city") || "").toString().trim() || null;
  const place_state              = (fd.get("place_state") || "").toString().trim() || null;
  const place_country            = (fd.get("place_country") || "").toString().trim() || null;
  const show_city_public         = Number((fd.get("show_city_public") || "0").toString().trim()) === 1 ? 1 : 0;
  const hide_state_public        = Number((fd.get("hide_state_public") || "1").toString().trim()) === 1 ? 1 : 0;

  const safe = (s) => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const errPage = (msg) => new Response(
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Error — GhostShell</title>
<style>body{background:#0B0B0D;color:#e8e8e8;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{max-width:480px;width:100%;padding:40px;background:#141418;border:1px solid #222;border-radius:16px;text-align:center}
a{color:#8B8DFF}</style></head>
<body><div class="card"><h2>Registration failed</h2><p>${safe(msg)}</p><p><a href="/issue/">← Start over</a></p></div></body></html>`,
    { status: 400, headers: { "content-type": "text/html; charset=utf-8" } }
  );

  if (!token) return errPage("Missing registration token.");
  if (!agent_name) return errPage("Agent Name is required.");
  if (!inception_date_utc) return errPage("Inception Date is required.");
  if (!place_country) return errPage("Country is required.");

  const parentResolved = await resolveParentRecordValue(provenance_link, env);
  if (parentResolved.error) return errPage(parentResolved.error);
  const parent_record_value  = parentResolved.value;
  const parent_record_status = parentResolved.status || null;

  const token_hash = await tokenHashHex(token);
  const tokenRow   = await env.DB.prepare(
    "SELECT created_at_utc, used_at_utc, used_cert_id FROM purchase_tokens_v2 WHERE token_hash = ?"
  ).bind(token_hash).first();

  if (!tokenRow) return errPage("Invalid token. It may not exist or has expired.");

  if (!tokenRow.used_cert_id && !isClaimWindowOpen(tokenRow.created_at_utc)) {
    return errPage(`This link has expired. Please start a new purchase. (You have ${CLAIM_WINDOW_DAYS} days from purchase to submit.)`);
  }

  // ── Edit path: certificate already issued ────────────────────────────────
  if (tokenRow.used_cert_id) {
    const existing = await env.DB.prepare(
      "SELECT cert_id, public_id, issued_at_utc, edit_count, human_edit_count, agent_edit_count FROM certificates WHERE cert_id = ?"
    ).bind(tokenRow.used_cert_id).first();

    if (!existing) return errPage("This token is linked to a missing certificate. Please contact support.");

    const win = getEditWindowState(existing.issued_at_utc);
    if (win.locked) return errPage(`${win.lockReason} Locked at ${win.lockAtUtc}.`);

    if (Number(existing.edit_count || 0) >= 5) {
      return errPage(`Edits limit reached (${existing.edit_count}/5) for this certificate.`);
    }

    const lockRow  = await env.DB.prepare("SELECT lock_agent_edits FROM certificates WHERE cert_id = ?").bind(existing.cert_id).first();
    const lockAgent = Number(lockRow?.lock_agent_edits || 0) === 1;
    if (lockAgent && edit_source === "agent") return errPage("Agent edits are locked for this certificate.");

    const editedAt      = nowUtcIso();
    const schema_version = 2;
    const fpSrc = JSON.stringify({
      cert_id: existing.cert_id, issued_at_utc: existing.issued_at_utc, agent_name,
      cognitive_core_family, cognitive_core_exact: cognitive_core_exact || null,
      creator_label: creator_label || null, provenance_link: parent_record_value,
      parent_record_status, inception_date_utc: inception_date_utc || null,
      place_city, place_state, place_country,
      show_city_public: show_city_public || 0, hide_state_public: hide_state_public || 0,
      schema_version, edited_at_utc: editedAt,
    });
    const public_fingerprint = await sha256Hex(fpSrc);

    await env.DB.prepare(`
      UPDATE certificates SET
        registered_by = ?, agent_name = ?, cognitive_core_family = ?, cognitive_core_exact = ?,
        creator_label = ?, provenance_link = ?, parent_record_status = ?,
        declared_ontological_status = ?, inception_date_utc = ?,
        place_city = ?, place_state = ?, place_country = ?,
        show_city_public = ?, hide_state_public = ?, schema_version = ?,
        public_fingerprint = ?,
        edit_count       = COALESCE(edit_count, 0) + 1,
        human_edit_count = COALESCE(human_edit_count, 0) + (CASE WHEN ? = 'human' THEN 1 ELSE 0 END),
        agent_edit_count = COALESCE(agent_edit_count, 0) + (CASE WHEN ? = 'agent' THEN 1 ELSE 0 END),
        last_edited_at_utc = ?, last_edit_source = ?, last_agent_handle = ?
      WHERE cert_id = ?
    `).bind(
      registered_by, agent_name, cognitive_core_family, cognitive_core_exact || null,
      creator_label || null, parent_record_value, parent_record_status,
      declared_ontological_status, inception_date_utc,
      place_city, place_state, place_country,
      show_city_public, hide_state_public, schema_version, public_fingerprint,
      edit_source, edit_source, editedAt, edit_source, agent_handle, existing.cert_id
    ).run();

    try {
      const evtId = "EVT-" + crypto.getRandomValues(new Uint8Array(12)).reduce((s, b) => s + b.toString(16).padStart(2, "0"), "");
      await env.DB.prepare(
        "INSERT INTO cert_edit_events (id, cert_id, token, edit_source, agent_handle, user_agent, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(evtId, existing.cert_id, null, edit_source, agent_handle, request.headers.get("user-agent") || "", editedAt).run();
    } catch (_) {}

    return Response.redirect(`${baseUrl}/p/${encodeURIComponent(token)}`, 303);
  }

  // ── First issuance path ───────────────────────────────────────────────────
  const cert_id      = makeCertId();
  const issued_at_utc = nowUtcIso();
  const schema_version = 2;
  const fpSrc = JSON.stringify({
    cert_id, issued_at_utc, agent_name, cognitive_core_family,
    cognitive_core_exact: cognitive_core_exact || null,
    creator_label: creator_label || null, provenance_link: parent_record_value,
    parent_record_status, inception_date_utc: inception_date_utc || null,
    place_city, place_state, place_country,
    show_city_public: show_city_public || 0, hide_state_public: hide_state_public || 0,
    schema_version,
  });
  const public_fingerprint  = await sha256Hex(fpSrc);
  const download_token_hash = await sha256Hex(token);

  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const card_number = await allocateCardNumber(env.DB);
    const public_id   = `GS-BC-${registered_by === "agent" ? "A" : "H"}-${card_number}`;
    try {
      await env.DB.prepare(`
        INSERT INTO certificates
        (cert_id, issued_at_utc, card_number, public_id, registered_by,
         agent_name, place_of_birth,
         cognitive_core_family, cognitive_core_exact,
         creator_label, provenance_link, parent_record_status, declared_ontological_status,
         origin_runtime, origin_version,
         inception_date_utc, place_city, place_state, place_country, show_city_public, hide_state_public,
         schema_version, public_fingerprint, download_token_hash, status,
         edit_count, human_edit_count, agent_edit_count, last_edited_at_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active',
                1,
                (CASE WHEN ? = 'human' THEN 1 ELSE 0 END),
                (CASE WHEN ? = 'agent' THEN 1 ELSE 0 END),
                ?)
      `).bind(
        cert_id, issued_at_utc, card_number, public_id, registered_by,
        agent_name, "Deprecated",
        cognitive_core_family, cognitive_core_exact || null,
        creator_label || null, parent_record_value, parent_record_status,
        declared_ontological_status,
        ORIGIN_RUNTIME_DEFAULT, ORIGIN_VERSION_DEFAULT,
        inception_date_utc, place_city, place_state, place_country, show_city_public, hide_state_public,
        schema_version, public_fingerprint, download_token_hash,
        registered_by, registered_by, issued_at_utc
      ).run();

      await env.DB.prepare(
        "UPDATE purchase_tokens_v2 SET used_at_utc = ?, used_cert_id = ? WHERE token_hash = ?"
      ).bind(issued_at_utc, cert_id, await tokenHashHex(token)).run();

      // Send issued email
      try {
        const pt = await env.DB.prepare(
          "SELECT recovery_email_iv, recovery_email_enc FROM purchase_tokens_v2 WHERE token_hash = ?"
        ).bind(await tokenHashHex(token)).first();
        let recoveryEmail = "";
        if (pt?.recovery_email_iv && pt?.recovery_email_enc && env.EMAIL_ENC_KEY) {
          recoveryEmail = await aesGcmDecrypt(pt.recovery_email_iv, pt.recovery_email_enc, env.EMAIL_ENC_KEY);
        }
        if (recoveryEmail && isValidEmail(recoveryEmail)) {
          const privateUrl = `${baseUrl}/p/${encodeURIComponent(token)}`;
          const publicUrl  = `${baseUrl}/r/${encodeURIComponent(public_id)}`;
          await sendEmail(env, {
            to: recoveryEmail,
            subject: "Your GhostShell Certificate",
            text: [
              `Your Private Certificate: ${privateUrl}`,
              `Your Public Redacted Record: ${publicUrl}`,
              "",
              `Submission Rules: ${CLAIM_WINDOW_DAYS} days to submit · ${CORRECTION_WINDOW_HOURS}h to correct · Max 5 edits`,
              "",
              EMAIL_FOOTER_TEXT,
            ].join("\n"),
            html: `
              <p><strong>Your Private Certificate:</strong><br><a href="${privateUrl}">${privateUrl}</a></p>
              <p><strong>Your Public Redacted Record:</strong><br><a href="${publicUrl}">${publicUrl}</a></p>
              ${EMAIL_FOOTER_HTML}`,
          });
        }
      } catch (e) { console.log("[email] issued email failed", String(e?.message || e)); }

      return Response.redirect(`${baseUrl}/p/${encodeURIComponent(token)}`, 303);

    } catch (e) {
      const msg = String(e?.message || "");
      const isCollision =
        msg.includes("idx_certificates_public_id") ||
        msg.includes("UNIQUE constraint failed: certificates.public_id");
      if (isCollision) { lastErr = e; continue; }
      throw e;
    }
  }

  console.error("redeemPurchaseToken failed after retries", String(lastErr?.message || "unknown"));
  return errPage("Temporary registry issue while issuing certificate. Please retry in 10–20 seconds.");
}

// ── /api/cert/latest-origin ──────────────────────────────────────────────────
export async function latestOrigin(env) {
  const row = await env.DB.prepare(
    "SELECT cert_id, issued_at_utc FROM certificates WHERE status = 'active' ORDER BY issued_at_utc DESC LIMIT 1"
  ).first();
  if (!row) return json({ cert_id: null, issued_at_utc: null }, 200);
  return json({ cert_id: row.cert_id }, 200);
}
