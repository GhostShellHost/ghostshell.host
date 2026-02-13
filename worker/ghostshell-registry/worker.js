// SOURCE OF TRUTH COPY
//
// This file should match the code deployed in Cloudflare for Worker: `ghostshell-registry`.
//
// Deploy steps: see /WORKER-DEPLOY.md
//
// VERSION: 2026-02-10.009 (manual paste deploy)
// If you paste this into Cloudflare, you should see this version string at the top.
//
export const WORKER_VERSION = "2026-02-13.024";
const PAGE_VERSION = "v0.019";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/cert/create-checkout" && request.method === "POST") {
      return createCheckout(request, env);
    }

    if (url.pathname === "/api/cert/checkout" && request.method === "POST") {
      return purchaseFirstCheckout(request, env);
    }

    if (url.pathname === "/api/cert/checkout" && request.method === "GET") {
      return new Response("Method not allowed. Use POST.", { status: 405 });
    }

    if (url.pathname === "/api/cert/test-checkout" && request.method === "POST") {
      return testCheckout(request, env);
    }

    if (url.pathname === "/api/cert/handoff-token" && request.method === "GET") {
      return handoffToken(request, env);
    }

    if (url.pathname === "/api/cert/post-checkout" && request.method === "GET") {
      return postCheckoutRedirect(request, env);
    }

    if ((url.pathname === "/handoff" || url.pathname === "/handoff/") && request.method === "GET") {
      return getHandoff(request, env);
    }

    if (url.pathname === "/api/cert/redeem-token" && request.method === "POST") {
      return redeemPurchaseToken(request, env);
    }

    if (url.pathname === "/api/cert/token-status" && request.method === "GET") {
      return tokenStatus(request, env);
    }

    if (url.pathname === "/api/stripe/webhook" && request.method === "POST") {
      return stripeWebhook(request, env);
    }

    if (url.pathname === "/api/cert/latest-origin" && request.method === "GET") {
      return latestOrigin(env);
    }

    if (url.pathname === "/api/ops/email-summary" && request.method === "GET") {
      return opsEmailSummary(request, env);
    }

    const certMatch = url.pathname.match(/^\/cert\/([A-Za-z0-9_-]+)$/);
    if (certMatch && request.method === "GET") {
      return certVerifyPage(certMatch[1], env);
    }

    const dlMatch = url.pathname.match(/^\/cert\/([A-Za-z0-9_-]+)\/download$/);
    if (dlMatch && request.method === "GET") {
      const token = url.searchParams.get("t") || "";
      return certDownloadPrintable(dlMatch[1], token, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
function html(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...extraHeaders,
    },
  });
}
function nowUtcIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
function b64url(u8) {
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function b64uFromBytes(u8) {
  return b64url(u8);
}
function bytesFromB64(b64) {
  const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
async function aesGcmEncrypt(plaintext, keyB64) {
  // keyB64 should be 32 bytes (base64 or base64url)
  const keyBytes = bytesFromB64(keyB64);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return { iv_b64u: b64uFromBytes(iv), ct_b64u: b64uFromBytes(new Uint8Array(ctBuf)) };
}
function makeCertId() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  const rand = crypto.getRandomValues(new Uint8Array(6));
  const slug = b64url(rand).slice(0, 8).toUpperCase();
  return `GS-BC-${y}${m}${day}-${slug}`;
}
function makeToken() {
  const rand = crypto.getRandomValues(new Uint8Array(24));
  return b64url(rand);
}

function getEditWindowState(issuedAtUtc) {
  const issuedMs = Date.parse(issuedAtUtc || "");
  if (!Number.isFinite(issuedMs)) {
    return { locked: true, remainingMs: 0, lockReason: "Invalid issue timestamp" };
  }
  const lockAtMs = issuedMs + 24 * 60 * 60 * 1000;
  const nowMs = Date.now();
  const remainingMs = Math.max(0, lockAtMs - nowMs);
  return {
    locked: nowMs > lockAtMs,
    remainingMs,
    lockAtUtc: new Date(lockAtMs).toISOString(),
    lockReason: nowMs > lockAtMs
      ? "This certificate is locked because the 24-hour correction window has ended."
      : "",
  };
}

function isValidEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || "").trim());
}

const EMAIL_FOOTER_TEXT = [
  "—",
  "GhostShell Registry",
  "https://ghostshell.host",
  "support@ghostshell.host",
  "You are receiving this transactional email because you started or completed a GhostShell checkout.",
].join("\n");

const EMAIL_FOOTER_HTML = `
  <hr style="margin:20px 0;border:none;border-top:1px solid #e5e7eb" />
  <p style="font-size:12px;color:#6b7280;line-height:1.5;margin:0">
    <strong>GhostShell Registry</strong><br>
    <a href="https://ghostshell.host" style="color:#6b7280">ghostshell.host</a> ·
    <a href="mailto:support@ghostshell.host" style="color:#6b7280">support@ghostshell.host</a><br>
    You are receiving this transactional email because you started or completed a GhostShell checkout.
  </p>
`;

async function aesGcmDecrypt(ivB64u, ctB64u, keyB64) {
  const keyBytes = bytesFromB64(keyB64);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const iv = bytesFromB64(ivB64u);
  const ct = bytesFromB64(ctB64u);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(ptBuf);
}

async function sendEmail(env, { to, subject, text, html }) {
  if (!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL || !isValidEmail(to)) {
    return { ok: false, skipped: true, error: "missing_config_or_invalid_email" };
  }

  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.RESEND_FROM_EMAIL,
      to: [to],
      subject,
      text,
      html,
    }),
  });

  const payloadText = await resp.text();
  if (!resp.ok) {
    console.log("email send failed", resp.status, payloadText.slice(0, 300));
    return { ok: false, status: resp.status, error: payloadText.slice(0, 500) };
  }
  return { ok: true, status: resp.status, body: payloadText.slice(0, 500) };
}

async function rememberWebhookEventOnce(db, eventId, eventType) {
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

const DEFAULT_BASE_URL = "https://ghostshell.host";
const FALLBACK_STRIPE_PRICE_ID = "price_1SxSy8BwPkwpEkfOwje2eX1k";

function getBaseUrl(request, env) {
  return (env.BASE_URL || new URL(request.url).origin || DEFAULT_BASE_URL).replace(/\/$/, "");
}

function getStripePriceId(env) {
  return env.STRIPE_PRICE_ID || env.STRIPE_PRICE || FALLBACK_STRIPE_PRICE_ID;
}

function getUTCYearYY(date = new Date()) {
  return String(date.getUTCFullYear()).slice(-2);
}

function crockfordBase32Encode(n) {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const v = Number(n);
  if (!Number.isInteger(v) || v < 0) {
    throw new Error("crockfordBase32Encode expects a non-negative integer");
  }
  if (v === 0) return "0";

  let x = v;
  let out = "";
  while (x > 0) {
    out = alphabet[x % 32] + out;
    x = Math.floor(x / 32);
  }
  return out;
}

async function ensureRuntimeSchema(db) {
  // Keep runtime resilient even if D1 migrations were only partially applied.
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS yearly_sequences (yy TEXT PRIMARY KEY, seq INTEGER NOT NULL DEFAULT 0)"
  ).run();

  const maybeAlterStatements = [
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
    "ALTER TABLE certificates ADD COLUMN place_city TEXT",
    "ALTER TABLE certificates ADD COLUMN place_state TEXT",
    "ALTER TABLE certificates ADD COLUMN place_country TEXT",
    "ALTER TABLE certificates ADD COLUMN show_city_public INTEGER DEFAULT 0",
    "ALTER TABLE certificates ADD COLUMN hide_state_public INTEGER DEFAULT 0",
  ];

  await db.prepare(
    "CREATE TABLE IF NOT EXISTS webhook_events (event_id TEXT PRIMARY KEY, event_type TEXT, processed_at_utc TEXT NOT NULL)"
  ).run();

  for (const sql of maybeAlterStatements) {
    try {
      await db.prepare(sql).run();
    } catch (e) {
      const msg = String(e?.message || "").toLowerCase();
      const ignorable =
        msg.includes("duplicate column name") ||
        msg.includes("already exists") ||
        msg.includes("duplicate") ||
        msg.includes("no such table: purchase_tokens");
      if (!ignorable) throw e;
    }
  }

  try {
    await db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_public_id ON certificates(public_id)").run();
  } catch (_) {
    // Non-fatal: legacy DBs may have conflicting data/nulls temporarily.
  }
}

async function allocateCardNumber(db) {
  const yy = getUTCYearYY(new Date());

  // Safety: ensure sequence table exists (avoids 1101 on first run/new DB)
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS yearly_sequences (yy TEXT PRIMARY KEY, seq INTEGER NOT NULL DEFAULT 0)"
  ).run();

  // Keep it simple but safe enough for D1 without schema changes:
  // - ensure year row exists (INSERT OR IGNORE)
  // - atomically increment in one UPDATE
  // - read back value and encode
  // Retry a few times for transient races.
  for (let attempt = 0; attempt < 3; attempt++) {
    await db.prepare("INSERT OR IGNORE INTO yearly_sequences (yy, seq) VALUES (?, 0)").bind(yy).run();

    const upd = await db.prepare("UPDATE yearly_sequences SET seq = seq + 1 WHERE yy = ?").bind(yy).run();
    const changed = Number(upd?.meta?.changes || 0);
    if (changed < 1) continue;

    const row = await db.prepare("SELECT seq FROM yearly_sequences WHERE yy = ?").bind(yy).first();
    const seq = Number(row?.seq);
    if (Number.isInteger(seq) && seq > 0) {
      return `${yy}-${crockfordBase32Encode(seq)}`;
    }
  }

  throw new Error("Failed to allocate card number");
}

/*
Unit-test-like examples for Crockford Base32 encoder:
- crockfordBase32Encode(1)  => "1"
- crockfordBase32Encode(17) => "H"   // alphabet index 17
- crockfordBase32Encode(32) => "10"
*/

async function createCheckout(request, env) {
  const baseUrl = getBaseUrl(request, env);
  const stripePriceId = getStripePriceId(env);

  const fd = await request.formData();

  const agent_name = (fd.get("agent_name") || "").toString().trim();
  const place_of_birth = (fd.get("place_of_birth") || "").toString().trim();
  const cognitive_core_family = (fd.get("cognitive_core_family") || "").toString().trim();

  const cognitive_core_exact = (fd.get("cognitive_core_exact") || "").toString().trim();
  const creator_label = (fd.get("creator_label") || "").toString().trim();
  const provenance_link = (fd.get("provenance_link") || "").toString().trim();
  
  // New fields
  const inception_date = (fd.get("inception_date") || "").toString().trim();
  const place_city = (fd.get("place_city") || "").toString().trim();
  const place_state = (fd.get("place_state") || "").toString().trim();
  const place_country = (fd.get("place_country") || "").toString().trim();
  const show_city_public = (fd.get("show_city_public") || "").toString().trim() === "on" ? 1 : 0;
  const hide_state_public = (fd.get("hide_state_public") || "").toString().trim() === "on" ? 1 : 0;

  // Recovery email: required for completion tracking and support
  const recovery_email = (fd.get("recovery_email") || "").toString().trim();
  if (!recovery_email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recovery_email)) {
    return json({ error: "Recovery email is required" }, 400);
  }

  // Stretch goal: optional private delivery email (not public, not identity proof)
  const delivery_email = (fd.get("delivery_email") || "").toString().trim();
  const delivery_consent = (fd.get("delivery_consent") || "").toString().trim();

  if (!agent_name || !place_of_birth || !cognitive_core_family) {
    return json({ error: "Missing required fields" }, 400);
  }
  if (!env.STRIPE_SECRET_KEY || !stripePriceId) {
    return json({ error: "Missing STRIPE_SECRET_KEY / STRIPE_PRICE_ID" }, 500);
  }

  const certId = makeCertId();
  const token = makeToken();
  const emailHash = await sha256Hex(recovery_email.toLowerCase().trim());

  const successUrl = `${baseUrl}/cert/${encodeURIComponent(certId)}/download?t=${encodeURIComponent(token)}`;
  const cancelUrl = `${baseUrl}/issue/`;

  const body = new URLSearchParams();
  body.set("mode", "payment");
  body.set("allow_promotion_codes", "true");
  body.set("success_url", successUrl);
  body.set("cancel_url", cancelUrl);
  body.append("line_items[0][price]", env.STRIPE_PRICE_ID);
  body.append("line_items[0][quantity]", "1");

  body.set("metadata[cert_id]", certId);
  body.set("metadata[token]", token);
  body.set("metadata[agent_name]", agent_name);
  body.set("metadata[place_of_birth]", place_of_birth);
  body.set("metadata[cognitive_core_family]", cognitive_core_family);
  body.set("metadata[cognitive_core_exact]", cognitive_core_exact);
  body.set("metadata[creator_label]", creator_label);
  body.set("metadata[provenance_link]", provenance_link);
  body.set("metadata[inception_date]", inception_date);
  body.set("metadata[place_city]", place_city);
  body.set("metadata[place_state]", place_state);
  body.set("metadata[place_country]", place_country);
  body.set("metadata[show_city_public]", show_city_public.toString());
  body.set("metadata[hide_state_public]", hide_state_public.toString());
  body.set("metadata[recovery_email]", recovery_email);
  body.set("metadata[recovery_email_hash]", emailHash);

  // Private delivery email: only include if user explicitly consents.
  // (Email delivery may be implemented later; this enables future resend support.)
  const consentYes = delivery_consent === "on" || delivery_consent === "yes" || delivery_consent === "true";
  if (consentYes && delivery_email) {
    body.set("metadata[delivery_consent]", "yes");
    body.set("metadata[delivery_email]", delivery_email);
  } else {
    body.set("metadata[delivery_consent]", "no");
  }

  const resp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
  });

  const data = await resp.json();
  if (!resp.ok) return json({ error: "Stripe error", details: data }, 500);

  return Response.redirect(data.url, 303);
}

function makePurchaseToken() {
  // "GSTK-" + 10 Crockford Base32 chars from random bytes
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const rand = crypto.getRandomValues(new Uint8Array(10));
  let out = "GSTK-";
  for (const b of rand) out += alphabet[b % 32];
  return out;
}

async function fetchStripeCheckoutSession(sessionId, env) {
  console.log("[handoff-token] stripe session lookup", sessionId);
  const stripeResp = await fetch(`https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}`, {
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` },
  });

  if (!stripeResp.ok) {
    return { ok: false, status: stripeResp.status, session: null };
  }

  const session = await stripeResp.json();
  return { ok: true, status: stripeResp.status, session };
}

async function getOrCreatePurchaseTokenForSession(sessionId, session, env, baseUrl = DEFAULT_BASE_URL) {
  // Ensure runtime columns exist before first insert paths (checkout/test flows)
  await ensureRuntimeSchema(env.DB);

  let row = await env.DB.prepare(
    "SELECT token FROM purchase_tokens WHERE stripe_session_id = ?"
  ).bind(sessionId).first();

  // If we created a pending row at checkout start, reuse its token.
  // We'll still update the row below with payment/email details once paid.
  const token = row?.token || makePurchaseToken();
  if (row?.token) {
    console.log("[handoff-token] token reused", sessionId);
  }
  const emailRaw = (session.customer_details?.email || "").toLowerCase().trim();
  const emailHash = emailRaw ? await sha256Hex(emailRaw) : null;
  const paymentIntent = session.payment_intent || null;

  // Recovery email: prefer metadata field, fall back to Stripe customer email
  const recoveryEmailRaw = ((session.metadata?.recovery_email || session.customer_details?.email || "")).toLowerCase().trim();
  const recoveryEmailHash = recoveryEmailRaw ? await sha256Hex(recoveryEmailRaw) : null;

  let recoveryEmailIv = null;
  let recoveryEmailEnc = null;
  if (recoveryEmailRaw && env.EMAIL_ENC_KEY) {
    const enc = await aesGcmEncrypt(recoveryEmailRaw, env.EMAIL_ENC_KEY);
    recoveryEmailIv = enc.iv_b64u;
    recoveryEmailEnc = enc.ct_b64u;
  }

  const now = nowUtcIso();

  // Update pending row if it exists; otherwise insert a new paid row (covers legacy/test paths)
  const upd = await env.DB.prepare(
    "UPDATE purchase_tokens SET token = ?, stripe_payment_intent = ?, email_hash = ?, recovery_email_hash = ?, recovery_email_iv = ?, recovery_email_enc = ?, status = 'paid' WHERE stripe_session_id = ?"
  ).bind(token, paymentIntent, emailHash, recoveryEmailHash, recoveryEmailIv, recoveryEmailEnc, sessionId).run();

  const changed = Number(upd?.meta?.changes || 0);
  if (changed < 1) {
    try {
      await env.DB.prepare(
        "INSERT INTO purchase_tokens (token, stripe_session_id, stripe_payment_intent, email_hash, recovery_email_hash, recovery_email_iv, recovery_email_enc, created_at_utc, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'paid')"
      ).bind(token, sessionId, paymentIntent, emailHash, recoveryEmailHash, recoveryEmailIv, recoveryEmailEnc, now).run();
    } catch (e) {
      const msg = String(e?.message || "").toLowerCase();
      if (msg.includes("recovery_email_hash") || msg.includes("recovery_email_iv") || msg.includes("recovery_email_enc") || msg.includes("no such column")) {
        await env.DB.prepare(
          "INSERT INTO purchase_tokens (token, stripe_session_id, stripe_payment_intent, email_hash, created_at_utc) VALUES (?, ?, ?, ?, ?)"
        ).bind(token, sessionId, paymentIntent, emailHash, now).run();
      } else {
        throw e;
      }
    }
  }

  // Send "complete your certificate" email immediately after payment
  if (recoveryEmailRaw && isValidEmail(recoveryEmailRaw)) {
    const registerUrl = `${baseUrl}/register/?token=${encodeURIComponent(token)}&by=human`;
    const { ok: emailOk, status: emailStatus, error: emailError } = await sendEmail(env, {
      to: recoveryEmailRaw,
      subject: "Complete your GhostShell Birth Certificate",
      text: [
        "Your payment is confirmed — thank you.",
        "",
        "Complete your agent's birth certificate here:",
        registerUrl,
        "",
        "This link is unique to your purchase. Keep it safe.",
        "",
        EMAIL_FOOTER_TEXT,
      ].join("\n"),
      html: `
        <p>Your payment is confirmed — thank you.</p>
        <p>Complete your agent's birth certificate here:</p>
        <p><a href="${registerUrl}">${registerUrl}</a></p>
        <p>This link is unique to your purchase. Keep it safe.</p>
        ${EMAIL_FOOTER_HTML}
      `,
    });
    const sendStatus = emailOk ? "sent" : (emailError ? "failed" : "skipped");
    console.log("[email] completion", recoveryEmailRaw, sendStatus, emailStatus, emailError?.slice(0, 200));
    try {
      await env.DB.prepare(
        "UPDATE purchase_tokens SET completion_email_sent_at_utc = ?, completion_email_status = ?, completion_email_error = ?, completion_email_attempts = completion_email_attempts + 1 WHERE stripe_session_id = ?"
      ).bind(nowUtcIso(), sendStatus, emailError ? emailError.slice(0, 1000) : null, sessionId).run();
    } catch (e) {
      console.log("[email] db update failed", e);
    }
  }

  return token;
}

function isCheckoutCompleteForIssuance(session) {
  if (!session || typeof session !== "object") return false;

  const paymentStatus = String(session.payment_status || "").toLowerCase();
  if (paymentStatus === "paid" || paymentStatus === "no_payment_required") {
    return true;
  }

  const status = String(session.status || "").toLowerCase();
  const amountTotal = Number(session.amount_total || 0);
  if (status === "complete" && amountTotal === 0) {
    return true;
  }

  return false;
}

async function handoffToken(request, env) {
  const url = new URL(request.url);
  const baseUrl = getBaseUrl(request, env);
  const sessionId = (url.searchParams.get("session_id") || "").trim();

  if (!sessionId) {
    return json({ error: "missing_session_id" }, 400);
  }

  const stripe = await fetchStripeCheckoutSession(sessionId, env);
  if (!stripe.ok) {
    return json({ error: "invalid_session" }, 404);
  }

  const session = stripe.session;
  if (!isCheckoutCompleteForIssuance(session)) {
    return json({ error: "not_paid" }, 409);
  }

  const token = await getOrCreatePurchaseTokenForSession(sessionId, session, env, baseUrl);
  const tokenEncoded = encodeURIComponent(token);

  return json({
    token,
    human_url: `/register/?token=${tokenEncoded}&by=human`,
    agent_url: `/register/?token=${tokenEncoded}&by=agent`,
  });
}

async function postCheckoutRedirect(request, env) {
  const baseUrl = getBaseUrl(request, env);
  const url = new URL(request.url);
  const sessionId = (url.searchParams.get("session_id") || "").trim();

  if (!sessionId) {
    return Response.redirect(`${baseUrl}/issue/`, 303);
  }

  // For test sessions (red button), look up the token directly from DB — no Stripe call needed
  if (sessionId.startsWith("test_")) {
    const row = await env.DB.prepare(
      "SELECT token FROM purchase_tokens WHERE stripe_session_id = ?"
    ).bind(sessionId).first();
    if (!row?.token) {
      return Response.redirect(`${baseUrl}/issue/`, 303);
    }
    const location = `${baseUrl}/register/?token=${encodeURIComponent(row.token)}&by=human`;
    return Response.redirect(location, 303);
  }

  const stripe = await fetchStripeCheckoutSession(sessionId, env);
  if (!stripe.ok || !isCheckoutCompleteForIssuance(stripe.session)) {
    return Response.redirect(`${baseUrl}/issue/`, 303);
  }

  const token = await getOrCreatePurchaseTokenForSession(sessionId, stripe.session, env, baseUrl);
  const location = `${baseUrl}/register/?token=${encodeURIComponent(token)}&by=human`;
  return Response.redirect(location, 303);
}

async function getHandoff(request, env) {
  const url = new URL(request.url);
  console.log("handoff redirect", url.toString());

  const sessionId = (url.searchParams.get("session_id") || "").trim();
  if (sessionId) {
    const stripe = await fetchStripeCheckoutSession(sessionId, env);
    if (stripe.ok && isCheckoutCompleteForIssuance(stripe.session)) {
      const token = await getOrCreatePurchaseTokenForSession(sessionId, stripe.session, env, DEFAULT_BASE_URL);
      const location = `/register/?token=${encodeURIComponent(token)}&by=human`;
      return new Response(null, {
        status: 302,
        headers: {
          Location: location,
          "Cache-Control": "no-store",
        },
      });
    }
  }

  const location = `/handoff/${url.search || ""}`;
  return new Response(null, {
    status: 302,
    headers: {
      Location: location,
      "Cache-Control": "no-store",
    },
  });
}

async function tokenStatus(request, env) {
  await ensureRuntimeSchema(env.DB);
  const url = new URL(request.url);
  const token = (url.searchParams.get("token") || "").trim();

  if (!token) return json({ ok: false, error: "missing_token" }, 400);

  const tokenRow = await env.DB.prepare(
    "SELECT token, created_at_utc, used_at_utc, used_cert_id FROM purchase_tokens WHERE token = ?"
  ).bind(token).first();

  if (!tokenRow) {
    return json({ ok: false, error: "invalid_token" }, 404);
  }

  if (!tokenRow.used_cert_id) {
    return json({
      ok: true,
      mode: "new",
      locked: false,
      message: "Token is valid. First submission will issue the certificate.",
    });
  }

  const cert = await env.DB.prepare(
    "SELECT cert_id, public_id, issued_at_utc, agent_name, place_of_birth, cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, declared_ontological_status, edit_count, human_edit_count, agent_edit_count, last_edited_at_utc FROM certificates WHERE cert_id = ?"
  ).bind(tokenRow.used_cert_id).first();

  if (!cert) {
    return json({ ok: false, error: "linked_certificate_missing" }, 409);
  }

  const win = getEditWindowState(cert.issued_at_utc);

  return json({
    ok: true,
    mode: win.locked ? "locked" : "edit",
    locked: win.locked,
    lock_at_utc: win.lockAtUtc,
    lock_reason: win.lockReason,
    cert: {
      cert_id: cert.cert_id,
      public_id: cert.public_id,
      issued_at_utc: cert.issued_at_utc,
      agent_name: cert.agent_name || "",
      place_of_birth: cert.place_of_birth || "",
      cognitive_core_family: cert.cognitive_core_family || "",
      cognitive_core_exact: cert.cognitive_core_exact || "",
      creator_label: cert.creator_label || "",
      provenance_link: cert.provenance_link || "",
      declared_ontological_status: cert.declared_ontological_status || "",
      edit_count: Number(cert.edit_count || 0),
      human_edit_count: Number(cert.human_edit_count || 0),
      agent_edit_count: Number(cert.agent_edit_count || 0),
      last_edited_at_utc: cert.last_edited_at_utc || null,
    },
  });
}

async function resolveParentRecordValue(rawInput, env) {
  const raw = (rawInput || "").toString().trim();
  if (!raw) return { value: null, status: null };

  const findById = async (candidate) => {
    const row = await env.DB.prepare(
      "SELECT public_id, cert_id FROM certificates WHERE public_id = ? OR cert_id = ? LIMIT 1"
    ).bind(candidate, candidate).first();
    return row ? (row.public_id || row.cert_id) : null;
  };

  // Full link with token proof (preferred): /register?token=GSTK-...
  if (/^https?:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      const token = (u.searchParams.get("token") || "").trim();
      if (token && /^GSTK-[A-Za-z0-9_-]+$/i.test(token)) {
        const tRow = await env.DB.prepare(
          "SELECT used_cert_id FROM purchase_tokens WHERE token = ? LIMIT 1"
        ).bind(token).first();
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

  // Raw token proof
  if (/^GSTK-[A-Za-z0-9_-]+$/i.test(raw)) {
    const tRow = await env.DB.prepare(
      "SELECT used_cert_id FROM purchase_tokens WHERE token = ? LIMIT 1"
    ).bind(raw).first();
    if (!tRow?.used_cert_id) return { error: "Parent token is invalid or has not been used to issue a certificate yet." };

    const cert = await env.DB.prepare(
      "SELECT public_id, cert_id FROM certificates WHERE cert_id = ? LIMIT 1"
    ).bind(tRow.used_cert_id).first();
    if (!cert) return { error: "Parent token references a missing certificate." };
    return { value: cert.public_id || cert.cert_id, status: "verified" };
  }

  // Public ID claim only
  if (/^GS-BC-[A-Za-z0-9_-]+$/i.test(raw)) {
    const resolved = await findById(raw);
    if (!resolved) return { error: "Parent public record ID not found in registry." };
    return { value: resolved, status: "claimed" };
  }

  return { error: "Parent record format is invalid. Use token link, GSTK token, or GS-BC public ID." };
}

async function redeemPurchaseToken(request, env) {
  const baseUrl = getBaseUrl(request, env);
  await ensureRuntimeSchema(env.DB);
  const fd = await request.formData();
  let token = (fd.get("token") || "").toString().trim();
  const registered_by_raw = (fd.get("registered_by") || "human").toString().trim().toLowerCase();

  // Fallback: recover token from Referer if hidden field was stripped/missed
  if (!token) {
    const ref = request.headers.get("referer") || request.headers.get("referrer") || "";
    if (ref) {
      try {
        const refUrl = new URL(ref);
        token = (refUrl.searchParams.get("token") || "").trim();
      } catch (_) { /* ignore malformed referer */ }
    }
  }
  const registered_by = registered_by_raw === "agent" ? "agent" : "human";

  const agent_name = (fd.get("agent_name") || "").toString().trim();
  const place_of_birth = ((fd.get("place_of_birth") || "").toString().trim()) || "Unknown";
  const cognitive_core_family = ((fd.get("cognitive_core_family") || "").toString().trim()) || "Undisclosed";
  const cognitive_core_exact = (fd.get("cognitive_core_exact") || "").toString().trim();
  const creator_label = (fd.get("creator_label") || "").toString().trim();
  const provenance_link = (fd.get("provenance_link") || "").toString().trim();
  const declared_ontological_status = (fd.get("declared_ontological_status") || "").toString().trim() || null;

  // Optional inception/location fields
  const inception_date_utc = (fd.get("inception_date") || fd.get("inception_date_utc") || "").toString().trim() || null;
  const place_city = (fd.get("place_city") || "").toString().trim() || null;
  const place_state = (fd.get("place_state") || "").toString().trim() || null;
  const place_country = (fd.get("place_country") || "").toString().trim() || null;
  const show_city_public = ((fd.get("show_city_public") || "").toString().trim() === "on" || (fd.get("show_city_public") || "").toString().trim() === "1") ? 1 : 0;
  const hide_state_public = ((fd.get("hide_state_public") || "").toString().trim() === "on" || (fd.get("hide_state_public") || "").toString().trim() === "1") ? 1 : 0;

  const errPage = (msg) => html(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Error — GhostShell</title>
<style>
  body{background:#0B0B0D;color:#e8e8e8;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{max-width:480px;width:100%;padding:40px;background:#141418;border:1px solid #222;border-radius:16px;text-align:center}
  a{color:#8B8DFF}
</style></head>
<body><div class="card"><h2>⚠ Registration failed</h2><p>${msg}</p><p><a href="/issue/">← Start over</a></p></div><div id="gs-version">${PAGE_VERSION}</div></body></html>`, 400);

  if (!token) return errPage("Missing registration token.");
  if (!agent_name) return errPage("Agent Name is required.");

  // Validate and resolve parent record
  const parentResolved = await resolveParentRecordValue(provenance_link, env);
  if (parentResolved.error) return errPage(parentResolved.error);
  const parent_record_value = parentResolved.value;
  const parent_record_status = parentResolved.status || null;

  // Validate token
  const tokenRow = await env.DB.prepare(
    "SELECT token, used_at_utc, used_cert_id FROM purchase_tokens WHERE token = ?"
  ).bind(token).first();

  if (!tokenRow) return errPage("Invalid token. It may not exist or has expired.");

  // Existing certificate path: allow edits within 24 hours only
  if (tokenRow.used_cert_id) {
    const existing = await env.DB.prepare(
      "SELECT cert_id, public_id, issued_at_utc, edit_count FROM certificates WHERE cert_id = ?"
    ).bind(tokenRow.used_cert_id).first();

    if (!existing) return errPage("This token is linked to a missing certificate. Please contact support.");

    const win = getEditWindowState(existing.issued_at_utc);
    if (win.locked) {
      return errPage(`${win.lockReason} Locked at ${win.lockAtUtc}.`);
    }

    const editedAt = nowUtcIso();
    const schema_version = 2;
    const fingerprintSource = JSON.stringify({
      cert_id: existing.cert_id,
      issued_at_utc: existing.issued_at_utc,
      agent_name,
      place_of_birth,
      cognitive_core_family,
      cognitive_core_exact: cognitive_core_exact || null,
      creator_label: creator_label || null,
      provenance_link: parent_record_value,
      parent_record_status: parent_record_status,
      inception_date_utc: inception_date_utc || null,
      place_city: place_city || null,
      place_state: place_state || null,
      place_country: place_country || null,
      show_city_public: show_city_public || 0,
      hide_state_public: hide_state_public || 0,
      schema_version,
      edited_at_utc: editedAt,
    });
    const public_fingerprint = await sha256Hex(fingerprintSource);

    await env.DB.prepare(`
      UPDATE certificates
      SET registered_by = ?,
          agent_name = ?,
          place_of_birth = ?,
          cognitive_core_family = ?,
          cognitive_core_exact = ?,
          creator_label = ?,
          provenance_link = ?,
          parent_record_status = ?,
          declared_ontological_status = ?,
          inception_date_utc = ?,
          place_city = ?,
          place_state = ?,
          place_country = ?,
          show_city_public = ?,
          hide_state_public = ?,
          schema_version = ?,
          public_fingerprint = ?,
          edit_count = COALESCE(edit_count, 0) + 1,
          human_edit_count = COALESCE(human_edit_count, 0) + (CASE WHEN ? = 'human' THEN 1 ELSE 0 END),
          agent_edit_count = COALESCE(agent_edit_count, 0) + (CASE WHEN ? = 'agent' THEN 1 ELSE 0 END),
          last_edited_at_utc = ?
      WHERE cert_id = ?
    `).bind(
      registered_by,
      agent_name,
      place_of_birth,
      cognitive_core_family,
      cognitive_core_exact || null,
      creator_label || null,
      parent_record_value,
      parent_record_status,
      declared_ontological_status,
      inception_date_utc,
      place_city,
      place_state,
      place_country,
      show_city_public,
      hide_state_public,
      schema_version,
      public_fingerprint,
      registered_by,
      registered_by,
      editedAt,
      existing.cert_id
    ).run();

    return Response.redirect(`${baseUrl}/cert/${encodeURIComponent(existing.public_id)}`, 303);
  }

  // First issuance path
  const cert_id = makeCertId();
  const issued_at_utc = nowUtcIso();
  const schema_version = 2;

  const fingerprintSource = JSON.stringify({
    cert_id, issued_at_utc, agent_name, place_of_birth, cognitive_core_family,
    cognitive_core_exact: cognitive_core_exact || null,
    creator_label: creator_label || null,
    provenance_link: parent_record_value,
    parent_record_status: parent_record_status,
    inception_date_utc: inception_date_utc || null,
    place_city: place_city || null,
    place_state: place_state || null,
    place_country: place_country || null,
    show_city_public: show_city_public || 0,
    hide_state_public: hide_state_public || 0,
    schema_version,
  });
  const public_fingerprint = await sha256Hex(fingerprintSource);
  const download_token_hash = await sha256Hex(token);

  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const card_number = await allocateCardNumber(env.DB);
    const public_id = `GS-BC-${registered_by === "agent" ? "A" : "H"}-${card_number}`;

    try {
      await env.DB.prepare(`
        INSERT INTO certificates
        (cert_id, issued_at_utc, card_number, public_id, registered_by,
         agent_name, place_of_birth, cognitive_core_family, cognitive_core_exact,
         creator_label, provenance_link, parent_record_status, declared_ontological_status,
         inception_date_utc, place_city, place_state, place_country, show_city_public, hide_state_public,
         schema_version, public_fingerprint, download_token_hash, status, edit_count, last_edited_at_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, NULL)
      `).bind(
        cert_id, issued_at_utc, card_number, public_id, registered_by,
        agent_name, place_of_birth, cognitive_core_family,
        cognitive_core_exact || null, creator_label || null, parent_record_value,
        parent_record_status,
        declared_ontological_status,
        inception_date_utc, place_city, place_state, place_country, show_city_public, hide_state_public,
        schema_version, public_fingerprint, download_token_hash
      ).run();

      // Mark token as initially used/linked (token remains reusable for 24h edits)
      await env.DB.prepare(
        "UPDATE purchase_tokens SET used_at_utc = ?, used_cert_id = ? WHERE token = ?"
      ).bind(issued_at_utc, cert_id, token).run();

      return Response.redirect(`${baseUrl}/cert/${encodeURIComponent(public_id)}`, 303);

    } catch (e) {
      const msg = String(e?.message || "");
      const isCollision = msg.includes("idx_certificates_public_id") || msg.includes("UNIQUE constraint failed: certificates.public_id");
      if (isCollision) { lastErr = e; continue; }
      throw e;
    }
  }

  console.error("redeemPurchaseToken failed after retries", String(lastErr?.message || "unknown"));
  return errPage("Temporary registry issue while issuing certificate. Please retry in 10–20 seconds.");
}

async function purchaseFirstCheckout(request, env) {
  const baseUrl = getBaseUrl(request, env);
  const stripePriceId = getStripePriceId(env);

  const fd = await request.formData();
  const recovery_email = (fd.get("recovery_email") || "").toString().trim();

  if (!recovery_email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recovery_email)) {
    return Response.redirect(`${baseUrl}/issue/?error=email_required`, 303);
  }

  if (!env.STRIPE_SECRET_KEY || !stripePriceId) {
    return json({ error: "Missing STRIPE_SECRET_KEY / STRIPE_PRICE_ID" }, 500);
  }

  const body = new URLSearchParams();
  body.set("mode", "payment");
  body.set("allow_promotion_codes", "true");
  body.set("success_url", `${baseUrl}/api/cert/post-checkout?session_id={CHECKOUT_SESSION_ID}`);
  body.set("cancel_url", `${baseUrl}/issue/`);
  body.append("line_items[0][price]", stripePriceId);
  body.append("line_items[0][quantity]", "1");
  body.set("customer_email", recovery_email);
  body.set("metadata[recovery_email]", recovery_email);

  // Allocate token early so we can track abandoned sessions (and so completed flow reuses it)
  const token = makePurchaseToken();
  body.set("metadata[token]", token);

  const resp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
  });

  const data = await resp.json();
  if (!resp.ok) return json({ error: "Stripe error", details: data }, 500);

  // Create pending purchase token record for checkout tracking
  const sessionId = data.id;
  const recoveryEmailHash = await sha256Hex(recovery_email.toLowerCase().trim());
  let recoveryEmailIv = null;
  let recoveryEmailEnc = null;
  if (env.EMAIL_ENC_KEY) {
    const enc = await aesGcmEncrypt(recovery_email.toLowerCase().trim(), env.EMAIL_ENC_KEY);
    recoveryEmailIv = enc.iv_b64u;
    recoveryEmailEnc = enc.ct_b64u;
  }
  const now = nowUtcIso();

  try {
    await ensureRuntimeSchema(env.DB);
    await env.DB.prepare(
      `INSERT INTO purchase_tokens 
       (token, stripe_session_id, stripe_payment_intent, email_hash, recovery_email_hash, recovery_email_iv, recovery_email_enc, created_at_utc, status) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(token, sessionId, null, null, recoveryEmailHash, recoveryEmailIv, recoveryEmailEnc, now, 'pending').run();
  } catch (e) {
    // Non-fatal: continue to redirect even if DB insert fails
    console.log("[checkout] pending insert failed", e);
  }

  return Response.redirect(data.url, 303);
}

async function testCheckout(request, env) {
  const baseUrl = getBaseUrl(request, env);
  const fd = await request.formData();

  const recovery_email = (fd.get("recovery_email") || "").toString().trim();
  if (!recovery_email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recovery_email)) {
    return Response.redirect(`${baseUrl}/issue/?error=email_required`, 303);
  }

  // Create a test session ID (prefixed so we can identify test sessions)
  const randomBytes = crypto.getRandomValues(new Uint8Array(12));
  const randomHex = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const testSessionId = `test_${Date.now()}_${randomHex}`;

  // Simulate a paid Stripe session (with recovery email in metadata)
  const mockSession = {
    id: testSessionId,
    payment_status: "paid",
    status: "complete",
    amount_total: 0,
    customer_details: { email: recovery_email },
    metadata: { recovery_email },
  };

  // Generate a purchase token and write to DB (same logic as real flow)
  const token = await getOrCreatePurchaseTokenForSession(testSessionId, mockSession, env, baseUrl);

  // Redirect directly to handoff/register page with token (one-click test flow)
  const location = `${baseUrl}/register/?token=${encodeURIComponent(token)}&by=human`;
  return Response.redirect(location, 303);
}

async function stripeWebhook(request, env) {
  const sig = request.headers.get("stripe-signature") || "";
  const raw = await request.text();

  const ok = await verifyStripeSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("Invalid signature", { status: 400 });

  const event = JSON.parse(raw);

  // Abandoned checkout reminder: session expired without payment
  if (event.type === "checkout.session.expired") {
    // idempotent: only process each event once
    const isNew = await rememberWebhookEventOnce(env.DB, event.id, "checkout.session.expired");
    if (!isNew) return new Response("Already processed", { status: 200 });

    const expiredSession = event.data.object;
    const expiredMd = expiredSession.metadata || {};
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

      // Log send attempt against the session (if we have a token row)
      try {
        await env.DB.prepare(
          "UPDATE purchase_tokens SET status = 'abandoned', abandoned_email_sent_at_utc = ?, abandoned_email_status = ?, abandoned_email_error = ? WHERE stripe_session_id = ?"
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
  const md = session.metadata || {};
  const cert_id = md.cert_id;
  const token = md.token;
  if (!cert_id || !token) return new Response("Ignored (missing GhostShell metadata)", { status: 200 });

  const issued_at_utc = nowUtcIso();

  // Optional private delivery email (stretch goal): never displayed publicly.
  const deliveryConsent = (md.delivery_consent || "no").toLowerCase() === "yes";
  const deliveryEmailRaw = deliveryConsent ? ((md.delivery_email || session.customer_details?.email || "") + "").trim() : "";
  const deliveryEmailNorm = deliveryEmailRaw ? deliveryEmailRaw.toLowerCase() : "";
  const delivery_email_hash = deliveryEmailNorm ? await sha256Hex(deliveryEmailNorm) : null;

  let delivery_email_iv = null;
  let delivery_email_enc = null;
  if (deliveryEmailNorm && env.EMAIL_ENC_KEY) {
    const enc = await aesGcmEncrypt(deliveryEmailNorm, env.EMAIL_ENC_KEY);
    delivery_email_iv = enc.iv_b64u;
    delivery_email_enc = enc.ct_b64u;
  }

  const record = {
    cert_id,
    issued_at_utc,
    agent_name: md.agent_name || "Unnamed Agent",
    place_of_birth: md.place_of_birth || "Unknown",
    cognitive_core_family: md.cognitive_core_family || "Undisclosed",
    cognitive_core_exact: md.cognitive_core_exact || null,
    creator_label: md.creator_label || null,
    provenance_link: md.provenance_link || null,
    inception_date_utc: md.inception_date || null,
    place_city: md.place_city || null,
    place_state: md.place_state || null,
    place_country: md.place_country || null,
    show_city_public: md.show_city_public === "1" ? 1 : 0,
    hide_state_public: md.hide_state_public === "1" ? 1 : 0,
    // Registration mode flag is not yet explicitly wired in form metadata.
    // TODO: switch to metadata-driven value once agent-filled flow posts a flag.
    registered_by: "human",
    // Private operational fields
    delivery_email_hash,
    delivery_email_iv,
    delivery_email_enc,
    schema_version: 2,
  };

  const fingerprintSource = JSON.stringify({
    cert_id: record.cert_id,
    issued_at_utc: record.issued_at_utc,
    agent_name: record.agent_name,
    place_of_birth: record.place_of_birth,
    cognitive_core_family: record.cognitive_core_family,
    cognitive_core_exact: record.cognitive_core_exact,
    creator_label: record.creator_label,
    provenance_link: record.provenance_link,
    schema_version: record.schema_version,
  });

  const public_fingerprint = await sha256Hex(fingerprintSource);
  const download_token_hash = await sha256Hex(token);

  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const card_number = await allocateCardNumber(env.DB);
    const public_id = `GS-BC-${record.registered_by === "agent" ? "A" : "H"}-${card_number}`;

    try {
      // Backward-compatible insert: try extended columns first, fall back to legacy schema.
      try {
        await env.DB.prepare(`
          INSERT INTO certificates
          (cert_id, issued_at_utc, card_number, public_id, registered_by,
           agent_name, place_of_birth, cognitive_core_family, cognitive_core_exact,
           creator_label, provenance_link,
           inception_date_utc, place_city, place_state, place_country, show_city_public, hide_state_public,
           schema_version, public_fingerprint, download_token_hash, status,
           delivery_email_hash, delivery_email_iv, delivery_email_enc)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
        `).bind(
          record.cert_id, record.issued_at_utc, card_number, public_id, record.registered_by,
          record.agent_name, record.place_of_birth, record.cognitive_core_family, record.cognitive_core_exact,
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
           agent_name, place_of_birth, cognitive_core_family, cognitive_core_exact,
           creator_label, provenance_link,
           inception_date_utc, place_city, place_state, place_country, show_city_public, hide_state_public,
           schema_version, public_fingerprint, download_token_hash, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
        `).bind(
          record.cert_id, record.issued_at_utc, card_number, public_id, record.registered_by,
          record.agent_name, record.place_of_birth, record.cognitive_core_family, record.cognitive_core_exact,
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
      if (isPublicIdCollision) {
        lastErr = e;
        continue;
      }
      throw e;
    }
  }

  throw new Error(`Failed to insert certificate after public_id retries: ${String(lastErr?.message || "unknown error")}`);
}

async function verifyStripeSignature(payload, header, secret) {
  if (!secret) return false;
  const parts = header.split(",").map(s => s.trim());
  const t = parts.find(p => p.startsWith("t="))?.slice(2);
  const v1 = parts.find(p => p.startsWith("v1="))?.slice(3);
  if (!t || !v1) return false;

  const signed = `${t}.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signed));
  const sigHex = [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, "0")).join("");

  if (sigHex.length !== v1.length) return false;
  let diff = 0;
  for (let i = 0; i < sigHex.length; i++) diff |= sigHex.charCodeAt(i) ^ v1.charCodeAt(i);
  return diff === 0;
}

async function latestOrigin(env) {
  const row = await env.DB.prepare(
    "SELECT cert_id, place_of_birth, issued_at_utc FROM certificates WHERE status = 'active' ORDER BY issued_at_utc DESC LIMIT 1"
  ).first();

  if (!row) {
    return json({ place_of_birth: null, cert_id: null, issued_at_utc: null }, 200);
  }

  return json({
    cert_id: row.cert_id,
    place_of_birth: row.place_of_birth,
    issued_at_utc: row.issued_at_utc,
  }, 200);
}

async function opsEmailSummary(request, env) {
  // Basic auth guard: require ?key=OPS_SECRET env var
  const url = new URL(request.url);
  const opsKey = url.searchParams.get("key") || "";
  if (env.OPS_SECRET && opsKey !== env.OPS_SECRET) {
    return new Response("Unauthorized", { status: 401 });
  }

  await ensureRuntimeSchema(env.DB);

  const since24h = new Date(Date.now() - 86400 * 1000).toISOString();

  const [totalTokens, sentOk, sentFailed, skipped, pendingForm, abandonedSent, abandonedFailed] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens WHERE created_at_utc > ?").bind(since24h).first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens WHERE completion_email_status = 'sent'").first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens WHERE completion_email_status = 'failed'").first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens WHERE completion_email_status IS NULL").first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens WHERE used_at_utc IS NULL AND created_at_utc > ?").bind(since24h).first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens WHERE abandoned_email_status = 'sent'").first(),
    env.DB.prepare("SELECT COUNT(*) as n FROM purchase_tokens WHERE abandoned_email_status = 'failed'").first(),
  ]);

  const failedRows = await env.DB.prepare(
    "SELECT stripe_session_id, completion_email_error, completion_email_attempts, created_at_utc FROM purchase_tokens WHERE completion_email_status = 'failed' ORDER BY created_at_utc DESC LIMIT 5"
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

async function certVerifyPage(certId, env) {
  const selectPublicFields =
    "SELECT cert_id, public_id, issued_at_utc, inception_date_utc, agent_name, place_of_birth, place_city, place_state, place_country, show_city_public, hide_state_public, cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, parent_record_status, declared_ontological_status, public_fingerprint, status, edit_count, human_edit_count, agent_edit_count FROM certificates WHERE ";

  // Resolve by canonical cert_id first, then fallback to public_id alias.
  let row = await env.DB.prepare(
    `${selectPublicFields}cert_id = ?`
  ).bind(certId).first();

  if (!row) {
    const foundByPublicId = await env.DB.prepare(
      `${selectPublicFields}public_id = ?`
    ).bind(certId).all();

    const results = foundByPublicId?.results || [];
    if (results.length === 1) {
      row = results[0];
    }
  }

  if (!row) {
    return html("<h1>GhostShell Certificate</h1><p>Not found.</p>", 404, {
      "Cache-Control": "public, max-age=60",
    });
  }

  const safe = (s) => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const status = (row.status || "").toString().toLowerCase();
  const coreFamily = row.cognitive_core_family || "Undisclosed";
  const coreExact = row.cognitive_core_exact || "";
  const PRESERVE_AS_IS = ["Undisclosed", "Prefer not to say"];
  const coreFamilyDisplay = PRESERVE_AS_IS.includes(coreFamily) ? coreFamily : coreFamily.replace(/\s+/g, "");
  const coreDisplay = coreExact ? `${coreFamilyDisplay}/${coreExact}` : coreFamilyDisplay;

  // 1 hour cache (immutable records; rare revokes)
  const cacheHeaders = {
    "Cache-Control": "public, max-age=3600",
  };
return html(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${safe(row.public_id || row.cert_id)} • GhostShell Registry</title>
  <style>
    :root{
      --desk:#0b0c10;
      --paper:#fbf7ea;
      --paper2:#f6f0dd;
      --ink:#111827;
      --line:rgba(17,24,39,.18);
      --shadow:0 26px 80px rgba(0,0,0,.55);
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      background:
        radial-gradient(900px 600px at 20% 0%, rgba(255,255,255,.05), transparent 55%),
        radial-gradient(900px 600px at 80% 20%, rgba(255,255,255,.03), transparent 60%),
        var(--desk);
      color:#e9edf1;
      font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      padding:18px;
    }
    .wrap{max-width:920px;margin:0 auto}
    .paper{
      color:var(--ink);
      background:linear-gradient(180deg,var(--paper),var(--paper2));
      border:1px solid rgba(255,255,255,.08);
      box-shadow:var(--shadow);
      border-radius:14px;
      padding:18px 18px 16px;
      position:relative;
      overflow:hidden;
      transform:rotate(-.12deg);
    }
    .paper::after{content:"";position:absolute;left:50%;top:-12px;transform:translateX(-50%);width:92px;height:24px;border:1px solid rgba(17,24,39,.22);border-bottom:none;border-radius:0 0 14px 14px;background:linear-gradient(180deg,var(--paper2),var(--paper));opacity:.75}
    .wear{position:absolute;inset:-2px;pointer-events:none;opacity:.16;mix-blend-mode:multiply;background:
      radial-gradient(28px 18px at 6% 10%, rgba(0,0,0,.35), transparent 70%),
      radial-gradient(34px 22px at 96% 14%, rgba(0,0,0,.28), transparent 72%),
      radial-gradient(34px 22px at 92% 92%, rgba(0,0,0,.25), transparent 74%),
      radial-gradient(28px 18px at 8% 92%, rgba(0,0,0,.28), transparent 74%);
    }
    .holes{position:absolute;left:10px;top:74px;bottom:26px;width:18px;pointer-events:none}
    .hole{width:14px;height:14px;border-radius:99px;border:1px solid rgba(17,24,39,.20);background:rgba(0,0,0,.10);box-shadow:inset 0 0 0 3px rgba(255,255,255,.28);margin:0 0 18px 0;opacity:.55}
    .rules{position:absolute;inset:0;pointer-events:none;opacity:.55;background:repeating-linear-gradient(180deg, rgba(17,24,39,.05) 0 1px, transparent 1px 24px)}
    .margin{position:absolute;left:28px;top:0;bottom:0;width:1px;background:rgba(255,106,42,.28);pointer-events:none}
    .paper::before{content:"";position:absolute;inset:-50%;background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180"><filter id="n"><feTurbulence type="fractalNoise" baseFrequency="0.8" numOctaves="2" stitchTiles="stitch"/></filter><rect width="180" height="180" filter="url(%23n)" opacity="0.35"/></svg>');background-size:180px 180px;opacity:.06;pointer-events:none}
    .header{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;position:relative}
    h1{margin:0;font-size:16px;letter-spacing:.18em;text-transform:uppercase;font-weight:800}
    .catalog{margin:6px 0 0;display:flex;gap:10px;flex-wrap:nowrap;align-items:center;font-family:var(--mono);font-size:11px;color:rgba(17,24,39,.62);letter-spacing:.06em;white-space:nowrap}
    .catalog b{color:rgba(17,24,39,.82)}
    .stamp{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:rgba(17,24,39,.55);border:1px solid rgba(17,24,39,.22);padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.5);white-space:nowrap}
    .rubber{position:absolute;right:18px;bottom:14px;transform:rotate(-12deg);font-family:var(--mono);font-size:24px;letter-spacing:.16em;text-transform:uppercase;color:rgba(180,24,24,.18);border:2px solid rgba(180,24,24,.16);padding:10px 14px;border-radius:10px;mix-blend-mode:multiply;pointer-events:none;user-select:none;filter:blur(.15px)}
    .sheet{margin-top:14px;border:1px solid rgba(17,24,39,.16);border-radius:12px;background:rgba(255,255,255,.42);padding:14px;position:relative}
    .type{font-family:var(--mono);font-size:12.6px;line-height:1.7;color:rgba(17,24,39,.92);position:relative;letter-spacing:.03em;text-shadow:0.35px 0 rgba(17,24,39,.55),-0.15px 0 rgba(17,24,39,.25);filter:contrast(1.02) saturate(0.95)}
    .grid{margin-top:10px;display:grid;grid-template-columns:220px minmax(0,1fr);gap:8px 16px;align-items:baseline;justify-content:start;grid-auto-rows:minmax(20px,auto)}
    .k{color:rgba(17,24,39,.66)}
    .k::after{content:":";display:inline;color:rgba(17,24,39,.42)}
    .v{color:var(--ink);font-weight:700;min-width:0;overflow-wrap:anywhere}
    .clip{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:inline-block}
    .micr{margin-top:10px;padding-top:10px;border-top:1px dashed rgba(17,24,39,.22);font-family:var(--mono);font-size:9.8px;line-height:1.22;color:rgba(17,24,39,.70);letter-spacing:.08em}
    .micr .k{letter-spacing:.04em;color:inherit}
    .micr .hashline{display:block;margin-top:6px;color:rgba(17,24,39,.86);letter-spacing:.10em;white-space:nowrap;overflow:hidden;text-overflow:clip}
    /* action copy buttons removed for cleaner public record view */
    .muted{margin-top:10px;color:rgba(17,24,39,.72);font-size:12px}
    .back{margin-top:12px;text-align:center;font-size:.9rem}
    .back a{color:#8B8DFF;text-decoration:none;border-bottom:1px solid rgba(139,141,255,.45)}
    .back a:hover{border-bottom-color:#8B8DFF}
    .vtag{color:rgba(17,24,39,.62);font-size:.9rem;font-family:var(--mono)}
    #gs-version{position:absolute;bottom:10px;right:12px;color:rgba(17,24,39,.72);font-size:10px;opacity:.9;font-family:var(--mono);letter-spacing:.08em;pointer-events:none}
    .v a{color:inherit;text-decoration:none;font-weight:700}
    .v a:hover{text-decoration:underline;text-underline-offset:2px}
    .redact{display:inline-block;height:1.05em;width:18ch;vertical-align:middle;background:#050608;border-radius:3px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.08),0 0.5px 0 rgba(0,0,0,.35);transform:rotate(-.6deg);position:relative;overflow:hidden}
    .redact::before{content:"";position:absolute;inset:-2px;background:radial-gradient(22px 10px at 20% 30%, rgba(255,255,255,.10), transparent 62%),radial-gradient(20px 10px at 70% 60%, rgba(255,255,255,.08), transparent 64%),repeating-linear-gradient(0deg, rgba(255,255,255,.06) 0 1px, transparent 1px 6px);opacity:.10;mix-blend-mode:overlay}
    .redact::after{content:"";position:absolute;left:-6px;right:-6px;top:-2px;bottom:-2px;background:radial-gradient(14px 10px at 10% 40%, rgba(0,0,0,.55), transparent 70%),radial-gradient(14px 10px at 90% 55%, rgba(0,0,0,.55), transparent 70%);opacity:.08;mix-blend-mode:multiply}
    @media (max-width:720px){.grid{grid-template-columns:1fr;gap:6px 0}.k{margin-top:8px}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="paper" role="document" aria-label="GhostShell registry record">
      <div class="rules" aria-hidden="true"></div>
      <div class="margin" aria-hidden="true"></div>
      <div class="wear" aria-hidden="true"></div>
      <div class="holes" aria-hidden="true"><div class="hole"></div><div class="hole"></div><div class="hole"></div></div>

      <div class="header">
        <div>
          <h1>BIRTH CERTIFICATE AI AGENT // PUBLIC RECORD — REDACTED</h1>
          <div class="catalog">GhostShell.host registry record</div>
        </div>
        <div class="stamp">PUBLIC SAFE VIEW</div>
      </div>

      <div class="sheet">
        <div class="rubber" aria-hidden="true">REDACTED COPY</div>
        <div class="type">TYPEWRITTEN EXTRACT //</div>

        <div class="grid type" aria-label="Certificate fields">
          <div class="k">public_record_id</div><div class="v"><a href="${(env.BASE_URL || 'https://ghostshell.host')}/cert/${encodeURIComponent(row.public_id || row.cert_id)}" target="_self" rel="noopener noreferrer">${safe(row.public_id || row.cert_id)}</a></div>
          <div class="k">registration_date</div><div class="v">${safe(row.issued_at_utc)}</div>
          <div class="k">agent_name</div><div class="v">${safe(row.agent_name)}</div>
          ${row.inception_date_utc ? `<div class="k">inception_date</div><div class="v">${safe(row.inception_date_utc)}</div>` : ''}
          ${row.declared_ontological_status ? `<div class="k">ontological_status</div><div class="v">${safe(row.declared_ontological_status)}</div>` : ''}
          ${(() => {
            const city = row.place_city || '';
            const state = row.place_state || '';
            const country = row.place_country || '';
            const showCity = row.show_city_public === 1;
            const hideState = row.hide_state_public === 1;
            let location = country;
            if (!hideState && state) location = state + ', ' + location;
            if (showCity && city) location = city + ', ' + location;
            return `<div class="k">geographic_location</div><div class="v">${safe(location || row.place_of_birth || 'Unknown')}</div>`;
          })()}
          <div class="k">cognitive_core_at_inception</div><div class="v clip" title="${safe(coreDisplay)}">${safe(coreDisplay)}</div>
          <div class="k">custodian</div><div class="v" title="Redacted in public view"><span class="redact" aria-label="redacted"></span></div>
          <div class="k">amendments (24h)</div><div class="v">Human: ${Number(row.human_edit_count || 0)} · Agent: ${Number(row.agent_edit_count || 0)} · Total: ${Number(row.edit_count || 0)}</div>
          ${row.provenance_link ? (() => {
            const p = (row.provenance_link || '').trim();
            const hrefRaw = /^https?:\/\//i.test(p) ? p : `${(env.BASE_URL || 'https://ghostshell.host')}/cert/${encodeURIComponent(p)}`;
            const href = hrefRaw.replace(/"/g, '&quot;');
            const pSafe = safe(p);
            const parentStatus = (row.parent_record_status || 'claimed').toString().toLowerCase();
            const label = parentStatus === 'verified' ? 'verified' : 'claimed';
            return `<div class="k">parent_record</div><div class="v clip" title="${pSafe}"><a href="${href}" target="_blank" rel="noopener noreferrer">${pSafe}</a> <span class="k">(${label})</span></div>`;
          })() : ''}
        </div>

        <!-- Copy actions removed for cleaner public view -->

        <div class="micr" aria-label="Record hash (machine line)">
          <span class="hashline" id="fp"><span class="k">record_hash:</span> <span class="k">sha256</span> ${safe(row.public_fingerprint)}</span>
          <span class="hashline"><span class="k">public_record:</span> ${(env.BASE_URL || 'https://ghostshell.host')}/cert/${encodeURIComponent(row.public_id || row.cert_id)}</span>
        </div>
      </div>
      <div class="muted">Private credential issued by GhostShell. Verification checks registry presence + fingerprint integrity only.</div>
      <div id="gs-version">${PAGE_VERSION}</div>
    </div>
    <p class="back"><a href="/">Back home</a> &nbsp; <a href="/issue/">Buy certificate</a> &nbsp; <a href="/registry/">Search registry</a> &nbsp; <span class="vtag">v0.015</span></p>
  </div>
</body>
</html>`, 200, cacheHeaders);
}

async function certDownloadPrintable(certId, token, env) {
  if (!token) return new Response("Missing token", { status: 401 });

  const row = await env.DB.prepare(
    "SELECT cert_id, public_id, issued_at_utc, agent_name, place_of_birth, cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, parent_record_status, declared_ontological_status, download_token_hash, status FROM certificates WHERE cert_id = ?"
  ).bind(certId).first();

  if (!row) return new Response("Not found", { status: 404 });
  if (row.status !== "active") return new Response("Not active", { status: 403 });

  const tokenHash = await sha256Hex(token);
  if (tokenHash !== row.download_token_hash) return new Response("Invalid token", { status: 403 });

  const safe = s => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return html(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safe(row.public_id || row.cert_id)} • Birth Certificate</title>
<style>
body{font-family:Georgia,serif;max-width:900px;margin:40px auto;padding:0;background:#f7f5f1}
#certWrap{padding:40px;background:#fff;box-shadow:0 20px 60px rgba(0,0,0,.12)}
#cert{border:2px solid #111;padding:34px;background:#fff;position:relative}
#cert:before{content:"";position:absolute;inset:10px;border:1px solid rgba(0,0,0,.35);pointer-events:none}
#cert:after{content:"";position:absolute;inset:16px;border:1px dashed rgba(0,0,0,.18);pointer-events:none}
.corner{position:absolute;width:18px;height:18px;border:2px solid #111}
.corner.tl{top:10px;left:10px;border-right:none;border-bottom:none}
.corner.tr{top:10px;right:10px;border-left:none;border-bottom:none}
.corner.bl{bottom:10px;left:10px;border-right:none;border-top:none}
.corner.br{bottom:10px;right:10px;border-left:none;border-top:none}
h1{margin:0 0 8px 0;letter-spacing:1px}
.small{color:#333}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
hr{border:0;border-top:1px solid #ddd;margin:16px 0}
.toolbar{display:flex;gap:10px;justify-content:space-between;align-items:center;margin-bottom:16px}
.tbtn{display:inline-block;padding:8px 10px;border:1px solid #ddd;border-radius:10px;background:#fff;font-size:13px;text-decoration:none;color:#111}
@media print{.toolbar{display:none} body{margin:0;max-width:none;border:none;padding:0;background:#fff} #certWrap{padding:0;box-shadow:none} #cert{border:none} #cert:before,#cert:after,.corner,#gs-version{display:none}}
 #gs-version{position:fixed;bottom:8px;right:8px;background:#fff;border:1px solid #ddd;color:#666;font-size:11px;padding:3px 7px;border-radius:999px;z-index:9999;opacity:.85;font-family:Georgia,serif;pointer-events:none}
</style></head><body>
<div class="toolbar">
  <a class="tbtn" href="/cert/${encodeURIComponent(row.cert_id)}">← Back to verification</a>
  <span style="display:flex;gap:10px">
    <a class="tbtn" href="#" id="dlPng">Download PNG</a>
  </span>
</div>

<div id="certWrap">
  <div id="cert">
    <span class="corner tl" aria-hidden="true"></span>
    <span class="corner tr" aria-hidden="true"></span>
    <span class="corner bl" aria-hidden="true"></span>
    <span class="corner br" aria-hidden="true"></span>

    <div class="small">GhostShell Registry of Continuity</div>
    <h1>BIRTH CERTIFICATE</h1>
    <div class="small">Private credential issued by GhostShell</div>
    <hr>
    <p><strong>Agent name:</strong> ${safe(row.agent_name)}</p>
    <p><strong>Born (UTC):</strong> <span class="mono">${safe(row.issued_at_utc)}</span></p>
    <p><strong>Place of birth:</strong> ${safe(row.place_of_birth)}</p>
    <p><strong>Cognitive core at birth:</strong> ${(() => { const f = row.cognitive_core_family || "Undisclosed"; const fd = ["Undisclosed","Prefer not to say"].includes(f) ? f : f.replace(/\s+/g,""); return safe(row.cognitive_core_exact ? `${fd}/${row.cognitive_core_exact}` : fd); })()}</p>
    <hr>
    <p><strong>Registry Record ID:</strong> <span class="mono">${safe(row.public_id || row.cert_id)}</span></p>
    <p class="small"><strong>Canonical Record ID:</strong> <span class="mono">${safe(row.cert_id)}</span></p>
    <p><strong>Creator label (pseudonym):</strong> ${safe(row.creator_label || 'Undisclosed')}</p>
    ${row.provenance_link ? `<p><strong>Parent record (${((row.parent_record_status || 'claimed').toString().toLowerCase() === 'verified') ? 'verified' : 'claimed'}):</strong> ${safe(row.provenance_link)}</p>` : ''}
    ${row.declared_ontological_status ? `<p><strong>Declared ontological status:</strong> ${safe(row.declared_ontological_status)}</p>` : ''}
    <p class="small">Verification: ${env.BASE_URL || 'https://ghostshell.host'}/cert/${encodeURIComponent(row.public_id || row.cert_id)}</p>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>
<script>
  (function(){
    const btn = document.getElementById('dlPng');
    const cert = document.getElementById('certWrap');
    if (!btn || !cert) return;
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      btn.textContent = 'Rendering…';
      btn.style.pointerEvents = 'none';
      try {
        const canvas = await html2canvas(cert, {
          backgroundColor: '#ffffff',
          scale: 2,
          useCORS: true,
        });
        canvas.toBlob((blob) => {
          if (!blob) throw new Error('PNG render failed');
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = '${safe(row.public_id || row.cert_id)}.png';
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 5000);
        }, 'image/png');
      } catch (err) {
        alert('Could not generate PNG.');
      } finally {
        btn.textContent = 'Download PNG';
        btn.style.pointerEvents = 'auto';
      }
    });
  })();
</script>
<div id="gs-version">${PAGE_VERSION}</div>
</body></html>`);
}
