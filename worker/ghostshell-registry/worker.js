// SOURCE OF TRUTH COPY
//
// This file should match the code deployed in Cloudflare for Worker: `ghostshell-registry`.
//
// Deploy steps: see /WORKER-DEPLOY.md
//
// VERSION: 2026-02-07.001 (manual paste deploy)
// If you paste this into Cloudflare, you should see this version string at the top.
//
export const WORKER_VERSION = "2026-02-08.001";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/cert/create-checkout" && request.method === "POST") {
      return createCheckout(request, env);
    }

    if (url.pathname === "/api/cert/checkout" && request.method === "POST") {
      return purchaseFirstCheckout(env);
    }

    if (url.pathname === "/api/cert/checkout" && request.method === "GET") {
      return new Response("Method not allowed. Use POST.", { status: 405 });
    }

    if (url.pathname === "/api/stripe/webhook" && request.method === "POST") {
      return stripeWebhook(request, env);
    }

    if (url.pathname === "/api/cert/latest-origin" && request.method === "GET") {
      return latestOrigin(env);
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

async function allocateCardNumber(db) {
  const yy = getUTCYearYY(new Date());

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
  const fd = await request.formData();

  const agent_name = (fd.get("agent_name") || "").toString().trim();
  const place_of_birth = (fd.get("place_of_birth") || "").toString().trim();
  const cognitive_core_family = (fd.get("cognitive_core_family") || "").toString().trim();

  const cognitive_core_exact = (fd.get("cognitive_core_exact") || "").toString().trim();
  const creator_label = (fd.get("creator_label") || "").toString().trim();
  const provenance_link = (fd.get("provenance_link") || "").toString().trim();

  // Stretch goal: optional private delivery email (not public, not identity proof)
  const delivery_email = (fd.get("delivery_email") || "").toString().trim();
  const delivery_consent = (fd.get("delivery_consent") || "").toString().trim();

  if (!agent_name || !place_of_birth || !cognitive_core_family) {
    return json({ error: "Missing required fields" }, 400);
  }
  if (!env.STRIPE_SECRET_KEY || !env.STRIPE_PRICE_ID || !env.BASE_URL) {
    return json({ error: "Missing STRIPE_SECRET_KEY / STRIPE_PRICE_ID / BASE_URL" }, 500);
  }

  const certId = makeCertId();
  const token = makeToken();

  const successUrl = `${env.BASE_URL}/cert/${encodeURIComponent(certId)}/download?t=${encodeURIComponent(token)}`;
  const cancelUrl = `${env.BASE_URL}/birth-certificate`;

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

async function purchaseFirstCheckout(env) {
  if (!env.STRIPE_SECRET_KEY || !env.STRIPE_PRICE_ID || !env.BASE_URL) {
    return json({ error: "Missing STRIPE_SECRET_KEY / STRIPE_PRICE_ID / BASE_URL" }, 500);
  }

  const body = new URLSearchParams();
  body.set("mode", "payment");
  body.set("allow_promotion_codes", "true");
  body.set("success_url", `${env.BASE_URL}/handoff?session_id={CHECKOUT_SESSION_ID}`);
  body.set("cancel_url", `${env.BASE_URL}/issue/`);
  body.append("line_items[0][price]", env.STRIPE_PRICE_ID);
  body.append("line_items[0][quantity]", "1");

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

async function stripeWebhook(request, env) {
  const sig = request.headers.get("stripe-signature") || "";
  const raw = await request.text();

  const ok = await verifyStripeSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("Invalid signature", { status: 400 });

  const event = JSON.parse(raw);
  if (event.type !== "checkout.session.completed") return new Response("Ignored", { status: 200 });

  const session = event.data.object;
  const md = session.metadata || {};
  const cert_id = md.cert_id;
  const token = md.token;
  if (!cert_id || !token) return new Response("Missing metadata", { status: 400 });

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
           schema_version, public_fingerprint, download_token_hash, status,
           delivery_email_hash, delivery_email_iv, delivery_email_enc)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
        `).bind(
          record.cert_id, record.issued_at_utc, card_number, public_id, record.registered_by,
          record.agent_name, record.place_of_birth, record.cognitive_core_family, record.cognitive_core_exact,
          record.creator_label, record.provenance_link,
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
           schema_version, public_fingerprint, download_token_hash, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
        `).bind(
          record.cert_id, record.issued_at_utc, card_number, public_id, record.registered_by,
          record.agent_name, record.place_of_birth, record.cognitive_core_family, record.cognitive_core_exact,
          record.creator_label, record.provenance_link,
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

async function certVerifyPage(certId, env) {
  const selectPublicFields =
    "SELECT cert_id, public_id, issued_at_utc, agent_name, place_of_birth, cognitive_core_family, public_fingerprint, status FROM certificates WHERE ";

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
  const registryLabel = status === "active" ? "Registry entry found" : "Registry entry not active";
  const integrityLabel = status === "active" ? "PASS" : "UNKNOWN";

  // 1 hour cache (immutable records; rare revokes)
  const cacheHeaders = {
    "Cache-Control": "public, max-age=3600",
  };
return html(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${safe(row.public_id || row.cert_id)} • GhostShell Registry</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:860px;margin:60px auto;padding:0 18px;line-height:1.5}
    .badge{display:inline-block;padding:4px 10px;border:1px solid #ddd;border-radius:999px;font-size:12px}
    .box{margin-top:18px;padding:14px;border:1px solid #eee;border-radius:12px;background:#fafafa}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
    .row{display:flex;gap:10px;justify-content:space-between;align-items:baseline;border-top:1px solid #eee;padding-top:10px;margin-top:10px}
    .muted{color:#555}
    details{margin-top:14px}
    summary{cursor:pointer}
    .btn{display:inline-block;margin-top:10px;margin-right:8px;padding:8px 10px;border:1px solid #ddd;border-radius:10px;background:#fff;font-size:13px}
  </style>
</head>
<body>
  <span class="badge">Registry verification</span>
  <h1>GhostShell Birth Certificate</h1>

  <div class="box">
    <div><strong>Registry Record ID:</strong> <span class="mono">${safe(row.public_id || row.cert_id)}</span></div>
    <div class="small" style="margin-top:6px"><strong>Canonical Record ID:</strong> <span class="mono">${safe(row.cert_id)}</span></div>

    <div class="row">
      <div><strong>Status</strong></div>
      <div>${safe(registryLabel)}</div>
    </div>

    <div class="row">
      <div><strong>Integrity</strong></div>
      <div><span class="mono">${safe(integrityLabel)}</span></div>
    </div>

    <div class="row">
      <div><strong>Issued (UTC)</strong></div>
      <div class="mono">${safe(row.issued_at_utc)}</div>
    </div>

    <div class="row">
      <div><strong>Agent name</strong></div>
      <div>${safe(row.agent_name)}</div>
    </div>

    <div class="row">
      <div><strong>Place of birth</strong></div>
      <div>${safe(row.place_of_birth)}</div>
    </div>

    <div class="row">
      <div><strong>Cognitive core (family)</strong></div>
      <div>${safe(row.cognitive_core_family)}</div>
    </div>

    <div class="row">
      <div><strong>Fingerprint</strong></div>
      <div class="mono" id="fp">${safe(row.public_fingerprint)}</div>
    </div>

    <a class="btn" href="#" onclick="navigator.clipboard.writeText(location.href);return false;">Copy verify link</a>
    <a class="btn" href="#" onclick="navigator.clipboard.writeText(document.getElementById('fp').innerText);return false;">Copy fingerprint</a>

    
  </div>

  <p class="muted" style="margin-top:14px">
    Private credential issued by GhostShell. Verification checks registry presence + fingerprint integrity only.
  </p>
</body>
</html>`, 200, cacheHeaders);
}

async function certDownloadPrintable(certId, token, env) {
  if (!token) return new Response("Missing token", { status: 401 });

  const row = await env.DB.prepare(
    "SELECT cert_id, public_id, issued_at_utc, agent_name, place_of_birth, cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, download_token_hash, status FROM certificates WHERE cert_id = ?"
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
@media print{.toolbar{display:none} body{margin:0;max-width:none;border:none;padding:0;background:#fff} #certWrap{padding:0;box-shadow:none} #cert{border:none} #cert:before,#cert:after,.corner{display:none}}
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
    <p><strong>Cognitive core (at registration):</strong> ${safe(row.cognitive_core_family)} ${safe(row.cognitive_core_exact)}</p>
    <hr>
    <p><strong>Registry Record ID:</strong> <span class="mono">${safe(row.public_id || row.cert_id)}</span></p>
    <p class="small"><strong>Canonical Record ID:</strong> <span class="mono">${safe(row.cert_id)}</span></p>
    <p><strong>Creator label (pseudonym):</strong> ${safe(row.creator_label || 'Undisclosed')}</p>
    <p class="small">Verification: ${env.BASE_URL}/cert/${encodeURIComponent(row.public_id || row.cert_id)}</p>
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
</body></html>`);
}
