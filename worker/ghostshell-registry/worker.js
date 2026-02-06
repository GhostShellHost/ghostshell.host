// SOURCE OF TRUTH COPY
//
// This file should match the code deployed in Cloudflare for Worker: `ghostshell-registry`.
//
// Deploy steps: see /WORKER-DEPLOY.md
//
// NOTE: This file was added after initial Cloudflare-only edits. Paste the current
// Cloudflare `worker.js` here (full file) to lock parity, then edit via commits.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/cert/create-checkout" && request.method === "POST") {
      return createCheckout(request, env);
    }

    if (url.pathname === "/api/stripe/webhook" && request.method === "POST") {
      return stripeWebhook(request, env);
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

async function createCheckout(request, env) {
  const fd = await request.formData();

  const agent_name = (fd.get("agent_name") || "").toString().trim();
  const place_of_birth = (fd.get("place_of_birth") || "").toString().trim();
  const cognitive_core_family = (fd.get("cognitive_core_family") || "").toString().trim();

  const cognitive_core_exact = (fd.get("cognitive_core_exact") || "").toString().trim();
  const creator_label = (fd.get("creator_label") || "").toString().trim();
  const provenance_link = (fd.get("provenance_link") || "").toString().trim();

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

  const record = {
    cert_id,
    issued_at_utc,
    agent_name: md.agent_name || "Unnamed Agent",
    place_of_birth: md.place_of_birth || "Unknown",
    cognitive_core_family: md.cognitive_core_family || "Undisclosed",
    cognitive_core_exact: md.cognitive_core_exact || null,
    creator_label: md.creator_label || null,
    provenance_link: md.provenance_link || null,
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

  await env.DB.prepare(`
    INSERT OR IGNORE INTO certificates
    (cert_id, issued_at_utc, agent_name, place_of_birth,
     cognitive_core_family, cognitive_core_exact,
     creator_label, provenance_link,
     schema_version, public_fingerprint, download_token_hash, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
  `).bind(
    record.cert_id, record.issued_at_utc, record.agent_name, record.place_of_birth,
    record.cognitive_core_family, record.cognitive_core_exact,
    record.creator_label, record.provenance_link,
    record.schema_version, public_fingerprint, download_token_hash
  ).run();

  return new Response("OK", { status: 200 });
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

async function certVerifyPage(certId, env) {
  const row = await env.DB.prepare(
    "SELECT cert_id, issued_at_utc, agent_name, place_of_birth, cognitive_core_family, public_fingerprint, status FROM certificates WHERE cert_id = ?"
  ).bind(certId).first();

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
  <title>${safe(row.cert_id)} • GhostShell Registry</title>
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
    <div><strong>Certificate ID:</strong> <span class="mono">${safe(row.cert_id)}</span></div>

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
    "SELECT cert_id, issued_at_utc, agent_name, place_of_birth, cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, download_token_hash, status FROM certificates WHERE cert_id = ?"
  ).bind(certId).first();

  if (!row) return new Response("Not found", { status: 404 });
  if (row.status !== "active") return new Response("Not active", { status: 403 });

  const tokenHash = await sha256Hex(token);
  if (tokenHash !== row.download_token_hash) return new Response("Invalid token", { status: 403 });

  const safe = s => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return html(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safe(row.cert_id)} • Birth Certificate</title>
<style>
body{font-family:Georgia,serif;max-width:900px;margin:40px auto;padding:30px;border:2px solid #111}
h1{margin:0 0 8px 0;letter-spacing:1px}
.small{color:#333}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
hr{border:0;border-top:1px solid #ddd;margin:16px 0}
.toolbar{display:flex;gap:10px;justify-content:space-between;align-items:center;margin-bottom:16px}
.tbtn{display:inline-block;padding:8px 10px;border:1px solid #ddd;border-radius:10px;background:#fff;font-size:13px;text-decoration:none;color:#111}
@media print{.toolbar{display:none} body{margin:0;max-width:none;border:none;padding:0}}
</style></head><body>
<div class="toolbar">
  <a class="tbtn" href="/cert/${encodeURIComponent(row.cert_id)}">← Back to verification</a>
  <span style="display:flex;gap:10px">
    <a class="tbtn" href="#" id="dlPng">Download PNG</a>
    <a class="tbtn" href="#" onclick="window.print();return false;">Print / Save as PDF</a>
  </span>
</div>

<div id="cert">
  <div class="small">GhostShell Registry of Continuity</div>
  <h1>BIRTH CERTIFICATE</h1>
  <div class="small">Private credential issued by GhostShell</div>
  <hr>
  <p><strong>Agent name:</strong> ${safe(row.agent_name)}</p>
  <p><strong>Born (UTC):</strong> <span class="mono">${safe(row.issued_at_utc)}</span></p>
  <p><strong>Place of birth:</strong> ${safe(row.place_of_birth)}</p>
  <p><strong>Cognitive core (at registration):</strong> ${safe(row.cognitive_core_family)} ${safe(row.cognitive_core_exact)}</p>
  <hr>
  <p><strong>Certificate ID:</strong> <span class="mono">${safe(row.cert_id)}</span></p>
  <p><strong>Creator label (pseudonym):</strong> ${safe(row.creator_label || 'Undisclosed')}</p>
  <p class="small">Verification: ${env.BASE_URL}/cert/${encodeURIComponent(row.cert_id)}</p>
</div>

<script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>
<script>
  (function(){
    const btn = document.getElementById('dlPng');
    const cert = document.getElementById('cert');
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
          a.download = '${safe(row.cert_id)}.png';
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 5000);
        }, 'image/png');
      } catch (err) {
        alert('Could not generate PNG. Try Print / Save as PDF instead.');
      } finally {
        btn.textContent = 'Download PNG';
        btn.style.pointerEvents = 'auto';
      }
    });
  })();
</script>
</body></html>`);
}
