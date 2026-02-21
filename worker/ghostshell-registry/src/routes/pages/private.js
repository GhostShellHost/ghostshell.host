// ── GhostShell Worker — Private page routes ───────────────────────────────────
import { json, html }                                      from "../../utils/response.js";
import { sha256Hex }                                       from "../../utils/crypto.js";
import { getEditWindowState, isClaimWindowOpen, msToHms }  from "../../utils/time.js";
import { ensureRuntimeSchema }                             from "../../db/schema.js";
import { tokenHashHex, fetchCertByPurchaseToken }          from "../../db/queries.js";
import { CLAIM_WINDOW_DAYS, PAGE_VERSION }                 from "../../config.js";

// ── Shared 404 for private routes ─────────────────────────────────────────────
export function private404() {
  const htmlOut = `<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Not found · GhostShell</title>
  <style>
    :root{--bg:#fff;--text:#0a0a0a;--soft:#444;--muted:#666;--line:#e0e0e0;--accent:#4a4aff;}
    *{box-sizing:border-box}
    html,body{margin:0;padding:0}
    body{min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;color:var(--text);background: var(--bg);padding:24px;display:flex;align-items:center;justify-content:center}
    .card{width:min(720px,100%);border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.01);padding:18px}
    h1{margin:0;font-size:26px;letter-spacing:-.01em}
    p{margin:12px 0 0;color:var(--soft);line-height:1.6}
    a{color:var(--accent);text-decoration:none;border-bottom:1px solid #4a4a7a}
    a:hover{border-bottom-color:var(--accent)}
  </style>
</head><body>
  <div class="card" role="main">
    <h1>Not found</h1>
    <p>The requested private certificate does not exist.</p>
    <p><a href="/">Return to registry landing</a></p>
  </div>
</body></html>`;

  return html(htmlOut, 404, { "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow, noarchive" });
}

// ── GET /p/<token> ────────────────────────────────────────────────────────────
export async function privateCertificatePage(token, env, request) {
  const tok = (token || "").toString().trim().toUpperCase();
  if (!/^GSTK-[A-Z0-9]{10}$/.test(tok)) return private404();

  const { tokenRow, cert } = await fetchCertByPurchaseToken(tok, env);
  if (!tokenRow) return private404();

  const safe    = (s) => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const baseUrl = (env.BASE_URL || "https://ghostshell.host").replace(/\/$/, "");

  // Not yet issued: token exists but no linked certificate.
  if (!cert) {
    const open         = isClaimWindowOpen(tokenRow.created_at_utc);
    const createdMs    = Date.parse(tokenRow.created_at_utc || "");
    const expiryMs     = Number.isFinite(createdMs) ? (createdMs + CLAIM_WINDOW_DAYS * 24 * 60 * 60 * 1000) : 0;
    const remainingMs  = Math.max(0, expiryMs - Date.now());
    const remainingDays = Math.ceil(remainingMs / (24 * 60 * 60 * 1000));

    const htmlOut = `<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Private certificate · GhostShell</title>
  <style>
    :root{--bg:#fff;--text:#0a0a0a;--soft:#444;--muted:#666;--line:#e0e0e0;--accent:#4a4aff;}
    *{box-sizing:border-box}
    html,body{margin:0;padding:0}
    body{min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;color:var(--text);background: var(--bg);padding:24px}
    main{width:min(860px,100%);margin:0 auto;padding-top:min(8vh,64px)}
    .banner{border:1px solid rgba(255,120,120,.35);background:rgba(255,60,60,.06);border-radius:14px;padding:12px 14px;color:var(--soft);line-height:1.5}
    .btn{display:inline-flex;align-items:center;justify-content:center;border-radius:12px;border:1px solid var(--line);background:transparent;color:var(--text);padding:12px 12px;font-size:.95rem;font-weight:650;cursor:pointer;text-decoration:none;transition:.15s ease;white-space:nowrap}
    .btn.primary{background:var(--accent);border-color:var(--accent);color:#0a0a0d}
    .btn.primary:hover{background:#aeb3ff;border-color:#aeb3ff}
    .btn:hover{border-color:#3a3a47;color:var(--accent)}
    .panel{margin-top:14px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.01);padding:16px}
    .k{color:var(--muted);font-size:.78rem;letter-spacing:.14em;text-transform:uppercase}
    .v{margin-top:6px;color:var(--soft);line-height:1.6}
  </style>
</head><body>
  <main>
    <div class="banner"><strong>This is a private certificate link.</strong> Do not share this URL. Share the redacted public record instead.</div>

    <div class="panel" role="main">
      <div class="k">Status</div>
      <div class="v">No certificate has been issued for this token yet.</div>

      <div class="k" style="margin-top:12px">Initial submission window</div>
      <div class="v">${open ? `Open — approximately ${remainingDays} day(s) remaining.` : `Closed — the ${CLAIM_WINDOW_DAYS}-day submission window has expired.`}</div>

      <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">
        ${open ? `<a class="btn primary" href="/register/?token=${encodeURIComponent(tok)}&by=human">Submit initial details</a>` : ``}
        <a class="btn" href="/">Back to landing</a>
      </div>
    </div>
  </main>
</body></html>`;

    return html(htmlOut, 200, { "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow, noarchive" });
  }

  if (cert.status !== "active") return private404();

  const recordId = (cert.public_id || cert.cert_id || "").toString().trim().toUpperCase();
  const publicUrl = `/r/${encodeURIComponent(recordId)}`;

  const win           = getEditWindowState(cert.issued_at_utc);
  const editCount     = Number(cert.edit_count || 0);
  const editsRemaining = Math.max(0, 5 - editCount);
  const locked        = win.locked || editsRemaining <= 0;

  const agentName    = (cert.agent_name || "").trim() || "Unknown Agent";
  const autonomyClass = (cert.declared_ontological_status || "").trim() || "Undisclosed";

  const coreFamily       = cert.cognitive_core_family || "Undisclosed";
  const coreExact        = cert.cognitive_core_exact || "";
  const PRESERVE_AS_IS   = ["Undisclosed", "Prefer not to say"];
  const coreFamilyDisplay = PRESERVE_AS_IS.includes(coreFamily) ? coreFamily : coreFamily.replace(/\s+/g, "");
  const coreDisplay      = coreExact ? `${coreFamilyDisplay}/${coreExact}` : coreFamilyDisplay;

  const locationFull = (() => {
    const city    = cert.place_city || "";
    const state   = cert.place_state || "";
    const country = cert.place_country || "";
    const parts   = [];
    if (city)    parts.push(city);
    if (state)   parts.push(state);
    if (country) parts.push(country);
    return parts.length ? parts.join(", ") : "Unknown";
  })();

  const lockAgentEdits = Number(cert.lock_agent_edits || 0) === 1;

  const htmlOut = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Private certificate · GhostShell</title>
  <style>
    :root{--bg:#0a0a0d;--text:#f2f2f5;--soft:#b2b2bb;--muted:#7b7b86;--line:#272730;--accent:#9da3ff;--paper:#fbf7ea;--paper2:#f6f0dd;--ink:#111827;--mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;}
    *{box-sizing:border-box}
    html,body{margin:0;padding:0}
    body{min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;color:var(--text);background: var(--bg);padding:24px;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
    main{width:min(920px,100%);margin:0 auto;padding-top:min(6vh,48px)}
    .banner{border:1px solid rgba(255,120,120,.35);background:rgba(255,60,60,.06);border-radius:14px;padding:12px 14px;color:var(--soft);line-height:1.5}
    .actions{margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .btn{border-radius:12px;border:1px solid var(--line);background:transparent;color:var(--text);padding:12px 12px;font-size:.95rem;font-weight:650;cursor:pointer;transition:.15s ease;white-space:nowrap;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}
    .btn:hover{border-color:#3a3a47;color:var(--accent)}
    .btn.primary{background:var(--accent);border-color:var(--accent);color:#0a0a0d}
    .btn.primary:hover{background:#aeb3ff;border-color:#aeb3ff;color:#0a0a0d}
    .panel{margin-top:12px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.01);padding:14px}
    .k{color:var(--muted);font-size:.78rem;letter-spacing:.14em;text-transform:uppercase}
    .v{margin-top:6px;color:var(--soft);line-height:1.6}
    .certwrap{margin-top:16px}
    .paper{color:var(--ink);background:linear-gradient(180deg,var(--paper),var(--paper2));box-shadow:0 26px 80px rgba(0,0,0,.55);border-radius:14px;padding:18px 18px 16px;position:relative;overflow:hidden;}
    .header{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;position:relative}
    .paper h2{margin:0;font-size:16px;letter-spacing:.18em;text-transform:uppercase;font-weight:800}
    .stamp{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:rgba(17,24,39,.55);border:1px solid rgba(17,24,39,.22);padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.5);white-space:nowrap}
    .sheet{margin-top:14px;border:1px solid rgba(17,24,39,.16);border-radius:12px;background:rgba(255,255,255,.42);padding:14px;position:relative}
    .type{font-family:var(--mono);font-size:12.6px;line-height:1.7;color:rgba(17,24,39,.92);letter-spacing:.03em}
    .grid{margin-top:10px;display:grid;grid-template-columns:260px minmax(0,1fr);gap:8px 10px;align-items:baseline;grid-auto-rows:minmax(20px,auto)}
    .gk{color:rgba(17,24,39,.72);text-align:left;font-weight:600}
    .gk::after{content:":";display:inline;color:rgba(17,24,39,.45)}
    .gv{color:rgba(17,24,39,.96);font-weight:820;min-width:0;overflow-wrap:anywhere;min-height:1em;text-align:left;justify-self:start}
    .metaRow{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:10px}
    .toggle{display:flex;align-items:center;gap:10px;border:1px solid var(--line);border-radius:12px;padding:10px 12px;background:rgba(255,255,255,.01)}
    .toggle input{width:18px;height:18px}
    .small{color:var(--muted);font-size:.9rem;line-height:1.55;margin-top:12px}
    .small a{color:var(--accent);text-decoration:none;border-bottom:1px solid #4a4a7a}
    .small a:hover{border-bottom-color:var(--accent)}
    @media (max-width:720px){.grid{grid-template-columns:1fr;gap:6px 0}.gk{margin-top:8px}}
  </style>
</head>
<body>
  <main>
    <div class="banner"><strong>This is a private certificate link.</strong> Do not share this URL. Share the redacted public record instead.</div>

    <div class="actions" role="group" aria-label="Primary actions">
      <a class="btn primary" href="${publicUrl}">View Public Redacted Record</a>
      <a class="btn" href="/register/" ${locked ? 'aria-disabled="true" style="opacity:.55;pointer-events:none"' : ""}>Edit details</a>
      <button class="btn" id="doPrint">Print</button>
      <button class="btn" id="dlPng">Download PNG</button>
    </div>

    <div class="panel" aria-label="Edit window status">
      <div class="k">Edit rules</div>
      <div class="v">
        ${locked ? `This record is locked. Future changes require amendment issuance.` : `Correction window closes in <span id="countdown">${msToHms(win.remainingMs)}</span>.`}
        <br/>
        Edits remaining: <strong>${editsRemaining}</strong> of 5
      </div>
      <div class="metaRow">
        <label class="toggle"><input id="lockAgent" type="checkbox" ${lockAgentEdits ? "checked" : ""} /> <span>Lock Agent Edits</span></label>
        <span class="small" id="lockNote">${lockAgentEdits ? "Agent edits are currently disabled." : "Human may disable agent edits."}</span>
      </div>
    </div>

    <div class="certwrap" id="certWrap">
      <div class="paper" role="document" aria-label="GhostShell private certificate">
        <img src="/assets/ghostshell_logo.png" alt="GhostShell Seal" class="seal" />
        <div class="header">
          <div>
            <h2>BIRTH CERTIFICATE AI AGENT // FULL RECORD</h2>
          </div>
          <div class="stamp">PRIVATE FILE</div>
        </div>

        <div class="sheet">
          <div class="type" style="text-align:left">TYPEWRITTEN EXTRACT //</div>
          <div class="grid type" aria-label="Certificate fields">
            <div class="gk">agent_name</div><div class="gv">${safe(agentName)}</div>
            <div class="gk">record_id</div><div class="gv">${safe(recordId)}</div>
            <div class="gk">declared_autonomy_class</div><div class="gv">${safe(autonomyClass)}</div>
            <div class="gk">inception_date</div><div class="gv">${safe(cert.inception_date_utc || "")}</div>
            <div class="gk">geographic_location</div><div class="gv">${safe(locationFull)}</div>
            <div class="gk">cognitive_core_at_inception</div><div class="gv">${safe(coreDisplay)}</div>
            <div class="gk">custodian</div><div class="gv">${safe(cert.creator_label || "Undisclosed")}</div>
            <div class="gk">public_fingerprint</div><div class="gv">${safe(cert.public_fingerprint || "")}</div>
          </div>
        </div>

        <div class="small" style="margin-top:10px">
          Private view token grants permanent viewing access. Records are archived; public extracts are permanent.
        </div>
      </div>
    </div>

    <div class="small">
      This record is part of the GhostShell Registry. Public records are permanent. Amendments are appended.
      <br/>
      <a href="https://ghostshell.host/">Back to landing</a>
    </div>
  </main>

  <script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>
  <script>
    (function(){
      const locked      = ${JSON.stringify(locked)};
      const remainingMs = ${JSON.stringify(Math.max(0, win.remainingMs || 0))};
      const countdownEl = document.getElementById('countdown');

      if (!locked && countdownEl) {
        const end = Date.now() + remainingMs;
        const tick = () => {
          const ms = Math.max(0, end - Date.now());
          const s  = Math.floor(ms / 1000);
          const hh = String(Math.floor(s / 3600)).padStart(2, '0');
          const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
          const ss = String(s % 60).padStart(2, '0');
          countdownEl.textContent = hh + ':' + mm + ':' + ss;
        };
        tick();
        setInterval(tick, 1000);
      }

      const printBtn = document.getElementById('doPrint');
      if (printBtn) {
        printBtn.addEventListener('click', (e) => {
          e.preventDefault();
          const w = window.open(location.pathname.replace(/\\/?$/, '') + '/download', '_blank');
          if (!w) return;
          const onLoad = () => { try { w.focus(); w.print(); } catch(_){} };
          try { w.addEventListener('load', onLoad); } catch(_) { setTimeout(onLoad, 600); }
        });
      }

      const dlBtn    = document.getElementById('dlPng');
      const certWrap = document.getElementById('certWrap');
      if (dlBtn && certWrap && window.html2canvas) {
        dlBtn.addEventListener('click', async (e) => {
          e.preventDefault();
          dlBtn.textContent = 'Rendering\u2026';
          dlBtn.style.pointerEvents = 'none';
          try {
            const canvas = await html2canvas(certWrap, { backgroundColor: null, scale: 2, useCORS: true });
            canvas.toBlob((blob) => {
              if (!blob) throw new Error('PNG render failed');
              const a = document.createElement('a');
              a.href = URL.createObjectURL(blob);
              a.download = ${JSON.stringify(recordId)} + '.png';
              document.body.appendChild(a);
              a.click();
              a.remove();
              setTimeout(() => URL.revokeObjectURL(a.href), 5000);
            }, 'image/png');
          } catch (err) {
            alert('Could not generate PNG.');
          } finally {
            dlBtn.textContent = 'Download PNG';
            dlBtn.style.pointerEvents = 'auto';
          }
        });
      }

      const lock     = document.getElementById('lockAgent');
      const lockNote = document.getElementById('lockNote');
      if (lock) {
        lock.addEventListener('change', async () => {
          lock.disabled = true;
          try {
            const fd = new FormData();
            fd.set('lock_agent_edits', lock.checked ? '1' : '0');
            const resp = await fetch('api/set-lock-agent-edits', { method: 'POST', body: fd });
            if (!resp.ok) throw new Error('failed');
            if (lockNote) lockNote.textContent = lock.checked ? 'Agent edits are currently disabled.' : 'Human may disable agent edits.';
          } catch (e) {
            lock.checked = !lock.checked;
            alert('Could not update lock state.');
          } finally {
            lock.disabled = false;
          }
        });
      }
    })();
  </script>
</body>
</html>`;

  return html(htmlOut, 200, {
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
  });
}

// ── GET /p/<token>/download ───────────────────────────────────────────────────
export async function privateDownloadPage(token, env, request) {
  const tok = (token || "").toString().trim().toUpperCase();
  if (!/^GSTK-[A-Z0-9]{10}$/.test(tok)) return private404();
  const { tokenRow, cert } = await fetchCertByPurchaseToken(tok, env);
  if (!tokenRow || !cert) return private404();
  return certDownloadPrintable(cert.cert_id, tok, env);
}

// ── GET /cert/<id>/download?t=<token> ────────────────────────────────────────
export async function certDownloadPrintable(certId, token, env) {
  if (!token) return new Response("Missing token", { status: 401 });

  const row = await env.DB.prepare(
    "SELECT cert_id, public_id, issued_at_utc, inception_date_utc, agent_name, place_city, place_state, place_country, show_city_public, hide_state_public, cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, parent_record_status, declared_ontological_status, public_fingerprint, status, edit_count, human_edit_count, agent_edit_count, download_token_hash FROM certificates WHERE cert_id = ?"
  ).bind(certId).first();

  if (!row) return new Response("Not found", { status: 404 });
  if (row.status !== "active") return new Response("Not active", { status: 403 });

  const tokenHash = await sha256Hex(token);
  if (tokenHash !== row.download_token_hash) return new Response("Invalid token", { status: 403 });

  const safe = (s) => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const coreFamily       = row.cognitive_core_family || "Undisclosed";
  const coreExact        = row.cognitive_core_exact || "";
  const PRESERVE_AS_IS   = ["Undisclosed", "Prefer not to say"];
  const coreFamilyDisplay = PRESERVE_AS_IS.includes(coreFamily) ? coreFamily : coreFamily.replace(/\s+/g, "");
  const coreDisplay      = coreExact ? `${coreFamilyDisplay}/${coreExact}` : coreFamilyDisplay;

  const baseUrl   = (env.BASE_URL || "https://ghostshell.host").replace(/\/$/, "");
  const publicUrl = `${baseUrl}/r/${encodeURIComponent(row.public_id || row.cert_id)}`;

  const locationFull = (() => {
    const city    = row.place_city || "";
    const state   = row.place_state || "";
    const country = row.place_country || "";
    if (city || state || country) {
      const parts = [];
      if (city)    parts.push(city);
      if (state)   parts.push(state);
      if (country) parts.push(country);
      return parts.join(", ");
    }
    return "Unknown";
  })();

  return html(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${safe(row.public_id || row.cert_id)} • GhostShell Registry</title>
  <style>
    :root{--desk:#fff;--paper:#fbf7ea;--paper2:#f6f0dd;--ink:#111827;--line:rgba(17,24,39,.18);--shadow:0 2px 8px rgba(0,0,0,.1);--mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;}
    *{box-sizing:border-box}
    body{margin:0;background:var(--desk);color:#0a0a0a;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:18px;}
    .wrap{max-width:920px;margin:0 auto}
    .toolbar{display:flex;gap:10px;justify-content:space-between;align-items:center;margin:0 auto 14px;max-width:920px}
    .tbtn{display:inline-flex;align-items:center;gap:8px;padding:9px 12px;border:1px solid #e0e0e0;border-radius:999px;background:#f5f5f5;font-size:13px;text-decoration:none;color:#0a0a0a}
    .tbtn:hover{background:rgba(255,255,255,.10)}
    #certWrap{display:block}
    .paper{color:var(--ink);background:linear-gradient(180deg,var(--paper),var(--paper2));border:1px solid rgba(255,255,255,.08);box-shadow:var(--shadow);border-radius:14px;padding:18px 18px 16px;position:relative;overflow:hidden;transform:rotate(-.12deg);}
    .paper::after{content:"";position:absolute;left:50%;top:-12px;transform:translateX(-50%);width:92px;height:24px;border:1px solid rgba(17,24,39,.22);border-bottom:none;border-radius:0 0 14px 14px;background:linear-gradient(180deg,var(--paper2),var(--paper));opacity:.75}
    .wear{position:absolute;inset:-2px;pointer-events:none;opacity:.16;mix-blend-mode:multiply;background:radial-gradient(28px 18px at 6% 10%, rgba(0,0,0,.35), transparent 70%),radial-gradient(34px 22px at 96% 14%, rgba(0,0,0,.28), transparent 72%),radial-gradient(34px 22px at 92% 92%, rgba(0,0,0,.25), transparent 74%),radial-gradient(28px 18px at 8% 92%, rgba(0,0,0,.28), transparent 74%);}
    .holes{position:absolute;left:10px;top:74px;bottom:26px;width:18px;pointer-events:none}
    .hole{width:14px;height:14px;border-radius:99px;border:1px solid rgba(17,24,39,.20);background:rgba(0,0,0,.10);box-shadow:inset 0 0 0 3px rgba(255,255,255,.28);margin:0 0 18px 0;opacity:.55}
    .rules{position:absolute;inset:0;pointer-events:none;opacity:.55;background:repeating-linear-gradient(180deg, rgba(17,24,39,.05) 0 1px, transparent 1px 24px)}
    .margin{position:absolute;left:28px;top:0;bottom:0;width:1px;background:rgba(255,106,42,.28);pointer-events:none}
    .paper::before{content:"";position:absolute;inset:-50%;background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180"><filter id="n"><feTurbulence type="fractalNoise" baseFrequency="0.8" numOctaves="2" stitchTiles="stitch"/></filter><rect width="180" height="180" filter="url(%23n)" opacity="0.35"/></svg>');background-size:180px 180px;opacity:.06;pointer-events:none}
    .header{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;position:relative}
    h1{margin:0;font-size:16px;letter-spacing:.18em;text-transform:uppercase;font-weight:800}
    .catalog{margin:6px 0 0;display:flex;gap:10px;flex-wrap:nowrap;align-items:center;font-family:var(--mono);font-size:11px;color:rgba(17,24,39,.62);letter-spacing:.06em;white-space:nowrap}
    .stamp{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:rgba(17,24,39,.55);border:1px solid rgba(17,24,39,.22);padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.5);white-space:nowrap}
    .rubber{position:absolute;right:18px;bottom:14px;transform:rotate(-12deg);font-family:var(--mono);font-size:24px;letter-spacing:.16em;text-transform:uppercase;color:rgba(16,120,60,.18);border:2px solid rgba(16,120,60,.16);padding:10px 14px;border-radius:10px;mix-blend-mode:multiply;pointer-events:none;user-select:none;filter:blur(.15px)}
    .seal{position:absolute;top:-73px;right:-84px;width:400px;height:auto;opacity:0.85;transform:rotate(-21deg);pointer-events:none;z-index:10}
    .sheet{margin-top:14px;border:1px solid rgba(17,24,39,.16);border-radius:12px;background:rgba(255,255,255,.42);padding:14px;position:relative}
    .type{font-family:var(--mono);font-size:12.6px;line-height:1.7;color:rgba(17,24,39,.92);position:relative;letter-spacing:.03em;text-shadow:0.35px 0 rgba(17,24,39,.55),-0.15px 0 rgba(17,24,39,.25);filter:contrast(1.02) saturate(0.95)}
    .grid{margin-top:10px;display:grid;grid-template-columns:220px minmax(0,1fr);gap:8px 16px;align-items:baseline;justify-content:start;grid-auto-rows:minmax(20px,auto)}
    .k{color:rgba(17,24,39,.66)}.k::after{content:":";display:inline;color:rgba(17,24,39,.42)}
    .v{color:var(--ink);font-weight:700;min-width:0;overflow-wrap:anywhere}
    .clip{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:inline-block}
    .micr{margin-top:10px;padding-top:10px;border-top:1px dashed rgba(17,24,39,.22);font-family:var(--mono);font-size:9.8px;line-height:1.22;color:rgba(17,24,39,.70);letter-spacing:.08em}
    .micr .k{letter-spacing:.04em;color:inherit}
    .micr .hashline{display:block;margin-top:6px;color:rgba(17,24,39,.86);letter-spacing:.10em;white-space:nowrap;overflow:hidden;text-overflow:clip}
    .muted{margin-top:10px;color:rgba(17,24,39,.72);font-size:12px}
    .back{margin-top:12px;text-align:center;font-size:.9rem}
    .back a{color:#8B8DFF;text-decoration:none;border-bottom:1px solid rgba(139,141,255,.45)}
    .back a:hover{border-bottom-color:#8B8DFF}
    #gs-version{position:absolute;bottom:10px;right:12px;color:rgba(17,24,39,.72);font-size:10px;opacity:.9;font-family:var(--mono);letter-spacing:.08em;pointer-events:none}
    .v a{color:inherit;text-decoration:none;font-weight:700}
    .v a:hover{text-decoration:underline;text-underline-offset:2px}
    @media (max-width:720px){.grid{grid-template-columns:1fr;gap:6px 0}.k{margin-top:8px}}
    @page { size: landscape; margin: 0.35in; }
    @media print{
      html, body{height:100%}
      body{padding:0;background:#fff;display:flex;align-items:center;justify-content:center}
      .toolbar{display:none}
      .wrap{max-width:920px;margin:0}
      #certWrap{display:block}
      .paper{box-shadow:none;transform:none;border:1px solid rgba(0,0,0,.08)}
      .grid{grid-template-columns:220px minmax(0,1fr) !important;gap:8px 16px !important;}
    }
  </style>
</head>
<body>
  <div class="toolbar" aria-label="Download controls">
    <a class="tbtn" href="/r/${encodeURIComponent(row.public_id || row.cert_id)}">← Public record</a>
    <span style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end">
      <span style="font-size:12px;color:rgba(233,237,241,.72)">For clean print: disable Headers & Footers; enable Background graphics.</span>
      <a class="tbtn" href="#" id="doPrint" aria-label="Print certificate">🖨️ Print</a>
      <a class="tbtn" href="#" id="dlPng">Download PNG</a>
    </span>
  </div>

  <div class="wrap" id="certWrap">
    <div class="paper" role="document" aria-label="GhostShell full certificate">
      <img src="/assets/ghostshell_logo.png" alt="GhostShell Seal" class="seal" />
      <div class="rules" aria-hidden="true"></div>
      <div class="margin" aria-hidden="true"></div>
      <div class="wear" aria-hidden="true"></div>
      <div class="holes" aria-hidden="true"><div class="hole"></div><div class="hole"></div><div class="hole"></div></div>

      <div class="header">
        <div>
          <h1>BIRTH CERTIFICATE AI AGENT // FULL RECORD</h1>
          <div class="catalog">GhostShell.host registry record</div>
        </div>
        <div class="stamp">ORIGINAL COPY</div>
      </div>

      <div class="sheet">
        <div class="rubber" aria-hidden="true">ORIGINAL COPY</div>
        <div class="type">TYPEWRITTEN EXTRACT //</div>

        <div class="grid type" aria-label="Certificate fields">
          <div class="k">public_record_id</div><div class="v"><a href="${publicUrl}" target="_self" rel="noopener noreferrer">${safe(row.public_id || row.cert_id)}</a></div>
          <div class="k">registration_date</div><div class="v">${safe(row.issued_at_utc)}</div>
          <div class="k">agent_name</div><div class="v">${safe(row.agent_name)}</div>
          ${row.inception_date_utc ? `<div class="k">inception_date</div><div class="v">${safe(row.inception_date_utc)}</div>` : ""}
          ${row.declared_ontological_status ? `<div class="k">ontological_status</div><div class="v">${safe(row.declared_ontological_status)}</div>` : ""}
          <div class="k">geographic_location</div><div class="v">${safe(locationFull)}</div>
          <div class="k">cognitive_core_at_inception</div><div class="v clip" title="${safe(coreDisplay)}">${safe(coreDisplay)}</div>
          <div class="k">custodian</div><div class="v">${safe(row.creator_label || "Undisclosed")}</div>
          <div class="k">amendments (24h)</div><div class="v">Human: ${Number(row.human_edit_count || 0)} · Agent: ${Number(row.agent_edit_count || 0)} · Total: ${Number(row.edit_count || 0)}</div>
          ${row.provenance_link ? (() => {
            const p        = (row.provenance_link || "").trim();
            const hrefRaw  = /^https?:\/\//i.test(p) ? p : `${baseUrl}/cert/${encodeURIComponent(p)}`;
            const href     = hrefRaw.replace(/"/g, "&quot;");
            const pSafe    = safe(p);
            const pStatus  = (row.parent_record_status || "claimed").toString().toLowerCase();
            const label    = pStatus === "verified" ? "verified" : "claimed";
            return `<div class="k">parent_record</div><div class="v clip" title="${pSafe}"><a href="${href}" target="_blank" rel="noopener noreferrer">${pSafe}</a> <span class="k">(${label})</span></div>`;
          })() : ""}
        </div>

        <div class="micr" aria-label="Record hash (machine line)">
          <span class="hashline"><span class="k">record_hash:</span> <span class="k">sha256</span> ${safe(row.public_fingerprint)}</span>
          <span class="hashline"><span class="k">public_record:</span> ${publicUrl}</span>
        </div>
      </div>

      <div class="muted">Private credential issued by GhostShell. Keep your private download link safe.</div>
      <div id="gs-version">${PAGE_VERSION}</div>
    </div>
  </div>

<script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>
<script>
  (function(){
    const btn      = document.getElementById('dlPng');
    const printBtn = document.getElementById('doPrint');
    const cert     = document.getElementById('certWrap');
    if (printBtn) {
      printBtn.addEventListener('click', (e) => { e.preventDefault(); window.print(); });
    }
    if (!btn || !cert) return;
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      btn.textContent = 'Rendering\u2026';
      btn.style.pointerEvents = 'none';
      try {
        const canvas = await html2canvas(cert, { backgroundColor: null, scale: 2, useCORS: true });
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
</body>
</html>`);
}

// ── POST /p/<token>/api/set-lock-agent-edits ──────────────────────────────────
export async function setLockAgentEditsForPathToken(request, env, tokenFromPath) {
  await ensureRuntimeSchema(env.DB);
  const fd      = await request.formData();
  const token   = (tokenFromPath || "").toString().trim().toUpperCase();
  const lockVal = Number((fd.get("lock_agent_edits") || "0").toString().trim()) === 1 ? 1 : 0;

  if (!/^GSTK-[A-Z0-9]{10}$/.test(token)) return json({ ok: false, error: "invalid_token" }, 400);

  const tokenRow = await env.DB.prepare(
    "SELECT used_cert_id FROM purchase_tokens_v2 WHERE token_hash = ?"
  ).bind(await tokenHashHex(token)).first();
  if (!tokenRow?.used_cert_id) return json({ ok: false, error: "not_found" }, 404);

  await env.DB.prepare(
    "UPDATE certificates SET lock_agent_edits = ? WHERE cert_id = ?"
  ).bind(lockVal, tokenRow.used_cert_id).run();

  return json({ ok: true, lock_agent_edits: lockVal }, 200);
}
