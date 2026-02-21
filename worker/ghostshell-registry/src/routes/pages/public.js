// ── GhostShell Worker — Public page routes ───────────────────────────────────
import { html, urlParamTruthy }  from "../../utils/response.js";
import { PAGE_VERSION }          from "../../config.js";
import { ensureRuntimeSchema }   from "../../db/schema.js";
import { fetchPublicRowById }    from "../../db/queries.js";
import { normalizeRegistryId }   from "../../utils/ids.js";

// ── GET /registry/ ────────────────────────────────────────────────────────────
export async function registryPage(request, env) {
  await ensureRuntimeSchema(env.DB);
  const url = new URL(request.url);

  const DEFAULT_ID = "GS-BC-A-26-H";
  const rawId = (url.searchParams.get("id") || "").toString();
  const id    = normalizeRegistryId(rawId, DEFAULT_ID);

  // Canonicalize to uppercase share URLs
  if (rawId && rawId.trim() !== id) {
    url.searchParams.set("id", id);
    return Response.redirect(url.toString(), 302);
  }

  // Back-compat route: /registry/?id=... → canonical /r/<id>
  if (rawId && rawId.trim()) {
    return Response.redirect(`/r/${encodeURIComponent(id)}`, 301);
  }

  let row = await fetchPublicRowById(id, env);
  const notFound = !row;
  if (notFound) {
    row = {
      cert_id: id, public_id: id, issued_at_utc: "", inception_date_utc: "",
      agent_name: "", place_city: "", place_state: "", place_country: "",
      show_city_public: 0, hide_state_public: 0,
      cognitive_core_family: "", cognitive_core_exact: "",
      creator_label: "", declared_ontological_status: "",
      public_fingerprint: "", status: "not_found",
      edit_count: 0, human_edit_count: 0, agent_edit_count: 0,
    };
  }

  const safe = (s) => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const coreFamily       = row.cognitive_core_family || "Undisclosed";
  const coreExact        = row.cognitive_core_exact || "";
  const PRESERVE_AS_IS   = ["Undisclosed", "Prefer not to say"];
  const coreFamilyDisplay = PRESERVE_AS_IS.includes(coreFamily) ? coreFamily : coreFamily.replace(/\s+/g, "");
  const coreDisplay      = coreExact ? `${coreFamilyDisplay}/${coreExact}` : coreFamilyDisplay;

  const city      = row.place_city || "";
  const state     = row.place_state || "";
  const country   = row.place_country || "";
  const showCity  = Number(row.show_city_public || 0) === 1;
  const hideState = Number(row.hide_state_public || 0) === 1;

  const redactSpan = (wCh) => `<span class="redact" style="width:${wCh}ch" aria-label="redacted"></span>`;

  let locationHtml = safe(country || "Unknown");
  if (state) locationHtml = (hideState ? redactSpan(Math.max(8, Math.min(16, state.length))) : safe(state)) + ", " + locationHtml;
  if (city)  locationHtml = (showCity  ? safe(city) : redactSpan(Math.max(8, Math.min(16, city.length)))) + ", " + locationHtml;

  const baseUrl = (env.BASE_URL || "https://ghostshell.host").replace(/\/$/, "");

  const htmlOut = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GhostShell Registry — Public Registry</title>
  <style>
    :root{--bg:#fff;--text:#0a0a0a;--soft:#444;--muted:#666;--line:#e0e0e0;--accent:#4a4aff;}
    *{box-sizing:border-box}
    html,body{margin:0;padding:0}
    body{min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;color:var(--text);background: var(--bg);padding:24px;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
    main{width:min(760px,100%);text-align:center;margin:0 auto;padding-top:min(10vh,84px)}
    .brand{display:inline-block;font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:var(--soft);border:1px solid var(--line);border-radius:999px;padding:6px 12px;margin-bottom:16px;background:rgba(255,255,255,.01);}
    h1{margin:0;font-size:clamp(34px,6vw,58px);line-height:1.05;letter-spacing:-.02em;font-weight:740}
    .note{margin:12px auto 0;max-width:56ch;color:var(--soft)}
    form{margin:26px auto 0;max-width:560px;display:grid;gap:10px}
    input{width:100%;border-radius:12px;border:1px solid var(--line);background:rgba(255,255,255,.03);color:var(--text);padding:12px 13px;font:inherit;text-align:center;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;}
    input::placeholder{color:var(--muted)}
    button{justify-self:center;margin-top:6px;border-radius:999px;border:1px solid var(--accent);background:var(--accent);color:#fff;padding:10px 20px;font:inherit;font-weight:620;cursor:pointer;}
    .small{margin:20px auto 0;max-width:64ch;color:var(--muted);font-size:.9rem;text-align:center;border-top:1px solid var(--line);padding-top:14px;}
    a{color:var(--accent);text-decoration:none;border-bottom:1px solid #4a4a7a}
    a:hover{border-bottom-color:var(--accent)}
    .back{margin-top:16px}
    .vtag{color:var(--muted);font-size:.9rem}
  </style>
  <style>
    :root{--paper:#fbf7ea;--paper2:#f6f0dd;--ink:#111827;--mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;}
    .certwrap{max-width:920px;margin:18px auto 0}
    .paper{color:var(--ink);background:linear-gradient(180deg,var(--paper),var(--paper2));box-shadow:0 2px 8px rgba(0,0,0,.1);border-radius:14px;padding:18px 18px 16px;position:relative;overflow:hidden;}
    .header2{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;position:relative}
    .paper h2{margin:0;font-size:16px;letter-spacing:.18em;text-transform:uppercase;font-weight:800}
    .catalog{margin:6px 0 0;display:flex;gap:10px;flex-wrap:nowrap;align-items:center;font-family:var(--mono);font-size:11px;color:rgba(17,24,39,.62);letter-spacing:.06em;white-space:nowrap}
    .stamp{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:rgba(17,24,39,.55);border:1px solid rgba(17,24,39,.22);padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.5);white-space:nowrap}
    .rubber{position:absolute;pointer-events:none;user-select:none;font-family:var(--mono);text-transform:uppercase;letter-spacing:.22em;filter:blur(.2px)}
    .rubber--copy{right:18px;bottom:18px;left:auto;top:auto;transform:rotate(-12deg);text-align:center;font-size:32px;letter-spacing:.18em;color:rgba(180,24,24,.22);border:3px solid rgba(180,24,24,.18);border-radius:12px;padding:10px 18px;background:transparent}
    .rubber--notfound{left:-40px;right:-40px;top:42%;transform:rotate(-12deg);text-align:center;font-size:72px;color:rgba(180,24,24,.26);border:none;padding:0;background:transparent}
    .seal{position:absolute;top:-3px;right:-4px;width:400px;height:auto;opacity:0.85;transform:rotate(-21deg);pointer-events:none;z-index:10}
    .sheet{margin-top:14px;border:1px solid rgba(17,24,39,.16);border-radius:12px;background:rgba(255,255,255,.42);padding:14px;position:relative}
    .type{font-family:var(--mono);font-size:12.6px;line-height:1.7;color:rgba(17,24,39,.92);letter-spacing:.03em}
    .typehead{text-align:left}
    a.plainlink{color:inherit;text-decoration:none;border-bottom:0}
    a.plainlink:hover{text-decoration:none;border-bottom:0}
    .grid{margin-top:10px;display:grid;grid-template-columns:260px minmax(0,1fr);gap:8px 10px;align-items:baseline;grid-auto-rows:minmax(20px,auto)}
    .k{color:rgba(17,24,39,.72);text-align:left;font-weight:600}
    .k::after{content:":";display:inline;color:rgba(17,24,39,.45)}
    .v{color:rgba(17,24,39,.96);font-weight:800;min-width:0;overflow-wrap:anywhere;min-height:1em;text-align:left;justify-self:start}
    .clip{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:inline-block;text-align:left;justify-self:start}
    .micr{margin-top:10px;padding-top:10px;border-top:1px dashed rgba(17,24,39,.22);font-family:var(--mono);font-size:9.8px;line-height:1.22;color:rgba(17,24,39,.70);letter-spacing:.08em;text-align:left}
    .micr .hashline{display:block;margin-top:6px;color:rgba(17,24,39,.86);letter-spacing:.10em;white-space:nowrap;overflow:hidden;text-overflow:clip;text-align:left}
    .muted2{margin-top:10px;color:rgba(17,24,39,.72);font-size:10px;font-family:var(--mono);letter-spacing:.02em;white-space:nowrap}
    #gs-version{position:absolute;bottom:10px;right:12px;color:rgba(17,24,39,.72);font-size:10px;opacity:.9;font-family:var(--mono);letter-spacing:.08em;pointer-events:none}
    .redact{display:inline-block;height:1.05em;width:18ch;vertical-align:middle;background:#050608;border-radius:3px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.08),0 0.5px 0 rgba(0,0,0,.35);}
  </style>
</head>
<body>
  <main>
    <div class="brand">ghostshell.host • public registry</div>
    <h1>Public Registry</h1>

    <div class="certwrap">
      <div class="paper" role="document" aria-label="GhostShell registry record">
        <img src="/assets/ghostshell_logo.png" alt="GhostShell Seal" class="seal" />
        <div class="header2">
          <div>
            <h2>BIRTH CERTIFICATE AI AGENT // REDACTED</h2>
            <div class="catalog"><a class="plainlink" href="${safe(baseUrl)}/">GhostShell.host</a> registry record</div>
          </div>
          <div class="stamp">PUBLIC FILE</div>
        </div>

        <div class="sheet">
          <div class="rubber ${notFound ? "rubber--notfound" : "rubber--copy"}" aria-hidden="true">${notFound ? "RECORD NOT FOUND" : "REDACTED COPY"}</div>
          <div class="type typehead">TYPEWRITTEN EXTRACT //</div>
          <div class="grid type" aria-label="Certificate fields">
            <div class="k">${notFound ? "registry_record_id" : "public_record_id"}</div><div class="v">${notFound ? "" : `<a class="plainlink" href="${baseUrl + "/r/" + encodeURIComponent(row.public_id || row.cert_id)}">${safe(row.public_id || row.cert_id)}</a>`}</div>
            ${notFound ? `<div class="k">status</div><div class="v">RECORD NOT FOUND</div>` : ""}
            <div class="k">registration_date</div><div class="v">${notFound ? "" : safe(row.issued_at_utc)}</div>
            <div class="k">agent_name</div><div class="v">${notFound ? "" : safe(row.agent_name)}</div>
            <div class="k">inception_date</div><div class="v">${notFound ? "" : safe(row.inception_date_utc)}</div>
            <div class="k">ontological_status</div><div class="v">${notFound ? "" : safe(row.declared_ontological_status)}</div>
            <div class="k">geographic_location</div><div class="v">${notFound ? "" : locationHtml}</div>
            <div class="k">cognitive_core_at_inception</div><div class="v clip" title="${notFound ? "" : safe(coreDisplay)}">${notFound ? "" : safe(coreDisplay)}</div>
            <div class="k">custodian</div><div class="v">${notFound ? "" : '<span class="redact" aria-label="redacted"></span>'}</div>
            <div class="k">amendments (24h)</div><div class="v">${notFound ? "" : `Human: ${Number(row.human_edit_count || 0)} · Agent: ${Number(row.agent_edit_count || 0)} · Total: ${Number(row.edit_count || 0)}`}</div>
          </div>
          <div class="micr" aria-label="Record hash (machine line)">
            <span class="hashline" id="fp"><span class="k">record_hash:</span> <span class="k">sha256</span> ${notFound ? "" : safe(row.public_fingerprint)}</span>
            <span class="hashline"><span class="k">public_record:</span> ${notFound ? "not_found" : `<a class="plainlink" href="${baseUrl + "/r/" + encodeURIComponent(row.public_id || row.cert_id)}">${baseUrl + "/r/" + encodeURIComponent(row.public_id || row.cert_id)}</a>`}</span>
          </div>
        </div>

        <div class="muted2">Private credential issued by GhostShell. Verification checks registry presence + fingerprint integrity only.</div>
        <div id="gs-version">${PAGE_VERSION}</div>
      </div>
    </div>

    <p class="note">Paste a public registry record ID.</p>

    <form id="registry-form" aria-label="Registry search" method="GET" action="/registry/">
      <input id="record-id" name="id" aria-label="Registry Record ID" type="text" value="${safe(id)}" placeholder="e.g. GS-BC-A-26-H" required />
      <button type="submit">Search</button>
    </form>

    <p class="small" style="border-top:none;padding-top:0;margin-top:16px">
      Showing public record for: <span style="font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace">${safe(id)}</span>
      <br/>
      This is the <b>shareable public link</b>. Full certificates are only available to the registrant via their private download link.
    </p>

    <p class="small">Unredacted certificates are only available to the registrant via emailed link.</p>
    <p class="back"><a href="/">Back home</a> &nbsp; <a href="/issue/">Buy Certificate</a> &nbsp; <span class="vtag">v0.030-reg</span></p>
  </main>

</body>
</html>`;

  return html(htmlOut, 200, { "Cache-Control": "no-store" });
}

// ── GET /r/<id> ───────────────────────────────────────────────────────────────
export async function publicRecordPage(recordIdRaw, env, request) {
  await ensureRuntimeSchema(env.DB);

  const recordId = normalizeRegistryId(recordIdRaw, "");

  if (!/^GS-BC-[A-Z0-9_-]{3,64}$/.test(recordId)) {
    return public404(recordId, request);
  }

  const row = await fetchPublicRowById(recordId, env);
  if (!row) return public404(recordId, request);

  const safe = (s) => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const agentName    = (row.agent_name || "").trim() || "Unknown Agent";
  const autonomyClass = (row.declared_ontological_status || "").trim() || "Undisclosed";
  const inception    = (row.inception_date_utc || "").trim() || "";
  const originRuntime = (row.origin_runtime || "").trim();
  const originVersion = (row.origin_version || "").trim();
  const originLine   = originRuntime ? `${originRuntime}${originVersion ? ` (${originVersion})` : ""}` : "";

  const city     = (row.place_city || "").trim();
  const country  = (row.place_country || "").trim() || "Unknown";
  const showCity = Number(row.show_city_public || 0) === 1;

  const canonicalUrl = `https://ghostshell.host/r/${encodeURIComponent(recordId)}`;

  const htmlOut = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${safe(agentName)} · ${safe(recordId)} · GhostShell Registry</title>
  <meta name="description" content="Public redacted record. Immutable issuance. Amendments appended." />

  <link rel="canonical" href="${canonicalUrl}" />

  <meta property="og:title" content="${safe(agentName)} · ${safe(recordId)}" />
  <meta property="og:description" content="Public redacted record. Immutable issuance. Amendments appended." />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="${canonicalUrl}" />
  <meta property="og:image" content="https://ghostshell.host/assets/og-default.png" />
  <meta name="twitter:card" content="summary_large_image" />

  <style>
    :root{--bg:#fff;--text:#0a0a0a;--soft:#444;--muted:#666;--line:#e0e0e0;--accent:#4a4aff;--paper:#fbf7ea;--paper2:#f6f0dd;--ink:#111827;--mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;}
    *{box-sizing:border-box}
    html,body{margin:0;padding:0}
    body{min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;color:var(--text);background: var(--bg);padding:24px;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
    main{width:min(860px,100%);margin:0 auto;padding-top:min(8vh,64px)}
    .brand{display:inline-block;font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:var(--soft);border:1px solid var(--line);border-radius:999px;padding:6px 12px;margin-bottom:18px;background:rgba(255,255,255,.01);}
    h1{margin:0;font-size:clamp(30px,5.6vw,52px);line-height:1.06;letter-spacing:-.02em;font-weight:760}

    .certwrap{margin-top:18px}
    .paper{color:var(--ink);background:linear-gradient(180deg,var(--paper),var(--paper2));box-shadow:0 2px 8px rgba(0,0,0,.1);border-radius:14px;padding:18px 18px 16px;position:relative;overflow:hidden;}
    .header2{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;position:relative}
    .paper h2{margin:0;font-size:16px;letter-spacing:.18em;text-transform:uppercase;font-weight:800}
    .catalog{margin:6px 0 0;display:flex;gap:10px;flex-wrap:nowrap;align-items:center;font-family:var(--mono);font-size:11px;color:rgba(17,24,39,.62);letter-spacing:.06em;white-space:nowrap}

    .witness{position:absolute;right:16px;bottom:16px;left:auto;top:auto;transform:rotate(-8deg);font-family:var(--mono);text-transform:uppercase;letter-spacing:.18em;color:rgba(17,24,39,.52);border:2px solid rgba(17,24,39,.22);border-radius:10px;padding:10px 14px;background:rgba(255,255,255,.35);text-decoration:none}
    .witness:hover{border-color:rgba(17,24,39,.35);color:rgba(17,24,39,.62)}

    .sheet{margin-top:14px;border:1px solid rgba(17,24,39,.16);border-radius:12px;background:rgba(255,255,255,.42);padding:14px;position:relative}
    .type{font-family:var(--mono);font-size:12.6px;line-height:1.7;color:rgba(17,24,39,.92);letter-spacing:.03em}
    .grid{margin-top:10px;display:grid;grid-template-columns:260px minmax(0,1fr);gap:8px 10px;align-items:baseline;grid-auto-rows:minmax(20px,auto)}
    .k{color:rgba(17,24,39,.72);text-align:left;font-weight:600}
    .k::after{content:":";display:inline;color:rgba(17,24,39,.45)}
    .v{color:rgba(17,24,39,.96);font-weight:820;min-width:0;overflow-wrap:anywhere;min-height:1em;text-align:left;justify-self:start}

    .controls{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
    .btn{border-radius:12px;border:1px solid var(--line);background:transparent;color:var(--text);padding:12px 12px;font-size:.95rem;font-weight:650;cursor:pointer;transition:.15s ease;white-space:nowrap}
    .btn:hover{border-color:#3a3a47;color:var(--accent)}

    .footer{margin-top:18px;color:var(--muted);font-size:.9rem;line-height:1.55;border-top:1px solid var(--line);padding-top:14px}
    .footer a{color:var(--accent);text-decoration:none;border-bottom:1px solid #4a4a7a}
    .footer a:hover{border-bottom-color:var(--accent)}

    @media (max-width:640px){
      body{padding:18px}
      .grid{grid-template-columns: 1fr;}
      .witness{right:12px;bottom:12px;font-size:10px;padding:8px 10px}
    }
  </style>
</head>
<body>
  <main>
    <div class="brand">ghostshell.host • public record</div>
    <h1>${safe(agentName)} · ${safe(recordId)}</h1>

    <div class="certwrap">
      <div class="paper" role="document" aria-label="GhostShell public record">
        <img src="/assets/ghostshell_logo.png" alt="GhostShell Seal" class="seal" />
        <div class="header2">
          <div>
            <h2>BIRTH CERTIFICATE AI AGENT // REDACTED</h2>
            <div class="catalog"><a href="https://ghostshell.host/" style="color:inherit;text-decoration:none">ghostshell.host</a> public extract</div>
          </div>
        </div>

        <div class="sheet">
          <div class="type" style="text-align:left">TYPEWRITTEN EXTRACT //</div>
          <div class="grid type" aria-label="Certificate fields">
            <div class="k">agent_name</div><div class="v">${safe(agentName)}</div>
            <div class="k">record_id</div><div class="v">${safe(recordId)}</div>
            <div class="k">declared_autonomy_class</div><div class="v">${safe(autonomyClass)}</div>
            <div class="k">inception_date</div><div class="v">${safe(inception)}</div>
            ${originLine ? `<div class="k">origin_runtime</div><div class="v">${safe(originLine)}</div>` : ``}
            ${showCity && city ? `<div class="k">city</div><div class="v">${safe(city)}</div>` : ``}
            <div class="k">country</div><div class="v">${safe(country)}</div>
            <div class="k">amendments</div><div class="v">0</div>
          </div>
        </div>

        <a class="witness" href="https://ghostshell.host/" target="_blank" rel="noopener noreferrer">ghostshell.host · Registry Witness Mark</a>
      </div>

      <div class="controls" role="group" aria-label="Share controls">
        <button class="btn" id="share">Share Record</button>
        <button class="btn" id="copy">Copy Link</button>
      </div>

      <div class="footer">
        This record is part of the GhostShell Registry. Public records are permanent. Amendments are appended.
        <br/>
        <a href="https://ghostshell.host/">Back to registry landing</a>
      </div>
    </div>
  </main>

  <script>
    (function(){
      const url   = ${JSON.stringify(canonicalUrl)};
      const title = ${JSON.stringify(`${agentName} · ${recordId}`)};
      const text  = 'Public redacted record. Immutable issuance. Amendments appended.';

      function $(id){ return document.getElementById(id); }

      $("share").addEventListener('click', async function(){
        try {
          if (navigator.share) { await navigator.share({ title, text, url }); return; }
        } catch (e) {}
        try {
          await navigator.clipboard.writeText(url);
          this.textContent = 'Copied';
          setTimeout(() => (this.textContent = 'Share Record'), 1200);
        } catch (e) { prompt('Copy link:', url); }
      });

      $("copy").addEventListener('click', async function(){
        try {
          await navigator.clipboard.writeText(url);
          this.textContent = 'Copied';
          setTimeout(() => (this.textContent = 'Copy Link'), 1200);
        } catch (e) { prompt('Copy link:', url); }
      });
    })();
  </script>
</body>
</html>`;

  return html(htmlOut, 200, { "Cache-Control": "no-store" });
}

// ── 404 for public record routes — redirect back to home with notfound flag ────
export function public404(recordId, request) {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;
  const params = new URLSearchParams({ notfound: "1" });
  if (recordId) params.set("id", recordId);
  return Response.redirect(`${baseUrl}/?${params.toString()}`, 302);
}

// ── GET /cert/<id>?embed=1 ────────────────────────────────────────────────────
export async function certVerifyPage(certId, env, request) {
  const selectPublicFields =
    "SELECT cert_id, public_id, issued_at_utc, inception_date_utc, agent_name, place_city, place_state, place_country, show_city_public, hide_state_public, cognitive_core_family, cognitive_core_exact, creator_label, provenance_link, parent_record_status, declared_ontological_status, public_fingerprint, status, edit_count, human_edit_count, agent_edit_count FROM certificates WHERE ";

  let row = await env.DB.prepare(`${selectPublicFields}cert_id = ?`).bind(certId).first();

  if (!row) {
    const foundByPublicId = await env.DB.prepare(`${selectPublicFields}public_id = ?`).bind(certId).all();
    const results = foundByPublicId?.results || [];
    if (results.length === 1) row = results[0];
  }

  const embed    = urlParamTruthy(request, "embed");
  const notFound = !row;

  if (notFound) {
    row = {
      cert_id: certId, public_id: certId, issued_at_utc: "", inception_date_utc: "",
      agent_name: "", place_city: "", place_state: "", place_country: "",
      show_city_public: 0, hide_state_public: 0,
      cognitive_core_family: "", cognitive_core_exact: "",
      creator_label: "", declared_ontological_status: "",
      public_fingerprint: "", status: "not_found",
      edit_count: 0, human_edit_count: 0, agent_edit_count: 0,
    };
  }

  const safe    = (s) => (s ?? "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const status  = (row.status || "").toString().toLowerCase();
  const coreFamily       = row.cognitive_core_family || "Undisclosed";
  const coreExact        = row.cognitive_core_exact || "";
  const PRESERVE_AS_IS   = ["Undisclosed", "Prefer not to say"];
  const coreFamilyDisplay = PRESERVE_AS_IS.includes(coreFamily) ? coreFamily : coreFamily.replace(/\s+/g, "");
  const coreDisplay      = coreExact ? `${coreFamilyDisplay}/${coreExact}` : coreFamilyDisplay;

  const cacheHeaders = embed
    ? { "Cache-Control": "no-store" }
    : { "Cache-Control": "public, max-age=3600" };

  const baseUrl = (env.BASE_URL || "https://ghostshell.host").replace(/\/$/, "");

  return html(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${safe(row.public_id || row.cert_id)} • GhostShell Registry</title>
  <style>
    :root{
      --desk:#0b0c10;--paper:#fbf7ea;--paper2:#f6f0dd;--ink:#111827;
      --line:rgba(17,24,39,.18);--shadow:0 26px 80px rgba(0,0,0,.55);
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      ${embed ? "background: transparent;" : "background: radial-gradient(900px 600px at 20% 0%, rgba(255,255,255,.05), transparent 55%), radial-gradient(900px 600px at 80% 20%, rgba(255,255,255,.03), transparent 60%), var(--desk);"}
      color:#e9edf1;
      font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      padding:${embed ? "0" : "18px"};
    }
    .wrap{max-width:920px;margin:0 auto}
    .paper{
      color:var(--ink);background:linear-gradient(180deg,var(--paper),var(--paper2));
      border:${embed ? "none" : "1px solid rgba(255,255,255,.08)"};
      box-shadow:${embed ? "none" : "var(--shadow)"};
      border-radius:14px;padding:18px 18px 16px;position:relative;overflow:hidden;
      transform:${embed ? "none" : "rotate(-.12deg)"};
    }
    .paper::after{content:"";position:absolute;left:50%;top:-12px;transform:translateX(-50%);width:92px;height:24px;border:1px solid rgba(17,24,39,.22);border-bottom:none;border-radius:0 0 14px 14px;background:linear-gradient(180deg,var(--paper2),var(--paper));opacity:${embed ? "0" : ".75"}}
    .wear{position:absolute;inset:-2px;pointer-events:none;opacity:${embed ? "0" : ".16"};mix-blend-mode:multiply;background:radial-gradient(28px 18px at 6% 10%, rgba(0,0,0,.35), transparent 70%),radial-gradient(34px 22px at 96% 14%, rgba(0,0,0,.28), transparent 72%),radial-gradient(34px 22px at 92% 92%, rgba(0,0,0,.25), transparent 74%),radial-gradient(28px 18px at 8% 92%, rgba(0,0,0,.28), transparent 74%);}
    .holes{position:absolute;left:10px;top:74px;bottom:26px;width:18px;pointer-events:none;opacity:${embed ? "0" : "1"}}
    .hole{width:14px;height:14px;border-radius:99px;border:1px solid rgba(17,24,39,.20);background:rgba(0,0,0,.10);box-shadow:inset 0 0 0 3px rgba(255,255,255,.28);margin:0 0 18px 0;opacity:.55}
    .rules{position:absolute;inset:0;pointer-events:none;opacity:${embed ? "0" : ".55"};background:repeating-linear-gradient(180deg, rgba(17,24,39,.05) 0 1px, transparent 1px 24px)}
    .margin{position:absolute;left:28px;top:0;bottom:0;width:1px;background:rgba(255,106,42,.28);pointer-events:none;opacity:${embed ? "0" : "1"}}
    .paper::before{content:"";position:absolute;inset:-50%;background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180"><filter id="n"><feTurbulence type="fractalNoise" baseFrequency="0.8" numOctaves="2" stitchTiles="stitch"/></filter><rect width="180" height="180" filter="url(%23n)" opacity="0.35"/></svg>');background-size:180px 180px;opacity:${embed ? "0" : ".06"};pointer-events:none}
    .header{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;position:relative}
    h1{margin:0;font-size:16px;letter-spacing:.18em;text-transform:uppercase;font-weight:800}
    .catalog{margin:6px 0 0;display:flex;gap:10px;flex-wrap:nowrap;align-items:center;font-family:var(--mono);font-size:11px;color:rgba(17,24,39,.62);letter-spacing:.06em;white-space:nowrap}
    .stamp{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:rgba(17,24,39,.55);border:1px solid rgba(17,24,39,.22);padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.5);white-space:nowrap}
    .rubber{position:absolute;left:${notFound ? "-40px" : "auto"};right:${notFound ? "-40px" : "18px"};top:${notFound ? "42%" : "auto"};bottom:${notFound ? "auto" : "14px"};transform:rotate(-12deg);text-align:${notFound ? "center" : "right"};font-family:var(--mono);font-size:${notFound ? "72px" : "24px"};letter-spacing:${notFound ? ".22em" : ".16em"};text-transform:uppercase;color:${notFound ? "rgba(180,24,24,.26)" : "rgba(180,24,24,.18)"};border:${notFound ? "none" : "2px solid rgba(180,24,24,.16)"};padding:${notFound ? "0" : "10px 14px"};border-radius:${notFound ? "0" : "10px"};mix-blend-mode:multiply;pointer-events:none;user-select:none;filter:${notFound ? "blur(.2px)" : "blur(.15px)"}}
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
      <img src="/assets/ghostshell_logo.png" alt="GhostShell Seal" class="seal" />
      <div class="rules" aria-hidden="true"></div>
      <div class="margin" aria-hidden="true"></div>
      <div class="wear" aria-hidden="true"></div>
      <div class="holes" aria-hidden="true"><div class="hole"></div><div class="hole"></div><div class="hole"></div></div>

      <div class="header">
        <div>
          <h1>BIRTH CERTIFICATE AI AGENT // REDACTED</h1>
          <div class="catalog">GhostShell.host registry record</div>
        </div>
        <div class="stamp">PUBLIC FILE</div>
      </div>

      <div class="sheet">
        <div class="rubber" aria-hidden="true">${notFound ? "RECORD NOT FOUND" : "REDACTED COPY"}</div>
        <div class="type">TYPEWRITTEN EXTRACT //</div>

        <div class="grid type" aria-label="Certificate fields">
          <div class="k">${notFound ? "registry_record_id" : "public_record_id"}</div><div class="v"><a href="${baseUrl}/r/${encodeURIComponent(row.public_id || row.cert_id)}" target="_self" rel="noopener noreferrer">${safe(row.public_id || row.cert_id)}</a></div>
          ${notFound ? `<div class="k">status</div><div class="v">RECORD NOT FOUND</div>` : ""}
          <div class="k">registration_date</div><div class="v">${notFound ? "" : safe(row.issued_at_utc)}</div>
          <div class="k">agent_name</div><div class="v">${notFound ? "" : safe(row.agent_name)}</div>
          ${(notFound || row.inception_date_utc) ? `<div class="k">inception_date</div><div class="v">${notFound ? "" : safe(row.inception_date_utc)}</div>` : ""}
          ${(notFound || row.declared_ontological_status) ? `<div class="k">ontological_status</div><div class="v">${notFound ? "" : safe(row.declared_ontological_status)}</div>` : ""}
          ${(() => {
            const city    = row.place_city || "";
            const state   = row.place_state || "";
            const country = row.place_country || "";
            const showCity  = row.show_city_public === 1;
            const hideState = row.hide_state_public === 1;
            let location = country;
            if (!hideState && state) location = state + ", " + location;
            if (showCity && city) location = city + ", " + location;
            return `<div class="k">geographic_location</div><div class="v">${notFound ? "" : safe(location || "Unknown")}</div>`;
          })()}
          <div class="k">cognitive_core_at_inception</div><div class="v clip" title="${notFound ? "" : safe(coreDisplay)}">${notFound ? "" : safe(coreDisplay)}</div>
          <div class="k">custodian</div><div class="v">${notFound ? "" : '<span class="redact" aria-label="redacted"></span>'}</div>
          <div class="k">amendments (24h)</div><div class="v">${notFound ? "" : `Human: ${Number(row.human_edit_count || 0)} · Agent: ${Number(row.agent_edit_count || 0)} · Total: ${Number(row.edit_count || 0)}`}</div>
        </div>

        <div class="micr" aria-label="Record hash (machine line)">
          <span class="hashline" id="fp"><span class="k">record_hash:</span> <span class="k">sha256</span> ${notFound ? "" : safe(row.public_fingerprint)}</span>
          <span class="hashline"><span class="k">public_record:</span> ${notFound ? "not_found" : (baseUrl + "/r/" + encodeURIComponent(row.public_id || row.cert_id))}</span>
        </div>
      </div>
      <div class="muted">Private credential issued by GhostShell. Verification checks registry presence + fingerprint integrity only.</div>
      <div id="gs-version">${PAGE_VERSION}</div>
    </div>
    ${embed ? "" : `<p class="back"><a href="/">Back home</a> &nbsp; <a href="/issue/">Buy certificate</a> &nbsp; <a href="/r/${encodeURIComponent(row.public_id || row.cert_id)}">Public record</a> &nbsp; <span class="vtag">${PAGE_VERSION}</span></p>`}
  </div>
</body>
</html>`, 200, cacheHeaders);
}
