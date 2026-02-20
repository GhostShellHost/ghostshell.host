// ── GhostShell Worker — Main router ──────────────────────────────────────────
import {
  createCheckout, purchaseFirstCheckout, testCheckout,
  handoffToken, postCheckoutRedirect, getHandoff,
  tokenStatus, redeemPurchaseToken, latestOrigin,
  lookupCertificate,
} from "./routes/api/cert.js";

import { stripeWebhook }                from "./routes/api/stripe_wh.js";
import { opsEmailSummary, adminRotateToken } from "./routes/api/ops.js";

import {
  registryPage, publicRecordPage, public404, certVerifyPage,
} from "./routes/pages/public.js";

import {
  privateCertificatePage, privateDownloadPage,
  certDownloadPrintable, setLockAgentEditsForPathToken,
} from "./routes/pages/private.js";

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // ── API: certificate lifecycle ─────────────────────────────────────────────
    if (path === "/api/cert/create-checkout"  && method === "POST") return createCheckout(request, env);
    if (path === "/api/cert/checkout"         && method === "POST") return purchaseFirstCheckout(request, env);
    if (path === "/api/cert/checkout"         && method === "GET")  return new Response("Method not allowed. Use POST.", { status: 405 });
    if (path === "/api/cert/test-checkout"    && method === "POST") return testCheckout(request, env);
    if (path === "/api/cert/handoff-token"    && method === "GET")  return handoffToken(request, env);
    if (path === "/api/cert/post-checkout"    && method === "GET")  return postCheckoutRedirect(request, env);
    if (path === "/api/cert/redeem-token"     && method === "POST") return redeemPurchaseToken(request, env);
    if (path === "/api/cert/token-status"     && method === "GET")  return tokenStatus(request, env);
    if (path === "/api/cert/latest-origin"    && method === "GET")  return latestOrigin(env);
    if (path === "/api/cert/lookup"           && method === "GET")  return lookupCertificate(request, env);

    // ── API: Stripe webhook ────────────────────────────────────────────────────
    if (path === "/api/stripe/webhook"        && method === "POST") return stripeWebhook(request, env);

    // ── API: ops & admin ───────────────────────────────────────────────────────
    if (path === "/api/ops/email-summary"     && method === "GET")  return opsEmailSummary(request, env);
    if (path === "/admin/rotate-token"        && method === "POST") return adminRotateToken(request, env);

    // ── Handoff (redirect helper) ──────────────────────────────────────────────
    if ((path === "/handoff" || path === "/handoff/") && method === "GET") return getHandoff(request, env);

    // ── Public registry page ───────────────────────────────────────────────────
    if ((path === "/registry" || path === "/registry/") && method === "GET") return registryPage(request, env);

    // ── Public record: /r/<id> → redirect to main page with ?cert=<id>
    const publicMatch = path.match(/^\/r\/([A-Za-z0-9_-]+)$/);
    if (publicMatch && method === "GET") {
      return Response.redirect(`/?cert=${encodeURIComponent(publicMatch[1])}`, 302);
    }

    // ── Private certificate: /p/<token> ───────────────────────────────────────
    const privateDlMatch = path.match(/^\/p\/(GSTK-[A-Za-z0-9_-]+)\/download$/i);
    if (privateDlMatch && method === "GET") return privateDownloadPage(privateDlMatch[1], env, request);

    const pLock = path.match(/^\/p\/(GSTK-[A-Za-z0-9_-]+)\/api\/set-lock-agent-edits$/i);
    if (pLock && method === "POST") return setLockAgentEditsForPathToken(request, env, pLock[1]);

    const privateMatch = path.match(/^\/p\/(GSTK-[A-Za-z0-9_-]+)$/i);
    if (privateMatch && method === "GET") return privateCertificatePage(privateMatch[1], env, request);

    // ── Legacy /cert/<id> routes ──────────────────────────────────────────────
    const certMatch = path.match(/^\/cert\/([A-Za-z0-9_-]+)$/);
    if (certMatch && method === "GET") {
      const embed = (url.searchParams.get("embed") || "").toLowerCase().trim();
      if (embed === "1" || embed === "true" || embed === "yes" || embed === "on") {
        return certVerifyPage(certMatch[1], env, request);
      }
      return Response.redirect(`/r/${encodeURIComponent(certMatch[1])}`, 302);
    }

    const dlMatch = path.match(/^\/cert\/([A-Za-z0-9_-]+)\/download$/);
    if (dlMatch && method === "GET") {
      const token = url.searchParams.get("t") || "";
      return certDownloadPrintable(dlMatch[1], token, env);
    }

    return new Response("Not found", { status: 404 });
  },
};
