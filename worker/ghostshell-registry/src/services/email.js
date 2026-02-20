// ── GhostShell Worker — Email service ────────────────────────────────────────
import { isValidEmail } from "../utils/ids.js";

export const EMAIL_FOOTER_TEXT = [
  "—",
  "GhostShell Registry",
  "https://ghostshell.host",
  "support@ghostshell.host",
  "You are receiving this transactional email because you started or completed a GhostShell checkout.",
].join("\n");

export const EMAIL_FOOTER_HTML = `
  <hr style="margin:20px 0;border:none;border-top:1px solid #e5e7eb" />
  <p style="font-size:12px;color:#6b7280;line-height:1.5;margin:0">
    <strong>GhostShell Registry</strong><br>
    <a href="https://ghostshell.host" style="color:#6b7280">ghostshell.host</a> ·
    <a href="mailto:support@ghostshell.host" style="color:#6b7280">support@ghostshell.host</a><br>
    You are receiving this transactional email because you started or completed a GhostShell checkout.
  </p>
`;

/**
 * Send a transactional email via Resend.
 * Returns { ok: boolean, status?, error? }
 */
export async function sendEmail(env, { to, subject, text, html }) {
  if (!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL || !isValidEmail(to)) {
    return { ok: false, skipped: true, error: "missing_config_or_invalid_email" };
  }

  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization:  `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from: env.RESEND_FROM_EMAIL, to: [to], subject, text, html }),
  });

  const payloadText = await resp.text();
  if (!resp.ok) {
    console.log("email send failed", resp.status, payloadText.slice(0, 300));
    return { ok: false, status: resp.status, error: payloadText.slice(0, 500) };
  }
  return { ok: true, status: resp.status, body: payloadText.slice(0, 500) };
}
