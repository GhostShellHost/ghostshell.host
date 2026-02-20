// ── GhostShell Worker — Stripe service ───────────────────────────────────────

/**
 * Fetch a Stripe Checkout Session by ID.
 * SECURITY: do not log session IDs.
 */
export async function fetchStripeCheckoutSession(sessionId, env) {
  console.log("[stripe] session lookup");
  const stripeResp = await fetch(
    `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}`,
    { headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` } }
  );
  if (!stripeResp.ok) {
    return { ok: false, status: stripeResp.status, session: null };
  }
  const session = await stripeResp.json();
  return { ok: true, status: stripeResp.status, session };
}

/**
 * Returns true if the Stripe session represents a completed payment
 * that should unlock certificate issuance.
 */
export function isCheckoutCompleteForIssuance(session) {
  if (!session || typeof session !== "object") return false;

  const paymentStatus = String(session.payment_status || "").toLowerCase();
  if (paymentStatus === "paid" || paymentStatus === "no_payment_required") return true;

  // Free checkout (e.g. 100% coupon) shows status=complete + amount_total=0
  const status      = String(session.status || "").toLowerCase();
  const amountTotal = Number(session.amount_total || 0);
  if (status === "complete" && amountTotal === 0) return true;

  return false;
}
