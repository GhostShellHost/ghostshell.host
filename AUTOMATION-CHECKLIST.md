# GhostShell Automation Checklist

## ✅ Completed
- [x] GitHub CI deploy fixed (new Cloudflare API token + GitHub secret)
- [x] Worker runtime secrets configured:
  - `STRIPE_SECRET_KEY`
  - `STRIPE_WEBHOOK_SECRET`
  - `RESEND_API_KEY`
  - `RESEND_FROM_EMAIL`
  - `EMAIL_ENC_KEY`
  - `OPS_SECRET`
- [x] `/api/ops/email-summary` endpoint secured & working
- [x] Weekly cron job created (daily health checks)
- [x] Test checkout flow fixed:
  - Redirects directly to register page (`/register/?token=...&by=human`)
  - Completion emails confirmed in testing
- [x] Email footer implementation (Resend + footer)
- [x] Full end-to-end registration flow verification

## 🔄 Pending
- [ ] Abandoned checkout email trigger test
  - Requires a real `checkout.session.expired` event (or Stripe CLI + valid webhook signing flow)
- [ ] Optional: 30-min email failure alert cron

## Next Steps (updated)
1. Validate abandoned checkout reminder with a genuine expired Stripe session.
2. Add optional failure-only alerting every 30 min.
3. Verify ops runbook notes for secret rotation (`OPS_SECRET`, Resend key).
