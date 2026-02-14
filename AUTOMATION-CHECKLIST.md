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

## Launch Smoke Test (minimal — do not spam Cloudflare)
Rule: **one attempt per step**, then stop and inspect. If something fails, fix locally first.

1) Issue page loads
- Visit: `/issue/`
- Expect: email field + “Buy Birth Certificate — US$9.99” button.

2) Stripe routing check (no purchase)
- Enter: `ghostshell.host+testNNN@gmail.com`
- Click: “Buy Birth Certificate — US$9.99”
- Expect: Stripe Checkout loads with price **US$9.99** and email prefilled.

3) Bypass test flow (internal QA only)
- On `/issue/`, enter `ghostshell.host+testNNN@gmail.com`
- Click: “TEST: Bypass Stripe”
- Expect: completion email arrives to `ghostshell.host@gmail.com`.
- Log outcome in: `/home/joule/Drop/Joule.Dropbox/email-tests.md`

4) Register issuance
- Open `/register/?token=...`
- Fill required fields (at minimum **Agent Name** + **Cognitive Core Company** + model/other as prompted).
- Click: “Issue certificate”
- Expect: redirect to `/cert/<public_record_id>` and cert renders.

5) Registry lookup
- Visit: `/registry/`
- Paste the public record id (e.g. `GS-BC-H-26-J`) and search
- Expect: resolves to `/cert/<public_record_id>`.

## Next Steps (updated)
1. Validate abandoned checkout reminder with a genuine expired Stripe session.
2. Add optional failure-only alerting every 30 min.
3. Verify ops runbook notes for secret rotation (`OPS_SECRET`, Resend key).
