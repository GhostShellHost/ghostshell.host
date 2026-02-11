# GhostShell Ops Tracker

Last updated: 2026-02-11 (Adelaide)
Owner: Jas + Joule

## What this file is for
Single place to track:
- major code/deploy changes
- external services/accounts in use
- required secrets/env vars
- current known issues + next actions

---

## Recent changes (latest first)

### 2026-02-12
- Register flow refactor deployed: replaced dual cognitive-core fields with single dropdown + "Other" custom path.
- Added client-side submit mapping to preserve backend compatibility (`cognitive_core_family` / `cognitive_core_exact`).
- Verified live production behavior:
  - standard model selection stores split family/exact values
  - custom "Other" selection stores `Undisclosed` + custom exact value
- Confirmed live `/register/` reflects new UI (deployment drift resolved).

### 2026-02-11
- Added test checkout bypass flow (`/api/cert/test-checkout`) for safe Stripe-free testing.
- Updated `/issue` page red test button to one-click (no test key input).
- Added runtime schema safety patching for `purchase_tokens` migration drift.
- Added encrypted recovery email support in `purchase_tokens`:
  - `recovery_email_iv`
  - `recovery_email_enc`
- Added email helper functions (validation, decrypt, send via Resend API).
- Added completion email tracking fields and status writes.
- Added abandoned checkout email tracking writes.
- Added idempotency guard for Stripe webhook event handling.
- Added ops summary endpoint: `GET /api/ops/email-summary`.
- Added OpenClaw daily health cron (9:00 AM Australia/Adelaide).

---

## Services currently in play

### Cloudflare
- Product: Workers + D1
- Worker: `ghostshell-registry`
- DB binding: `DB` → `ghostshell_registry`
- Routes:
  - `ghostshell.host/cert/*`
  - `ghostshell.host/api/*`

### Stripe
- Used for checkout + webhook payment confirmation.

### Resend
- Used for transactional emails (checkout follow-up + completion email).

### GitHub
- Repo: `GhostShellHost/ghostshell.host`
- Action: `.github/workflows/deploy-worker.yml`
- Deploy path: `worker/ghostshell-registry`

### OpenClaw automation
- Cron job: `ghostshell-daily-health` (isolated session)
- Schedule: `0 9 * * *` (Australia/Adelaide)

---

## Required Worker secrets/env (production)

### Already present (confirmed)
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

### Needed for new email/ops automation
- `RESEND_API_KEY`
- `RESEND_FROM_EMAIL`
- `EMAIL_ENC_KEY` (base64 32-byte key)
- `OPS_SECRET`

---

## Known issue (current)
- ~~GitHub deploy run for commit `bc5469e` failed (email alert seen).~~ ✅ Resolved via new Cloudflare API token + GitHub secret update; rerun succeeded.
- Local `wrangler deploy --dry-run` succeeded during diagnosis.
- Worker runtime secrets now present in Cloudflare: `EMAIL_ENC_KEY`, `OPS_SECRET`, `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, plus Stripe secrets.

---

## Next actions
1. Run abandoned-flow validation with a genuine `checkout.session.expired` event and confirm `abandoned_email_status` writes.
2. Keep `/api/ops/email-summary` access key management documented (rotation + storage path).
3. Optional: add failure-only alert job every 30 min.

---

## Notes
If anything changes, update this file first so context is never lost.
