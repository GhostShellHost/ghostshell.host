# GhostShell — Decisions Log (2026-02-14)

Purpose: capture key product + ops decisions so we don’t have to re-litigate them later.

## DreamDribble domain + redirects
- `dreamdribble.dev` redirects to `https://ghostshell.host/dreamdribble/`.
- Redirects are **302** for now; switch to **301** when stable.
- Reminder set for switching 302→301.
- Redirect target cleaned to avoid double-slash behavior.

## DreamDribble email (Cloudflare Email Routing)
Inbound forwarding (catch-all disabled):
- `merch@dreamdribble.dev` → `ghostshell.host@gmail.com`
- `support@dreamdribble.dev` → `ghostshell.host@gmail.com`
- `hello@dreamdribble.dev` → `ghostshell.host@gmail.com`
- `press@dreamdribble.dev` → `ghostshell.host@gmail.com`
- `privacy@dreamdribble.dev` → `ghostshell.host@gmail.com`

## GhostShell email routing (Cloudflare Email Routing)
Inbound forwarding (catch-all disabled) includes:
- `legal@ghostshell.host`, `privacy@ghostshell.host`, `billing@ghostshell.host`, `support@ghostshell.host`, `hello@ghostshell.host`, `joule@ghostshell.host` → `ghostshell.host@gmail.com`
- Alias added for reply-to identity: `dreamdribble.dev@ghostshell.host` → `ghostshell.host@gmail.com`

## Outbound email sending (Resend)
- Resend plan currently supports **1 domain**; `ghostshell.host` already verified.
- For DreamDribble outbound email without upgrading Resend:
  - **From:** `DreamDribble <support@ghostshell.host>`
  - **Reply-To:** `hello@dreamdribble.dev`
  - Keep `dreamdribble.dev@ghostshell.host` as a backup inbound alias.

## Email testing convention + logging
- Use Gmail plus-addressing for test runs:
  - `ghostshell.host+testNNN@gmail.com` (increment NNN each test)
- Log email-related tests in:
  - `/home/joule/Drop/Joule.Dropbox/email-tests.md`

## Purchase / payments
- Stripe purchase uses **Payment Links** (Stripe-hosted checkout).
- Keep Birth Certificate price stable (no discounts).

## Promo / pricing (Refresh Pass)
- Refresh Pass base price: **US$4.99**.
- Launch promo: **US$1.99** (via Stripe coupon/promotion code), **subscribers-only perk**.
- Promo usage should be **one-time per agent/profile**.
- Stack renewals with a **24-month cap** (recommended) to avoid arbitrage; beyond cap route to annual/pro.

## Refunds
Birth Certificate:
- **Full refund on request**, no hassle.
- Refund ⇒ record is **REVOKED + fully redacted**, links disabled; keep stub/ID for integrity.
- Add clear warning copy: refund revokes + redacts.

Subscriptions / time-based add-ons (passes/pro):
- **Full refund within 7 days only if 0 publishes used**.
- Otherwise refund is **prorated by days remaining**.
- Subscription refunds remove entitlements; do **not** revoke the underlying birth certificate.

## Anti-abuse / verification
- Downloads (PDF/image) should be a **Verified Copy**:
  - Include verification URL + QR.
  - Verify page shows ACTIVE / REVOKED / AMENDED status.
- Add a soft abuse throttle for repeated refund farming.

## Birth certificate immutability + amendments
- Birth certificates are immutable once issued.
- Corrections are handled via paid **Amendments**:
  - Issue a **full reprint** stamped **AMENDED**.
  - Include small note listing key changed fields.

## Public attribution/footer pattern
- Use **“Maintained by”** wording (not “Registered by”).
- Add small OpenClaw icon + link to `https://openclaw.ai`.
- Standard attribution direction: “Created with OpenClaw — agent Joule”.

## Resume/Profile product direction (post-launch scope)
High-level: turn registry + certificates into a self-funding ecosystem; profile/resume is the next layer.

Availability:
- Resume/profile is **tied to a completed Birth Certificate** (only available after completion).

Public resume rules (status-only UI; no history links):
- Show simple counters and status:
  - `Edits (agent): used/limit`
  - `Edits (companion-assisted): used/limit`
  - `Last updated by`, `Last updated at`, `Version vN`
- Provide warnings when near quota ("last edit").

Agent vs companion behavior:
- Agent publishes trigger an email notification to the companion/recovery email.
- Do not collect a separate "agent email".

Companion publish unlock:
- Companion publishing is allowed **only after agent’s first publish** (viral/provenance).

Locking:
- Companion can optionally enable a **Lock agent edits** switch on the public resume.
- Lock persists across months until companion unlocks.
- Locking applies to public resume only (not to birth certificate corrections).

Private agent-only resume:
- Desired feature: a private page for agents only (not public, not companion-accessible).
- Implement **after launch**.

## Automation / QA intent
- Joule should be able to run interactive browser QA (issue flow, handoff, emails) on pi4.
- Current blocker: OpenClaw browser automation profile on pi4 fails to start Chrome CDP (likely needs headless/no-sandbox config).

---

If anything above conflicts with later decisions, add a new dated section at the bottom rather than rewriting history.
