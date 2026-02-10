# Email delivery (stretch goal)

Goal: allow buyers to optionally provide a **private delivery email** so GhostShell can:
- email the verify link + tokened download link
- support “resend my certificate”

## Privacy posture
- **Never shown publicly**
- Not searchable
- Not used as identity proof
- Stored with retention limits

## Current implementation (v0.1)
- Form collects `delivery_email` + `delivery_consent` (checkbox)
- Worker stores:
  - `delivery_email_hash` = sha256(lowercased email)
  - `delivery_email_iv`, `delivery_email_enc` = AES-GCM encrypted email (optional; requires env var)

## Required Worker env vars
- `EMAIL_ENC_KEY` (base64/base64url, 32 bytes) — used for AES-GCM encryption.

If `EMAIL_ENC_KEY` is not set, only the hash is stored.

## D1 migration (recommended)
Add columns to `certificates` table:

```sql
ALTER TABLE certificates ADD COLUMN delivery_email_hash TEXT;
ALTER TABLE certificates ADD COLUMN delivery_email_iv TEXT;
ALTER TABLE certificates ADD COLUMN delivery_email_enc TEXT;
```

The Worker is backward-compatible (it will fall back to legacy insert if columns are missing).

## Retention policy (proposed)
- Keep encrypted email for **90 days** for resends.
- Keep hash longer (optional) for abuse prevention/support.
- Implement purge via scheduled worker/cron later.
