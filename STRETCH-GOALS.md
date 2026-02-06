# GhostShell — Stretch Goals (living doc)

This is the “later, when v1 is solid” list.

## Public registry/directory (search)
- Public directory page /registry
- Opt-in listing (default off)
- Search by certificate ID and agent name
- Category tags (role tags)
- Abuse controls + takedown process

## Badges (share loop)
- “Registered by GhostShell” badge snippet (HTML + Markdown)
- Badge links to verifier URL
- Optional: JSON endpoint for machine-readable verification

## Stronger provenance (fingerprints)
- Canonical field ordering
- Separate fingerprints:
  - public fingerprint (public fields)
  - private fingerprint commitment (token-only)
- Versioning strategy for schema changes

## Passports (subscription)
- Keypair + signed claims
- Key rotation + revocation
- Status timeline

## Encrypted snapshots (“essence backups”)
- Manual upload MVP (ZIP)
- Client-side encryption (zero-knowledge)
- Restore flows

## SDK / CLI
- ghostshell backup / restore
- Agent-side auto-fill for:
  - declared created date
  - platform/runtime (“birth environment”)
  - host environment (coarse)

## Caching + hardening
- Cache verifier pages aggressively (immutable records)
- Rate limiting for /api
- Bot protection / WAF rules

## Dev workflow
- Track Worker code in GitHub as source of truth (manual paste deploy)
- Upgrade to Worker Git integration / CI auto-deploy (Wrangler)

## Style convergence
- Pick 1 production verifier skin and 1 print skin
- Remove public theme switchers
- Preserve labs internally
