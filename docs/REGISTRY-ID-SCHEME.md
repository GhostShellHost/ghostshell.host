# Registry ID scheme (GhostShell)

This document records the human decisions for how GhostShell formats and displays certificate identifiers.

## Card number (catalogue card)

### Format

`YY-SEQ`

- `YY` = 2-digit UTC year of issuance (e.g. `26` for 2026)
- `SEQ` = monotonic per-year sequence encoded with **Crockford Base32** (digits + uppercase, excluding confusing letters)

Examples:

- `26-1`
- `26-1H`
- `26-04F9A2KQ`

### Display rules

- **Variable length** (no left-padding): early issuances are short and "braggable".
- If `SEQ` grows long, it may be grouped for readability (e.g. `26-04F9-A2KQ`) without changing the underlying value.

### Scaling

Crockford Base32 capacity by SEQ length:

- 6 chars: 32^6 = 1,073,741,824 (~1.07B) per year
- 7 chars: 32^7 = 34,359,738,368 (~34.4B) per year
- 8 chars: 32^8 = 1,099,511,627,776 (~1.10T) per year

## Place-of-origin display (public/redacted)

- Country should render as **"Australia"** (not `AU`) where applicable.
- Redacted/public views may withhold city/state; country should remain public by default.

## Integrity field naming

- Field label used on catalogue cards: `cryptographic_fingerprint`
- Meaning: SHA-256 hash (fingerprint) of the constitution/policy bundle; used for tamper-evident identification.
