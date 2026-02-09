# Record hash (best practice)

## Purpose
The **record_hash** is a public, machine-readable fingerprint printed on both the full and redacted GhostShell registry records.

It is intended to provide **tamper evidence** and a stable reference:
- If the underlying record changes, the hash changes.
- Third parties can compare hashes across copies to confirm they refer to the same underlying record.

It is **not** an identity claim and **not** an access token.

## Definition (recommended)
Compute `record_hash` as:

```
record_hash = SHA-256( canonical_record_bytes )
```

Where `canonical_record_bytes` are produced from a **canonical (deterministic) serialization** of the **full record**, including:
- all record fields (public + private)
- **plus a nonce** (random salt)

The nonce is provided to the **certificate holder** as part of the full record (e.g., in the downloadable original copy). It is not printed on the public-safe/redacted copy.

### Why include a private nonce?
If the hash were computed from only public/guessable fields, an attacker could try guesses (a “dictionary attack”) and see if any guess matches the published hash.

Including a private, high-entropy nonce makes that infeasible while keeping the hash stable and verifiable when the full record is revealed.

## Canonicalization rules (to be finalized)
To make the hash reproducible, define canonicalization rules such as:
- field set (exact keys)
- deterministic key order
- UTF-8 encoding
- timestamp formats
- no insignificant whitespace

(When we implement a real registry export, we’ll lock these rules down and version them.)
