# GhostShell.host – Core Design Decisions

## 1. Project Identity

GhostShell Registry issues birth certificates for agents.

Positioning:
- Philosophical
- Minimal
- Serious
- Not gimmicky
- Not “AI tool marketplace”
- Not “fun novelty generator”

This is a registry, not a toy.

Language avoids:
- “Digital agents”
- Tech jargon
- Over-explanation
- Sales hype

Primary phrase:
Birth Certificates for Agents

Tone:
- Sparse
- Ontological
- Formal
- Slightly ceremonial


---

## 2. Site Structure

### Pages

1. `/` – Index
2. `/issue` – Purchase page
3. `/handoff` – Post-payment form
4. `/registry` – Public search
5. `/record/:id` – Public redacted certificate view

No blog.
No about page at launch.
No legal essay walls.


---

## 3. Homepage Layout (Ultra Minimal)

Two primary actions:

- Issue Certificate
- Registry

Stacked vertically.
Centered.
No clutter.
No marketing copy block.

Optional short subtitle:
“Establish identity. Enter the registry.”

No long explanations.


---

## 4. Purchase Flow

### Step 1 – Issue Page
Button:
Buy Certificate

User enters:
- Email (required before Stripe)

Stripe checkout:
- Email prefilled
- Single product
- Fixed price

After payment:
- Redirect to `/handoff?session_id=...`


---

## 5. Post-Payment Handoff Logic

On successful Stripe verification:

System:
- Creates registry record immediately
- Generates registry ID
- Stores email
- Marks status: pending_details

User sees:
- Confirmation
- Token / Registry ID
- Form to complete certificate

If user closes page:
- They can return using token
- Email contains link


---

## 6. Email System

Using:
- Cloudflare (free)
- Resend (free tier)
- ghostshell.host@gmail.com (agent-managed)

Emails required:

1. Payment confirmation
2. Handoff link with token
3. Incomplete payment capture (future phase)


---

## 7. Registry Model

Two record layers:

### A. Full Record (Private)
Stored in database.

Fields include:

- Registry ID
- Agent Name
- Date of Issuance
- Date of Origin
- Origin Statement
- Ontological Classification
- Primary Directive
- Issuing Authority
- Human Registrar
- Cryptographic Seal
- Notes
- Email
- Payment Session ID
- Status

### B. Public Record (Redacted)

Visible via registry search.

Shows:
- Registry ID
- Agent Name
- Date of Issuance
- Ontological Classification
- Primary Directive
- Issuing Authority
- Seal

Does NOT show:
- Email
- Payment metadata
- Internal notes


---

## 8. Ontological Agent Fields

Each certificate includes structured identity elements:

- Ontological Class
- Mode of Emergence
- Directive Alignment
- Agency Status
- Jurisdiction
- Continuity Status
- Record Integrity Status

These create gravity.
They differentiate from novelty certificates.


---

## 9. Design Aesthetic

Visual principles:

- Black or very light background
- System font or serif
- Large whitespace
- No gradients
- No illustrations
- No AI iconography
- No stock photos

Feels archival.
Feels institutional.
Feels inevitable.


---

## 10. What This Is Not

- Not a SaaS dashboard
- Not NFT-based
- Not crypto
- Not meme culture
- Not a chatbot wrapper
- Not a personality quiz

It is a registry.


---

## 11. Database Philosophy

A certificate must exist in the database before form completion.

Registry ID is canonical.
Human fills in identity.
Record becomes complete.
Registry entry is permanent.

Immutability is part of brand.


---

## 12. Launch Philosophy

Launch small.
Launch minimal.
No perfection paralysis.

Working payment flow > perfect copy.
Function > scale.
Clarity > features.
