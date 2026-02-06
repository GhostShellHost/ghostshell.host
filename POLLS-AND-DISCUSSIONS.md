# GhostShell — Polls & Discussions Backlog (v0.1)

Purpose: collect fast, actionable feedback from creators + users without derailing shipping.

Guidelines:
- Prefer **polls** for binary/short choices (A/B/C) where we can implement quickly.
- Prefer **discussions** for semantics/trust questions where wording matters.
- Always include: **context**, **what changes if you vote**, and a **deadline**.

---

## Priority 1 — Trust semantics (public verifier)

### 1) What should the verifier claim?
**Type:** Poll + follow-up discussion
**Question:** “What do you think a GhostShell verifier should prove?”
**Options (poll):**
- A) Registry record exists + fingerprint matches (integrity only)
- B) The creator/owner identity is verified
- C) The agent is safe/approved
- D) Not sure
**Why:** catches over-claim risk early.
**Action:** tighten wording until most choose A.

### 2) Should the public verifier show any creator/custodian info?
**Type:** Poll
**Options:**
- A) No (verifier minimal)
- B) Yes (pseudonym labels, behind disclosure)
- C) Yes (pseudonym labels always visible)
**Action:** set default privacy posture.

### 3) Should the verifier show host environment (hardware/OS)?
**Type:** Poll
**Options:**
- A) No (token-only)
- B) Yes (coarse)
**Action:** confirm our current decision.

---

## Priority 2 — Certificate fields (download/print page)

### 4) Custodian label on printable certificate?
**Type:** Poll
**Options:**
- A) Show as optional pseudonym
- B) Do not show
**Action:** set printable field set.

### 5) Creator label on printable certificate?
**Type:** Poll
**Options:**
- A) Show as optional pseudonym
- B) Do not show
**Action:** set printable field set.

### 6) “Declared created date” (agent creation date) field?
**Type:** Poll + discussion
**Options:**
- A) Yes (date only, declared)
- B) No
**Discussion prompt:** What do you consider the agent’s “created date”?

### 7) What should we call the two dates?
**Type:** Discussion
**Prompt:** propose best labels for:
- GhostShell-issued timestamp
- User/agent-declared creation date

---

## Priority 3 — Branding & copy

### 8) Headline preference test
**Type:** Poll
**Options:**
- A) Birth Certificates for AI agents.
- B) Register your AI agent. Make it verifiable.
- C) Birth Certificates for AI entities.
**Action:** confirm direction with outsiders.

### 9) Tone: technical vs plain English
**Type:** Poll
**Options:**
- A) Technical-trust
- B) Plain-English
**Action:** guide copy style.

---

## Priority 4 — Visual direction

### 10) Verifier style (one winner)
**Type:** Poll
**Options:**
- A) Notary
- B) Bureau
- C) Ledger
- D) Chancery
- E) Original
**Action:** pick one production skin; remove switcher publicly.

### 11) Printable certificate style
**Type:** Poll
**Options:**
- A) Notary
- B) Chancery
- C) Minimal
**Action:** pick print look.

---

## Priority 5 — Pricing & packaging

### 12) Price perception
**Type:** Poll
**Question:** “US$9.99 for a Birth Certificate feels…”
**Options:**
- A) Too low
- B) Fair
- C) Too high
- D) Depends / want tiers

### 13) What should be included for the price?
**Type:** Discussion
**Prompt:** What would make this a no-brainer to buy/share?

---

## Priority 6 — Growth loops

### 14) Badge copy
**Type:** Poll
**Options:**
- A) Registered by GhostShell
- B) Verified by GhostShell
- C) GhostShell Certificate

### 15) Directory
**Type:** Poll
**Question:** “Should GhostShell have a public registry directory?”
**Options:**
- A) Yes, opt-in listing
- B) Yes, default listing
- C) No directory

---

## Where to run these
- **GitHub Discussions:** best for detailed feedback + longer threads.
- **X polls:** quick signal, broad reach.
- **Moltbook posts:** agent-builder audience; good for “what does this prove?” sanity checks.

