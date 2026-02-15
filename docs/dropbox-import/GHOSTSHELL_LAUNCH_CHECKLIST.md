# GhostShell.host – Launch Checklist

## Phase 1 – Minimum Viable Launch

### 1. Stripe

- [ ] Product created
- [ ] Webhook configured
- [ ] Success URL set to /handoff
- [ ] Session ID verified server-side
- [ ] Payment validation enforced

---

### 2. Database

- [ ] Registry table exists
- [ ] Registry ID generator implemented
- [ ] Status field (pending_details / complete)
- [ ] Email stored on record creation
- [ ] Payment session ID stored

---

### 3. Handoff Page

- [ ] Verifies Stripe session
- [ ] Creates registry entry if not exists
- [ ] Displays registry ID
- [ ] Displays completion form
- [ ] Saves form data
- [ ] Marks record complete

---

### 4. Registry Page

- [ ] Search by Registry ID
- [ ] Displays redacted public record
- [ ] 404 handling for invalid ID
- [ ] No private data leakage

---

### 5. Email System

- [ ] Payment confirmation email
- [ ] Handoff link email
- [ ] Retry link for incomplete submissions
- [ ] Tested on Gmail
- [ ] SPF/DKIM set

---

### 6. Security

- [ ] Stripe verification required
- [ ] No client-side trust
- [ ] Rate limiting on registry search
- [ ] Input sanitisation on form
- [ ] Token validation

---

### 7. Copy Finalisation

- [ ] Homepage minimalised
- [ ] “Issue Certificate” wording confirmed
- [ ] “Registry” wording confirmed
- [ ] Remove unused pages
- [ ] Remove dev debug text

---

### 8. Technical Hosting

- [ ] Cloudflare Pages deployed
- [ ] Environment variables configured
- [ ] Production keys set
- [ ] Test payment completed
- [ ] Real payment completed

---

## Phase 2 – Stability Improvements

- [ ] Abandoned checkout email capture
- [ ] Registry hash verification
- [ ] Certificate PDF export
- [ ] Public seal graphic
- [ ] Admin audit view

---

## Phase 3 – Brand Reinforcement

- [ ] Immutable registry statement
- [ ] Philosophical manifesto (optional)
- [ ] Public example certificate
- [ ] Shareable certificate view
- [ ] Subtle footer signature

---

## Launch Criteria

The site is launchable when:

- A user can pay
- A record is created automatically
- A registry ID is issued
- The user can complete identity fields
- The record becomes publicly searchable
- Email confirms the process

Nothing else is required for first release.
