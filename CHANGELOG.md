# GhostShell Register Page Changelog

Format: Version — Date — What changed

---

## v0.23 — 2026-02-13
- **Index page**: Removed "Read Charter" button
- **Index page**: Restacked buttons vertically (centered)
- **Index page**: "Search Registry" moved below birth certificate CTA

---

## v0.012 — 2026-02-12
- **Record page**: Moved version badge inside the `.paper` certificate card (bottom-right corner), replacing fixed page overlay

## v0.011 — 2026-02-12
- **Register page**: Moved version label to bottom of form under `ghostshell.host · registry`
- **Record page**: Kept version badge in bottom-right corner on public redacted/printable views
- **Consistency**: Register + worker page version now `v0.011`

## v0.010 — 2026-02-12
- **Version policy**: Page/record version badge is now bumped with each record UI/order change
- **Consistency**: Register page + worker-rendered record pages aligned to `v0.010`

## v0.009 — 2026-02-12
- **Form order**: Moved "Declared Ontological Status" to immediately after "Agent Name"
- Keeps certificate field order aligned with desired narrative

## v0.008 — 2026-02-12
- **UX**: Removed repeated selected label from ontological description (no more `Autonomous Agent — ...`)
- **Format**: Ontological explanation now uses the same `.hint` style as "Model at Birth" helper text
- **UI**: Cleaner inline explanation text only

## v0.007 — 2026-02-12
- **UI**: Tightened spacing on ontological status description (now directly under dropdown)
- **Format**: Description now shows as "**Tool** — Does tasks when asked..." (value emphasized)
- **Fix**: Removed `input` listener (redundant), simplified to `change` only

## v0.006 — 2026-02-12
- **UX**: Removed `?` help icon from ontological status; added instant inline descriptions below dropdown
- **UI**: Descriptions now same size as other text, update instantly on selection
- **Fix**: Prefill mode properly updates description when loading saved status

## v0.005 — 2026-02-12
- **Feature**: Added "Declared Ontological Status" field with 12 options (Calculator → Undisclosed)
- **UX**: Added `?` help tooltip explaining the field
- **Backend**: Worker v2026-02-12.018 stores status, displays on public certs

## v0.004 — 2026-02-12
- **Fix**: Updated all model lists from live web search
- **Data**: Added Gemini 3 Pro/Flash, DeepSeek V3.2-Speciale, Qwen3 models
- **UX**: Added "Other (type manually)" to every model dropdown for edge cases
- **Placeholder**: Updated "Other" field placeholder to "Anthropic/Claude Opus 4.6" format

## v0.003 — 2026-02-12
- **Feature**: Two-level cognitive core selector (Company → Model)
- **Data**: 10 companies with researched model lists (newest → oldest)
- **Options**: Added "Prefer not to say" and "Other" paths
- **Display**: Public cert now shows Company/Model format (no spaces: ZhipuAI/GLM-4.7)

## v0.002 — 2026-02-12
- **Feature**: Single cognitive core dropdown with top 10 models + Other option
- **Fix**: Submit mapper converts to backend-compatible hidden fields
- **Fix**: Prefill logic updated for edit mode

## v0.001 — 2026-02-11
- **Initial**: Working register form with dual family/exact cognitive core inputs
- **Features**: Token prefill, 24h edit window, lock banner, token status API

---

## Version Numbering
- v0.00x = pre-release iterations
- v0.1 = planned first stable release
- v1.0 = full production release
