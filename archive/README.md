# Archive

This folder contains **non-core** or **superseded** materials that were moved out of the production surface area.

GhostShell’s production deployment is intentionally minimal:
- Cloudflare Worker code lives under `worker/`
- Static HTML entrypoints live at the repo root (e.g. `index.html`, `_redirects`)

## Why this exists

- Reduce production surface area
- Keep history without deleting files
- Make it clearer what is actually deployed

## What was moved here

- `old-root-index*.html`: previous root pages kept for reference
- `moved/registry-nextjs/`: prior Next.js-based UI (framework-based; not part of the current no-framework release)
- `moved/unused-variants/`, `moved/index_test/`, `moved/dreamdribble/`, `moved/handoff/`, `moved/issue/`: drafts, experiments, and legacy pages

## Notes

- Old URLs/paths may break after this relocation.
- If you need to resurrect something, copy it back intentionally (don’t re-expand the live surface area by accident).
