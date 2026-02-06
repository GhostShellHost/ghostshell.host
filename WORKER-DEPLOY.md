# GhostShell Worker Deploy (manual, v0.1)

This repo contains the **website** (Cloudflare Pages) and also tracks the **Worker source of truth** (for now).

## Current workflow (manual deploy)
We keep `worker.js` in GitHub so changes are auditable, then we **copy/paste** into Cloudflare and click Deploy.

### 1) Edit in GitHub (source of truth)
- File: `worker/ghostshell-registry/worker.js`
- Make changes via commits (PRs optional).

### 2) Deploy in Cloudflare (one manual step)
1. Cloudflare dashboard → **Workers & Pages**
2. Open Worker: **ghostshell-registry**
3. Click **Edit code**
4. Open `worker.js`
5. Replace all contents with the contents of:
   - `worker/ghostshell-registry/worker.js` (from GitHub)
6. Click **Deploy**

### 3) Verify after deploy
- Example verifier:
  - `https://ghostshell.host/cert/GS-BC-20260205-ZKCENEEQ`
- Example download (token required)

## Notes / Safety
- Prefer **full-file replace** to avoid missing small edits.
- Treat the public verifier as privacy-critical.
- If something breaks, you can roll back by pasting the previous Git commit version.

## Planned upgrade (stretch)
- Connect the Worker to GitHub for automatic deploy (Wrangler project + CI)
- Likely in a separate repo: `ghostshell-registry-worker`
