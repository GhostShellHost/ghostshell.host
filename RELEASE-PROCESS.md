# GhostShell Release Process

One change → one version bump → one commit → push.
No exceptions.

---

## The Rule

Any edit to a live page must:
1. Bump the version number (in page footer + VERSION.txt)
2. Add changelog entry
3. Commit with version in message
4. Push to deploy

---

## Quick Reference

| Step | Command / Action |
|------|------------------|
| Bump footer | Edit `v0.xx` in page HTML |
| VERSION.txt | `echo "v0.xx" > VERSION.txt` |
| Changelog | Add entry to top of CHANGELOG.md |
| Commit | `git add -A && git commit -m "v0.xx: what changed"` |
| Deploy | `git push` |

---

## Version Format

- `v0.xxx` = pre-release iterations (current)
- `v0.1` = first stable release
- `v1.0` = full production release

Always use 3 digits during pre-release: v0.023 not v0.23

---

## Pages That Need Version Bumping

- `index.html`
- `issue/index.html`
- `register/index.html`
- `registry/index.html`
- `handoff/index.html`

(Use `bump-version.sh` if updating all at once)

---

## What Triggers a Version Bump

ANY change to:
- Visual layout
- Copy/text
- Links or navigation
- Styling
- Functionality

If you touched it, you version it.

---

## Do Not

- Skip the version bump
- Skip the changelog
- Commit without the version in the message
- Ask "should I version this?" — yes, always yes

---

*Last updated: 2026-02-13*
