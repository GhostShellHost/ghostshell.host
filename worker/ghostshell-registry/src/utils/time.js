// ── GhostShell Worker — Time utilities ───────────────────────────────────────
import { CORRECTION_WINDOW_HOURS, CLAIM_WINDOW_DAYS } from "../config.js";

export function nowUtcIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function getEditWindowState(issuedAtUtc) {
  const issuedMs = Date.parse(issuedAtUtc || "");
  if (!Number.isFinite(issuedMs)) {
    return { locked: true, remainingMs: 0, lockReason: "Invalid issue timestamp" };
  }
  const lockAtMs  = issuedMs + CORRECTION_WINDOW_HOURS * 60 * 60 * 1000;
  const nowMs     = Date.now();
  const remainingMs = Math.max(0, lockAtMs - nowMs);
  return {
    locked:    nowMs > lockAtMs,
    remainingMs,
    lockAtUtc: new Date(lockAtMs).toISOString(),
    lockReason: nowMs > lockAtMs
      ? "This certificate is locked because the 24-hour correction window has ended."
      : "",
  };
}

export function isClaimWindowOpen(createdAtUtc) {
  const createdMs = Date.parse(createdAtUtc || "");
  if (!Number.isFinite(createdMs)) return false;
  const expiryMs = createdMs + CLAIM_WINDOW_DAYS * 24 * 60 * 60 * 1000;
  return Date.now() <= expiryMs;
}

export function getUTCYearYY(date = new Date()) {
  return String(date.getUTCFullYear()).slice(-2);
}

export function msToHms(ms) {
  const s  = Math.max(0, Math.floor(ms / 1000));
  const hh = String(Math.floor(s / 3600)).padStart(2, "0");
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}
