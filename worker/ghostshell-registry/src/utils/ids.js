// ── GhostShell Worker — ID/token generation & helpers ───────────────────────
import { b64url } from "./crypto.js";
import { getUTCYearYY } from "./time.js";
import { DEFAULT_BASE_URL, FALLBACK_STRIPE_PRICE_ID } from "../config.js";

export function makeCertId() {
  const d   = new Date();
  const y   = d.getUTCFullYear();
  const m   = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  const rand = crypto.getRandomValues(new Uint8Array(6));
  const slug = b64url(rand).slice(0, 8).toUpperCase();
  return `GS-BC-${y}${m}${day}-${slug}`;
}

export function makeToken() {
  const rand = crypto.getRandomValues(new Uint8Array(24));
  return b64url(rand);
}

export function makePurchaseToken() {
  // "GSTK-" + 10 Crockford Base32 chars from random bytes
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const rand = crypto.getRandomValues(new Uint8Array(10));
  let out = "GSTK-";
  for (const b of rand) out += alphabet[b % 32];
  return out;
}

export function crockfordBase32Encode(n) {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const v = Number(n);
  if (!Number.isInteger(v) || v < 0) {
    throw new Error("crockfordBase32Encode expects a non-negative integer");
  }
  if (v === 0) return "0";
  let x = v, out = "";
  while (x > 0) {
    out = alphabet[x % 32] + out;
    x   = Math.floor(x / 32);
  }
  return out;
}

export function normalizeRegistryId(raw, fallback) {
  const v = (raw || fallback || "").toString().trim();
  return v.toUpperCase();
}

export function isValidEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || "").trim());
}

export function getBaseUrl(request, env) {
  return (env.BASE_URL || new URL(request.url).origin || DEFAULT_BASE_URL).replace(/\/$/, "");
}

export function getStripePriceId(env) {
  return env.STRIPE_PRICE_ID || env.STRIPE_PRICE || FALLBACK_STRIPE_PRICE_ID;
}
