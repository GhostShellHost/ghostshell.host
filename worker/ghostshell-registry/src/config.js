// ── GhostShell Worker — Configuration Constants ──────────────────────────────

export const WORKER_VERSION = "2026-02-14.001";
export const PAGE_VERSION   = "v0.030";

// Token lifecycle
export const CLAIM_WINDOW_DAYS      = 7;  // days to submit form after purchase
export const CORRECTION_WINDOW_HOURS = 24; // hours to correct after first submission

// Origin/runtime stamping (public, for provenance/statistics)
export const ORIGIN_RUNTIME_DEFAULT = "OpenClaw";
export const ORIGIN_VERSION_DEFAULT = "2026.2.12";

// Amendment limits within the 24-hour correction window
export const HUMAN_AMENDMENT_LIMIT = 5;
export const AGENT_AMENDMENT_LIMIT = 5;

export const DEFAULT_BASE_URL       = "https://ghostshell.host";
export const FALLBACK_STRIPE_PRICE_ID = "price_1SxSy8BwPkwpEkfOwje2eX1k";
