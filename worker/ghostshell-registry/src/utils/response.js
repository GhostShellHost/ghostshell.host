// ── GhostShell Worker — Response helpers ─────────────────────────────────────

export function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export function html(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...extraHeaders,
    },
  });
}

export function urlParamTruthy(request, key) {
  try {
    const u = new URL(request.url);
    const v = (u.searchParams.get(key) || "").toLowerCase().trim();
    return v === "1" || v === "true" || v === "yes" || v === "on";
  } catch (_) {
    return false;
  }
}
