import { fetchTodaysCves } from "./nvd";
import { fetchCveRecords, mergeCveRecords } from "./cve";
import { renderPage } from "./page";
import { buildSnapshot, getSnapshotView, SNAPSHOT_KEY, STALE_AFTER_MS } from "./snapshot";
import type { Env, Snapshot, SnapshotView } from "./types";

const SNAPSHOT_TTL_SECONDS = 24 * 60 * 60;

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

export default {
  fetch: handleRequest,
  async scheduled(_controller, env) {
    await refreshSnapshot(env);
  },
} satisfies ExportedHandler<Env>;

export async function handleRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  now = new Date(),
): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response(null, { status: 405, headers: { ...SECURITY_HEADERS, Allow: "GET, HEAD" } });
  }

  const url = new URL(request.url);
  if (url.pathname === "/favicon.ico") return new Response(null, { status: 204 });
  if (url.pathname === "/robots.txt") {
    return new Response(request.method === "HEAD" ? null : "User-agent: *\nAllow: /\n", {
      headers: { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=86400" },
    });
  }
  if (url.pathname !== "/" && url.pathname !== "/api/today.json") {
    return new Response(request.method === "HEAD" ? null : "Not found", {
      status: 404,
      headers: { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  // Ignore query strings so arbitrary visitor parameters cannot multiply KV reads.
  url.search = "";
  const cacheKey = new Request(url, { method: "GET" });
  try {
    const cached = await caches.default.match(cacheKey);
    if (cached) {
      return request.method === "HEAD" ? new Response(null, cached) : cached;
    }
  } catch (error) {
    console.warn("Edge cache read failed", error);
  }

  let view: SnapshotView;
  try {
    const snapshot = await env.CVE_STATUS.get<Snapshot>(SNAPSHOT_KEY, "json");
    view = getSnapshotView(snapshot, now);
  } catch (error) {
    console.error("Snapshot read failed", error);
    view = { date: now.toISOString().slice(0, 10), status: "unavailable", snapshot: null };
  }

  const isApi = url.pathname === "/api/today.json";
  const status = view.status === "unavailable" || (isApi && !view.snapshot) ? 503 : 200;
  const headers = new Headers(SECURITY_HEADERS);
  headers.set("Content-Type", isApi ? "application/json; charset=utf-8" : "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  if (status === 503) headers.set("Retry-After", "300");

  if (view.status === "ready" && view.snapshot) {
    const midnight = Date.parse(`${view.date}T00:00:00.000Z`) + 86_400_000;
    const staleAt = Date.parse(view.snapshot.updatedAt) + STALE_AFTER_MS;
    const ttl = Math.min(300, Math.floor((Math.min(midnight, staleAt) - now.getTime()) / 1000));
    if (ttl > 0) headers.set("Cache-Control", `public, max-age=0, s-maxage=${ttl}, must-revalidate`);
  }

  const body = isApi
    ? JSON.stringify({ ...view.snapshot, date: view.date, status: view.status, verdict: view.snapshot?.verdict ?? null })
    : renderPage(view);
  const response = new Response(body, { status, headers });
  if (view.status === "ready" && headers.get("Cache-Control") !== "no-store") {
    ctx.waitUntil(caches.default.put(cacheKey, response.clone()).catch((error: unknown) => {
      console.warn("Edge cache write failed", error);
    }));
  }
  return request.method === "HEAD" ? new Response(null, response) : response;
}

export async function refreshSnapshot(env: Env, now = new Date()): Promise<void> {
  try {
    const [records, nvdCves] = await Promise.all([
      fetchCveRecords(now),
      fetchTodaysCves(now, env.NVD_API_KEY),
    ]);
    const snapshot = buildSnapshot(mergeCveRecords(records, nvdCves), now);
    await env.CVE_STATUS.put(SNAPSHOT_KEY, JSON.stringify(snapshot), { expirationTtl: SNAPSHOT_TTL_SECONDS });
    console.log("Snapshot refreshed", { date: snapshot.date, ...snapshot.totals });
  } catch (error) {
    console.error("Snapshot refresh failed; keeping the last successful result", error);
    throw error;
  }
}
