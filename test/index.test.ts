import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { handleRequest, refreshSnapshot } from "../src/index";
import { buildSnapshot } from "../src/snapshot";
import type { CveRecord, Env, Snapshot } from "../src/types";
import { cve, nvdCve } from "./helpers";

const now = new Date("2026-11-19T09:00:00.000Z");
let snapshot: Snapshot;
let env: Env;
let ctx: ExecutionContext;
let kv: { get: ReturnType<typeof vi.fn>; put: ReturnType<typeof vi.fn> };
let cache: { match: ReturnType<typeof vi.fn>; put: ReturnType<typeof vi.fn> };

beforeEach(() => {
  snapshot = buildSnapshot([cve({ sources: ["cve", "nvd"] })], now);
  kv = { get: vi.fn().mockResolvedValue(snapshot), put: vi.fn().mockResolvedValue(undefined) };
  env = { CVE_STATUS: kv as unknown as KVNamespace };
  ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn(), props: {} } as unknown as ExecutionContext;
  cache = { match: vi.fn().mockResolvedValue(undefined), put: vi.fn().mockResolvedValue(undefined) };
  vi.stubGlobal("caches", { default: cache });
  vi.stubGlobal("fetch", vi.fn());
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("HTTP handler", () => {
  it("serves a cached HTML snapshot with the donation and author links", async () => {
    const response = await handleRequest(new Request("https://example.com/"), env, ctx, now);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("text/html");
    expect(response.headers.get("Cache-Control")).toContain("s-maxage=300");
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    const html = await response.text();
    expect(html).toContain('href="https://ko-fi.com/gsilvapt"');
    expect(html).toContain('Made by <a href="https://github.com/gsilvapt"');
    expect(html).toContain("Today's answer: YES");
    expect(cache.put).toHaveBeenCalledOnce();
    expect(ctx.waitUntil).toHaveBeenCalledOnce();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("serves JSON with the verdict, counts, and freshness status", async () => {
    const response = await handleRequest(new Request("https://example.com/api/today.json"), env, ctx, now);
    expect(response.headers.get("Content-Type")).toContain("application/json");
    expect(response.headers.get("Cache-Control")).toContain("s-maxage=300");
    expect(await response.json()).toMatchObject({
      date: "2026-11-19", status: "ready", verdict: "YES", totals: { high: 1 },
    });
  });

  it("serves RSS from the shared snapshot without upstream requests", async () => {
    const response = await handleRequest(new Request("https://example.com/api/today.rss"), env, ctx, now);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("application/rss+xml");
    expect(response.headers.get("Cache-Control")).toContain("s-maxage=300");
    expect(await response.text()).toContain('<guid isPermaLink="false">CVE-2026-1000</guid>');
    expect(cache.put).toHaveBeenCalledOnce();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("uses the request origin for RSS links and drops query parameters", async () => {
    const request = new Request("http://localhost:8787/api/today.rss?reader=test");
    const response = await handleRequest(request, env, ctx, now);
    const xml = await response.text();
    expect(xml).toContain("<link>http://localhost:8787/</link>");
    expect(xml).toContain('<atom:link href="http://localhost:8787/api/today.rss" rel="self"');
  });

  it.each([{}, { software: [] }])("labels unknown software in stored RSS entries (%j)", async (fields) => {
    kv.get.mockResolvedValue({
      ...snapshot,
      categories: snapshot.categories.map(category => ({
        ...category,
        cves: category.cves.map(({ software: _software, ...cve }) => ({ ...cve, ...fields })),
      })),
    });
    const response = await handleRequest(new Request("https://example.com/api/today.rss"), env, ctx, now);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("<title>CVE-2026-1000 [HIGH 8.1] Unknown</title>");
  });

  it("serves bodyless RSS HEAD", async () => {
    const response = await handleRequest(new Request("https://example.com/api/today.rss", { method: "HEAD" }), env, ctx, now);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("application/rss+xml");
    expect(await response.text()).toBe("");
  });

  it.each([null, "yesterday"])("returns RSS 503 when today's data is missing: %s", async (stored) => {
    kv.get.mockResolvedValue(stored ? buildSnapshot([], new Date("2026-11-18T23:00:00Z")) : null);
    const response = await handleRequest(new Request("https://example.com/api/today.rss"), env, ctx, now);
    expect(response.status).toBe(503);
    expect(response.headers.get("Retry-After")).toBe("300");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(cache.put).not.toHaveBeenCalled();
    expect(await response.text()).not.toContain("<item>");
  });

  it("keeps stale RSS items without caching", async () => {
    const response = await handleRequest(new Request("https://example.com/api/today.rss"), env, ctx, new Date("2026-11-19T11:00:00Z"));
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    const xml = await response.text();
    expect(xml).toContain("Stale snapshot");
    expect(xml).toContain("<item>");
    expect(cache.put).not.toHaveBeenCalled();
  });

  it("uses the edge cache before reading KV and ignores visitor query strings", async () => {
    cache.match.mockResolvedValue(new Response("cached"));
    const response = await handleRequest(new Request("https://example.com/?random=123"), env, ctx, now);
    expect(await response.text()).toBe("cached");
    expect((cache.match.mock.calls[0]![0] as Request).url).toBe("https://example.com/");
    expect(kv.get).not.toHaveBeenCalled();
  });

  it.each(["GET", "HEAD"])("revalidates browser caches even when cached %s headers carry a longer zone TTL", async (method) => {
    cache.match.mockResolvedValue(new Response("cached", {
      headers: { "Cache-Control": "public, max-age=14400, s-maxage=300, must-revalidate" },
    }));
    const response = await handleRequest(new Request("https://example.com/", { method }), env, ctx, now);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=0, must-revalidate");
    expect(await response.text()).toBe(method === "HEAD" ? "" : "cached");
    expect(kv.get).not.toHaveBeenCalled();
  });

  it.each([false, true])("serves a bodyless HEAD response (cache hit: %s)", async (cached) => {
    if (cached) cache.match.mockResolvedValue(new Response("cached", { headers: { "Content-Type": "text/html" } }));
    const response = await handleRequest(new Request("https://example.com/", { method: "HEAD" }), env, ctx, now);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("");
    expect(response.headers.get("Content-Type")).toContain("text/html");
  });

  it("does not cache an answer past UTC midnight", async () => {
    const late = new Date("2026-11-19T23:59:40Z");
    kv.get.mockResolvedValue(buildSnapshot([], late));
    const response = await handleRequest(new Request("https://example.com/"), env, ctx, late);
    expect(response.headers.get("Cache-Control")).toContain("s-maxage=20");
  });

  it("does not cache a fresh answer past the staleness threshold", async () => {
    kv.get.mockResolvedValue(buildSnapshot([], new Date("2026-11-19T08:00:00Z")));
    const response = await handleRequest(new Request("https://example.com/"), env, ctx, new Date("2026-11-19T09:29:40Z"));
    expect(response.headers.get("Cache-Control")).toContain("s-maxage=20");
  });

  it("labels stale data and retains the last successful result", async () => {
    const response = await handleRequest(new Request("https://example.com/"), env, ctx, new Date("2026-11-19T11:00:00Z"));
    expect(await response.text()).toContain("Stale data. Last successful check");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(cache.put).not.toHaveBeenCalled();
  });

  it.each([null, "yesterday"])("does not report NO when today's snapshot is missing: %s", async (stored) => {
    kv.get.mockResolvedValue(stored ? buildSnapshot([], new Date("2026-11-18T23:00:00Z")) : null);
    const htmlResponse = await handleRequest(new Request("https://example.com/"), env, ctx, now);
    expect(htmlResponse.status).toBe(200);
    expect(await htmlResponse.text()).toContain("Today's answer: CHECKING");
    expect(htmlResponse.headers.get("Cache-Control")).toBe("no-store");

    const apiResponse = await handleRequest(new Request("https://example.com/api/today.json"), env, ctx, now);
    expect(apiResponse.status).toBe(503);
    expect(apiResponse.headers.get("Retry-After")).toBe("300");
    expect(await apiResponse.json()).toEqual({ date: "2026-11-19", status: "pending", verdict: null });
    expect(cache.put).not.toHaveBeenCalled();
  });

  it("shows UNKNOWN rather than NO when KV fails", async () => {
    kv.get.mockRejectedValue(new Error("KV unavailable"));
    const response = await handleRequest(new Request("https://example.com/"), env, ctx, now);
    expect(response.status).toBe(503);
    expect(await response.text()).toContain("Today's answer: UNKNOWN");
    expect(cache.put).not.toHaveBeenCalled();
  });

  it("can still serve the snapshot if the edge cache fails", async () => {
    cache.match.mockRejectedValue(new Error("cache unavailable"));
    cache.put.mockRejectedValue(new Error("cache unavailable"));
    const response = await handleRequest(new Request("https://example.com/"), env, ctx, now);
    expect(response.status).toBe(200);
    await Promise.all((ctx.waitUntil as ReturnType<typeof vi.fn>).mock.calls.map(([promise]) => promise));
  });

  it.each([
    ["POST", "/", 405],
    ["GET", "/missing", 404],
    ["GET", "/__scheduled", 404],
    ["GET", "/favicon.ico", 204],
    ["GET", "/robots.txt", 200],
  ])("handles %s %s without reading KV or querying NVD", async (method, path, status) => {
    const response = await handleRequest(new Request(`https://example.com${path}`, { method }), env, ctx, now);
    expect(response.status).toBe(status);
    expect(kv.get).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("scheduled refresh", () => {
  it("replaces the snapshot only after a complete successful fetch", async () => {
    const fetchMock = mockFeeds();
    await refreshSnapshot(env, now);
    expect(kv.put).toHaveBeenCalledOnce();
    expect(kv.put.mock.calls[0]![0]).toBe("today");
    expect(JSON.parse(kv.put.mock.calls[0]![1])).toEqual(snapshot);
    expect(kv.put.mock.calls[0]![2]).toEqual({ expirationTtl: 24 * 60 * 60 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each(["nvd", "cve"])("does not write or extend snapshot expiration when %s fails", async (source) => {
    mockFeeds(source === "nvd" ? { nvdStatus: 503 } : { cveStatus: 503 });
    await expect(refreshSnapshot(env, now)).rejects.toThrow("HTTP 503");
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("keeps the previous snapshot for an invalid or partial upstream response", async () => {
    mockFeeds({ nvdPage: { startIndex: 0, totalResults: 1, vulnerabilities: [] } });
    await expect(refreshSnapshot(env, now)).rejects.toThrow("incomplete");
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("does not hide storage failures from cron monitoring", async () => {
    mockFeeds({ records: [], nvdPage: { startIndex: 0, totalResults: 0, vulnerabilities: [] } });
    kv.put.mockRejectedValue(new Error("write failed"));
    await expect(refreshSnapshot(env, now)).rejects.toThrow("write failed");
  });

  it("connects the scheduled handler to ingestion", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(now);
    mockFeeds({ records: [], nvdPage: { startIndex: 0, totalResults: 0, vulnerabilities: [] } });
    await worker.scheduled({} as ScheduledController, env);
    expect(kv.put).toHaveBeenCalledOnce();
    expect(JSON.parse(kv.put.mock.calls[0]![1])).toMatchObject({ verdict: "NO", date: "2026-11-19" });
    expect(kv.put.mock.calls[0]![2]).toEqual({ expirationTtl: 24 * 60 * 60 });
  });
});

function mockFeeds(options: { records?: CveRecord[]; nvdPage?: unknown; cveStatus?: number; nvdStatus?: number } = {}) {
  const fetchMock = vi.fn().mockImplementation(async (input: URL) => {
    if (input.hostname === "vulnerability.circl.lu") {
      return Response.json(options.records ?? [{
        cveMetadata: { cveId: "CVE-2026-1000", state: "PUBLISHED", datePublished: "2026-11-19T08:00:00.000Z" },
        containers: { cna: {
          providerMetadata: { orgId: "test@example.com" },
          descriptions: cve().descriptions,
          metrics: [{ cvssV3_1: { version: "3.1", baseScore: 8.1 } }],
        } },
      }], { status: options.cveStatus ?? 200 });
    }
    if (input.hostname === "services.nvd.nist.gov") {
      return Response.json(options.nvdPage ?? {
        startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: nvdCve() }],
      }, { status: options.nvdStatus ?? 200 });
    }
    throw new Error(`Unexpected upstream URL: ${input}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}
