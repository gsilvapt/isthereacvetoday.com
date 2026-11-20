import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { handleRequest, refreshSnapshot } from "../src/index";
import { buildSnapshot } from "../src/snapshot";
import type { CveRecord, Env, OsvState, Snapshot } from "../src/types";
import { completeOsv, cve, nvdCve } from "./helpers";

const now = new Date("2026-11-19T09:00:00.000Z");
let snapshot: Snapshot;
let env: Env;
let ctx: ExecutionContext;
let kv: { get: ReturnType<typeof vi.fn>; put: ReturnType<typeof vi.fn> };
let cache: { match: ReturnType<typeof vi.fn>; put: ReturnType<typeof vi.fn> };

beforeEach(() => {
  snapshot = buildSnapshot([cve({ sources: ["cve", "nvd"] })], now, completeOsv);
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
      date: "2026-11-19", status: "ready", verdict: "YES", totals: { high: 1 }, osv: completeOsv,
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
    kv.get.mockResolvedValue(stored ? buildSnapshot([], new Date("2026-11-18T23:00:00Z"), completeOsv) : null);
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
    kv.get.mockResolvedValue(buildSnapshot([], late, completeOsv));
    const response = await handleRequest(new Request("https://example.com/"), env, ctx, late);
    expect(response.headers.get("Cache-Control")).toContain("s-maxage=20");
  });

  it("does not cache a fresh answer past the staleness threshold", async () => {
    kv.get.mockResolvedValue(buildSnapshot([], new Date("2026-11-19T08:00:00Z"), completeOsv));
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
    kv.get.mockResolvedValue(stored ? buildSnapshot([], new Date("2026-11-18T23:00:00Z"), completeOsv) : null);
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
  const osvState: OsvState = {
    date: "2026-11-19",
    cursor: "2026-11-19T08:10:00.000000000Z",
    gap: false,
    records: [{
      id: "GHSA-earlier",
      modified: "2026-11-19T08:10:00.000000000Z",
      cves: ["CVE-2026-1000"],
      packages: [{ ecosystem: "npm", name: "earlier-package" }],
    }],
  };

  beforeEach(() => {
    kv.get.mockResolvedValue(null);
  });

  it("replaces the snapshot only after a complete successful fetch", async () => {
    const fetchMock = mockFeeds();
    await refreshSnapshot(env, now);
    expect(kv.put).toHaveBeenCalledTimes(2);
    expect(kv.put.mock.calls[0]![0]).toBe("today");
    expect(JSON.parse(kv.put.mock.calls[0]![1])).toEqual({
      ...snapshot, osv: { complete: true, through: null },
    });
    expect(JSON.parse(kv.put.mock.calls[1]![1])).toMatchObject({ cursor: null });
    expect(kv.put.mock.calls[0]![2]).toEqual({ expirationTtl: 24 * 60 * 60 });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("adds OSV packages and saves OSV state after the snapshot", async () => {
    kv.get.mockResolvedValue(JSON.stringify(osvState));
    mockFeeds({
      osvLines: ["2026-11-19T08:30:00Z,PyPI/GHSA-new", osvStop],
      osvRecords: { "PyPI/GHSA-new.json": {
        id: "GHSA-new", modified: "2026-11-19T08:30:00Z", aliases: ["CVE-2026-1000"],
        affected: [{ package: { ecosystem: "PyPI", name: "new-package" } }],
      } },
    });
    await refreshSnapshot(env, now);
    expect(kv.get).toHaveBeenCalledWith("osv");
    expect(kv.put.mock.calls.map(([key]) => key)).toEqual(["today", "osv"]);
    const published: Snapshot = JSON.parse(kv.put.mock.calls[0]![1]);
    expect(published.osv).toEqual({ complete: true, through: "2026-11-19T08:30:00.000000000Z" });
    expect(published.totals).toEqual(snapshot.totals);
    expect(published.categories.find((category) => category.id === "libraries")?.cves[0]).toMatchObject({
      id: "CVE-2026-1000", sources: ["cve", "nvd", "osv"], software: ["earlier-package", "new-package"],
    });
    expect(JSON.parse(kv.put.mock.calls[1]![1])).toMatchObject({
      date: "2026-11-19", cursor: "2026-11-19T08:30:00.000000000Z", records: [{ id: "GHSA-earlier" }, { id: "GHSA-new" }],
    });
    expect(kv.put.mock.calls[1]![2]).toEqual({ expirationTtl: 24 * 60 * 60 });
  });

  it("publishes with earlier OSV packages and leaves OSV state unchanged when OSV fails", async () => {
    kv.get.mockResolvedValue(JSON.stringify(osvState));
    mockFeeds({ osvStatus: 500 });
    await refreshSnapshot(env, now);
    expect(kv.put).toHaveBeenCalledOnce();
    const published: Snapshot = JSON.parse(kv.put.mock.calls[0]![1]);
    expect(published).toMatchObject({ verdict: "YES", totals: snapshot.totals, osv: { complete: false, through: osvState.cursor } });
    expect(published.categories.flatMap((category) => category.cves)[0]?.software).toEqual(["earlier-package"]);
    expect(console.warn).toHaveBeenCalled();
  });

  it("publishes an incomplete OSV status when OSV hits its cap", async () => {
    mockFeeds({ osvLines: [...Array.from({ length: 10 }, (_, index) => `2026-11-19T08:${10 + index}:00Z,PyPI/GHSA-${index}`).toReversed(), osvStop] });
    await refreshSnapshot(env, now);
    expect(kv.put.mock.calls.map(([key]) => key)).toEqual(["today", "osv"]);
    expect(JSON.parse(kv.put.mock.calls[0]![1])).toMatchObject({ verdict: "YES", osv: { complete: false } });
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

  it.each([1, 2])("does not hide storage failures from cron monitoring (write %i)", async (failingWrite) => {
    mockFeeds({ records: [], nvdPage: { startIndex: 0, totalResults: 0, vulnerabilities: [] } });
    if (failingWrite === 2) kv.put.mockResolvedValueOnce(undefined);
    kv.put.mockRejectedValueOnce(new Error("write failed"));
    await expect(refreshSnapshot(env, now)).rejects.toThrow("write failed");
    expect(kv.put).toHaveBeenCalledTimes(failingWrite);
    expect(console.error).toHaveBeenCalledWith(
      expect.stringMatching(failingWrite === 1 ? /^Snapshot refresh failed/ : /^OSV progress save failed; the snapshot was saved/),
      expect.any(Error),
    );
  });

  it("connects the scheduled handler to ingestion", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(now);
    mockFeeds({ records: [], nvdPage: { startIndex: 0, totalResults: 0, vulnerabilities: [] } });
    await worker.scheduled({} as ScheduledController, env);
    expect(kv.put).toHaveBeenCalledTimes(2);
    expect(JSON.parse(kv.put.mock.calls[0]![1])).toMatchObject({ verdict: "NO", date: "2026-11-19" });
    expect(kv.put.mock.calls[0]![2]).toEqual({ expirationTtl: 24 * 60 * 60 });
  });
});

const osvStop = "2026-11-18T22:00:00Z,PyPI/GHSA-before-scan";

function mockFeeds(options: {
  records?: CveRecord[];
  nvdPage?: unknown;
  cveStatus?: number;
  nvdStatus?: number;
  osvLines?: string[];
  osvRecords?: Record<string, unknown>;
  osvStatus?: number;
} = {}) {
  const fetchMock = vi.fn().mockImplementation(async (input: URL | string) => {
    const url = new URL(input);
    if (url.hostname === "vulnerability.circl.lu") {
      return Response.json(options.records ?? [{
        cveMetadata: { cveId: "CVE-2026-1000", state: "PUBLISHED", datePublished: "2026-11-19T08:00:00.000Z" },
        containers: { cna: {
          providerMetadata: { orgId: "test@example.com" },
          descriptions: cve().descriptions,
          metrics: [{ cvssV3_1: { version: "3.1", baseScore: 8.1 } }],
        } },
      }], { status: options.cveStatus ?? 200 });
    }
    if (url.hostname === "services.nvd.nist.gov") {
      return Response.json(options.nvdPage ?? {
        startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: nvdCve() }],
      }, { status: options.nvdStatus ?? 200 });
    }
    if (url.hostname === "osv-vulnerabilities.storage.googleapis.com") {
      const path = decodeURIComponent(url.pathname.slice(1));
      if (path === "modified_id.csv") {
        return new Response(`${(options.osvLines ?? [osvStop]).join("\n")}\n`, { status: options.osvStatus ?? 206 });
      }
      const [modified] = options.osvLines?.find((line) => line.endsWith(`,${path.replace(/\.json$/, "")}`))?.split(",") ?? [];
      return Response.json(options.osvRecords?.[path] ?? { id: path.split("/")[1]!.replace(/\.json$/, ""), modified });
    }
    throw new Error(`Unexpected upstream URL: ${input}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}
