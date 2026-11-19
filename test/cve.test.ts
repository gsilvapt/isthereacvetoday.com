import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchCveRecords, mergeCveRecords } from "../src/cve";
import { buildSnapshot } from "../src/snapshot";
import type { CveRecord } from "../src/types";
import fixture from "./fixtures/cve-photo-album.json";
import { nvdCve } from "./helpers";

const now = new Date("2026-11-19T09:00:00.000Z");

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("fetchCveRecords", () => {
  it("fetches the original CVE feed by publication date, not other advisory feeds", async () => {
    const fetchMock = vi.fn().mockResolvedValue(Response.json([fixture]));
    vi.stubGlobal("fetch", fetchMock);
    expect(await fetchCveRecords(now)).toEqual([fixture]);
    const [url, options] = fetchMock.mock.calls[0]!;
    expect(url.searchParams.get("source")).toBe("cvelistv5");
    expect(url.searchParams.get("date_sort")).toBe("published");
    expect(url.searchParams.get("since")).toBe("2026-11-19T00:00:00Z");
    expect(url.searchParams.get("per_page")).toBe("100");
    expect(options.headers["User-Agent"]).toContain("github.com/gsilvapt");
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(options.redirect).toBe("manual");
  });

  it("follows full pages and respects the anonymous rate limit", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(Response.json(Array.from({ length: 100 }, () => fixture)))
      .mockResolvedValueOnce(Response.json([fixture]));
    vi.stubGlobal("fetch", fetchMock);
    const result = fetchCveRecords(now);
    await vi.advanceTimersByTimeAsync(3099);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(await result).toHaveLength(101);
    expect(fetchMock.mock.calls[1]![0].searchParams.get("page")).toBe("2");
  });

  it.each([301, 429, 503])("fails closed for feed HTTP %s", async (status) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("error", { status })));
    await expect(fetchCveRecords(now)).rejects.toThrow(`HTTP ${status}`);
  });

  it.each([
    {},
    [{ cveMetadata: { cveId: "GHSA-xxxx-yyyy-zzzz", state: "PUBLISHED" } }],
    [{ cveMetadata: { ...fixture.cveMetadata, datePublished: undefined }, containers: fixture.containers }],
    [{ cveMetadata: { ...fixture.cveMetadata, datePublished: "invalid" }, containers: fixture.containers }],
    [{ cveMetadata: fixture.cveMetadata }],
    [{ cveMetadata: { ...fixture.cveMetadata, dateUpdated: "invalid" }, containers: fixture.containers }],
  ].map((data) => [data]))("rejects missing or invalid authoritative data %#", async (data) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json(data)));
    await expect(fetchCveRecords(now)).rejects.toThrow();
  });

  it("allows rejected records without CNA data so they can be excluded", async () => {
    const rejected = { cveMetadata: {
      cveId: fixture.cveMetadata.cveId, state: "REJECTED", dateUpdated: "2026-11-19T08:30:00Z",
    } };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json([rejected])));
    expect(await fetchCveRecords(now)).toEqual([rejected]);
  });

  it("never silently publishes a truncated feed at the subrequest cap", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockImplementation(async () => Response.json(Array.from({ length: 100 }, () => fixture)));
    vi.stubGlobal("fetch", fetchMock);
    const assertion = expect(fetchCveRecords(now)).rejects.toThrow("subrequest budget");
    await vi.runAllTimersAsync();
    await assertion;
    expect(fetchMock).toHaveBeenCalledTimes(20);
  });
});

describe("mergeCveRecords", () => {
  it("uses datePublished, never reservation, disclosure, NVD publication, or update dates", () => {
    const [cve] = mergeCveRecords([fixture], [nvdCve({ id: fixture.cveMetadata.cveId })]);
    expect(cve?.publishedAt).toBe("2026-11-19T08:00:13.233Z");
    const snapshot = buildSnapshot([cve!], now);
    expect(snapshot.totals).toEqual({ published: 1, critical: 1, high: 0, unscored: 0 });
    const [listed] = snapshot.categories.flatMap((category) => category.cves);
    expect(listed?.software).toEqual(["WP Photo Album Plus (wp-photo-album-plus)"]);
  });

  it("excludes old CVEs updated today or newly ingested by NVD today", () => {
    const older = { ...fixture, cveMetadata: { ...fixture.cveMetadata, datePublished: "2026-11-18T08:00:00Z" } };
    const merged = mergeCveRecords([older], [nvdCve({ id: fixture.cveMetadata.cveId })]);
    expect(buildSnapshot(merged, now).totals.published).toBe(0);
  });

  it("does not invent a CVE publication date for NVD-only records", () => {
    expect(mergeCveRecords([], [nvdCve()])).toEqual([]);
  });

  it("includes CVEs not yet in NVD and preserves CNA and ADP scores", () => {
    const enriched: CveRecord = {
      ...fixture,
      containers: { ...fixture.containers, adp: [{
        providerMetadata: { orgId: "adp-source" },
        metrics: [{ cvssV4_0: { version: "4.0", baseScore: 10 } }],
      }] },
    };
    const [merged] = mergeCveRecords([enriched], []);
    expect(merged?.sources).toEqual(["cve"]);
    expect(merged?.metrics?.cvssMetricV31?.[0]?.source).toBe(fixture.cveMetadata.assignerOrgId);
    const [listed] = buildSnapshot([merged!], now).categories.flatMap((category) => category.cves);
    expect(listed).toMatchObject({ score: 10, version: "4.0", source: "adp-source" });
  });

  it("counts one canonical CVE across sources and repeated feed entries", () => {
    const nvd = nvdCve({ id: fixture.cveMetadata.cveId.toLowerCase() });
    const merged = mergeCveRecords([fixture, fixture], [nvd, nvd]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.sources).toEqual(["cve", "nvd"]);
    expect(merged[0]?.id).toBe(fixture.cveMetadata.cveId);
  });

  it("uses the latest CVE revision even when duplicate records are out of order", () => {
    const older = { ...fixture, cveMetadata: { ...fixture.cveMetadata, dateUpdated: "2026-11-19T07:00:00Z" }, containers: { cna: {} } };
    expect(mergeCveRecords([fixture, older], [])[0]?.descriptions).toEqual(fixture.containers.cna.descriptions);
    expect(mergeCveRecords([older, fixture], [])[0]?.descriptions).toEqual(fixture.containers.cna.descriptions);
  });

  it("lets an authoritative rejection remove a CVE even if NVD still reports it", () => {
    const rejected = { cveMetadata: { ...fixture.cveMetadata, state: "REJECTED", dateUpdated: "2026-11-19T08:30:00Z" } };
    expect(mergeCveRecords([fixture, rejected], [nvdCve({ id: fixture.cveMetadata.cveId })])).toEqual([]);
  });

  it.each([false, true])("fails closed for a rejection without a revision date (reversed: %s)", (reversed) => {
    const records: CveRecord[] = [fixture, { cveMetadata: { cveId: fixture.cveMetadata.cveId, state: "REJECTED" } }];
    expect(() => mergeCveRecords(reversed ? records.toReversed() : records, [])).toThrow("revision date");
  });

  it.each([false, true])("fails closed for conflicting states at the same revision (reversed: %s)", (reversed) => {
    const records = [fixture, { cveMetadata: { ...fixture.cveMetadata, state: "REJECTED" } }];
    expect(() => mergeCveRecords(reversed ? records.toReversed() : records, [])).toThrow("conflicting states");
  });

  it("preserves NVD scores with their source when they determine the displayed severity", () => {
    const nvd = nvdCve({ id: fixture.cveMetadata.cveId, metrics: {
      cvssMetricV40: [{ source: "nvd@nist.gov", cvssData: { version: "4.0", baseScore: 10 } }],
    } });
    const merged = mergeCveRecords([fixture], [nvd]);
    const [listed] = buildSnapshot(merged, now).categories.flatMap((category) => category.cves);
    expect(listed).toMatchObject({ score: 10, source: "nvd@nist.gov", sources: ["cve", "nvd"] });
    expect(merged[0]?.metrics?.cvssMetricV31).toHaveLength(1);
  });
});
