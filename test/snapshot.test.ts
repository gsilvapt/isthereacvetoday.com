import { describe, expect, it } from "vitest";
import { buildSnapshot, getSnapshotView, highestScore, STALE_AFTER_MS } from "../src/snapshot";
import fixture from "./fixtures/nvd-sample.json";
import { cve } from "./helpers";

const now = new Date("2026-11-19T09:00:00.000Z");

describe("buildSnapshot", () => {
  it("uses numeric High/Critical boundaries", () => {
    const snapshot = buildSnapshot([6.9, 7, 8.9, 9, 10].map((baseScore, index) => cve({
      id: `CVE-2026-${1000 + index}`,
      metrics: { cvssMetricV31: [{ cvssData: { version: "3.1", baseScore } }] },
    })), now);
    expect(snapshot.verdict).toBe("YES");
    expect(snapshot.totals).toEqual({ published: 5, critical: 2, high: 2, unscored: 0 });
    const other = snapshot.categories.find((category) => category.id === "other")!;
    expect(other.maxScore).toBe(10);
    expect(other.cves.map((entry) => entry.score)).toEqual([10, 9, 8.9, 7]);
  });

  it("counts unscored and v2-only CVEs without treating them as High/Critical", () => {
    const snapshot = buildSnapshot([
      cve({ metrics: undefined }),
      cve({ id: "CVE-2026-1001", metrics: { cvssMetricV2: [{ cvssData: { version: "2.0", baseScore: 10 } }] } }),
    ], now);
    expect(snapshot.verdict).toBe("NO");
    expect(snapshot.totals.unscored).toBe(2);
  });

  it.each([
    ["includes exact UTC midnight", "2026-11-19T00:00:00.000Z", 1],
    ["includes the current instant", "2026-11-19T09:00:00.000Z", 1],
    ["excludes the previous UTC day", "2026-11-18T23:59:59.999Z", 0],
    ["excludes a future instant today", "2026-11-19T09:00:00.001Z", 0],
    ["excludes the next UTC day", "2026-11-20T00:00:00.000Z", 0],
    ["includes an offset timestamp at UTC midnight", "2026-11-19T01:00:00.000+01:00", 1],
    ["includes a previous local date falling today UTC", "2026-11-18T23:30:00.000-01:00", 1],
    ["excludes a current local date falling yesterday UTC", "2026-11-19T00:30:00.000+01:00", 0],
    ["excludes a future instant expressed with an offset", "2026-11-19T08:30:00.000-01:00", 0],
    ["excludes invalid publication timestamps", "not-a-timestamp", 0],
  ])("%s", (_name, publishedAt, published) => {
    const snapshot = buildSnapshot([cve({ publishedAt })], now);
    expect(snapshot.totals).toEqual({ published, critical: 0, high: published, unscored: 0 });
    expect(snapshot.categories.flatMap((category) => category.cves)).toHaveLength(published);
    expect(snapshot.verdict).toBe(published ? "YES" : "NO");
    expect(snapshot.date).toBe("2026-11-19");
    expect(snapshot.updatedAt).toBe(now.toISOString());
  });

  it.each(["Rejected", "REJECTED", "rejected"])("skips %s records", (vulnStatus) => {
    const snapshot = buildSnapshot([cve({ vulnStatus })], now);
    expect(snapshot.totals).toEqual({ published: 0, critical: 0, high: 0, unscored: 0 });
    expect(snapshot.verdict).toBe("NO");
    expect(snapshot.categories.every((category) => category.cves.length === 0)).toBe(true);
  });

  it("counts and lists each CVE ID once", () => {
    const snapshot = buildSnapshot([cve(), cve({ sources: ["cve", "nvd"] })], now);
    expect(snapshot.totals).toEqual({ published: 1, critical: 0, high: 1, unscored: 0 });
    expect(snapshot.categories.flatMap((category) => category.cves).map((entry) => entry.id))
      .toEqual(["CVE-2026-1000"]);
  });

  it("does not let an excluded duplicate hide an eligible record", () => {
    const snapshot = buildSnapshot([
      cve({ publishedAt: "2026-11-18T08:00:00.000Z" }),
      cve(),
    ], now);
    expect(snapshot.totals).toEqual({ published: 1, critical: 0, high: 1, unscored: 0 });
  });

  it("preserves publication, provenance, software, and scoring metadata in listed CVEs", () => {
    const record = cve({
      publishedAt: "2026-11-19T02:34:56.789Z",
      sources: ["cve", "nvd"],
      affected: [{ affectedData: [{ product: "Example Server", packageName: "example-server" }] }],
      descriptions: [{ lang: "en", value: "An issue in Example Server." }],
    });
    const snapshot = buildSnapshot([record], now);
    expect(snapshot.categories.flatMap((category) => category.cves)).toEqual([{
      id: record.id,
      publishedAt: record.publishedAt,
      sources: ["cve", "nvd"],
      severity: "HIGH",
      software: ["Example Server (example-server)"],
      score: 8.1,
      version: "3.1",
      source: "test@example.com",
      summary: "An issue in Example Server.",
    }]);
  });

  it("returns NO for a successfully fetched empty day", () => {
    const snapshot = buildSnapshot([], now);
    expect(snapshot.verdict).toBe("NO");
    expect(snapshot.categories).toHaveLength(10);
    expect(snapshot.categories.every((category) => category.maxScore === null)).toBe(true);
  });

  it("normalizes descriptions and provides an English fallback", () => {
    const snapshot = buildSnapshot([
      cve({ descriptions: [{ lang: "en", value: `Text\n\t${"x".repeat(800)}` }] }),
      cve({ id: "CVE-2026-1001", descriptions: [{ lang: "pt", value: "Texto" }] }),
    ], now);
    const entries = snapshot.categories.flatMap((category) => category.cves);
    expect(entries[0]?.summary).toHaveLength(600);
    expect(entries[0]?.summary).not.toMatch(/\s{2}/);
    expect(entries[1]?.summary).toBe("No English description available.");
  });

  it("normalizes products and metrics from sampled NVD metadata", () => {
    // Supply a test-only CVE Program date, not the sample's NVD publication time.
    const records = fixture.vulnerabilities.map(({ cve: { published: _published, ...metadata } }) => cve({
      ...metadata,
      publishedAt: "2026-11-19T08:00:00.000Z",
      sources: ["cve", "nvd"],
    }));
    const snapshot = buildSnapshot(records, now);
    expect(snapshot.totals).toEqual({ published: 5, high: 3, critical: 0, unscored: 0 });
    expect(snapshot.categories.find((category) => category.id === "libraries")?.cves[0]).toMatchObject({
      id: "CVE-2026-126962",
      software: ["open62541"],
      score: 8.8,
      version: "3.0",
      source: "zdi-disclosures@trendmicro.com",
    });
  });
});

describe("affected software", () => {
  it("combines a product and its distinct package name", () => {
    const snapshot = buildSnapshot([cve({ affected: [{ affectedData: [
      { product: "  Example\n Server  ", packageName: " example-server " },
    ] }] })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software)
      .toEqual(["Example Server (example-server)"]);
  });

  it("does not repeat a package name matching its product case-insensitively", () => {
    const snapshot = buildSnapshot([cve({ affected: [{ affectedData: [
      { product: "ExampleServer", packageName: "exampleserver" },
    ] }] })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software).toEqual(["ExampleServer"]);
  });

  it("lists multiple affected products across containers", () => {
    const snapshot = buildSnapshot([cve({ affected: [
      { affectedData: [{ product: "Example Server" }, { product: "Example Client" }] },
      { affectedData: [{ product: "Example Agent" }] },
    ] })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software)
      .toEqual(["Example Server", "Example Client", "Example Agent"]);
  });

  it("deduplicates software names case-insensitively", () => {
    const snapshot = buildSnapshot([cve({ affected: [{ affectedData: [
      { product: "Example Server", packageName: "example-server" },
      { product: "EXAMPLE SERVER", packageName: "EXAMPLE-SERVER" },
      { product: "Example Client" },
      { product: "example client" },
    ] }] })], now);
    const software = snapshot.categories.flatMap((category) => category.cves)[0]!.software;
    expect(software.map((name) => name.toLowerCase())).toEqual(["example server (example-server)", "example client"]);
  });

  it.each(["CNA first", "NVD first"])("prefers the richer cross-source product label with %s", (order) => {
    const affected = [
      { affectedData: [{ product: "Example Server", packageName: "example-server" }] },
      { affectedData: [{ product: "Example Server" }] },
    ];
    const snapshot = buildSnapshot([cve({
      sources: ["cve", "nvd"],
      affected: order === "CNA first" ? affected : affected.toReversed(),
    })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software)
      .toEqual(["Example Server (example-server)"]);
  });

  it.each(["package-only first", "named product first"])("merges entries sharing a package with %s", (order) => {
    const affected = [
      { affectedData: [{ packageName: "@example/server" }] },
      { affectedData: [{ product: "Example Server", packageName: "@example/server" }] },
    ];
    const snapshot = buildSnapshot([cve({
      sources: ["cve", "nvd"],
      affected: order === "package-only first" ? affected : affected.toReversed(),
    })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software)
      .toEqual(["Example Server (@example/server)"]);
  });

  it("retains distinct package labels for the same product name", () => {
    const snapshot = buildSnapshot([cve({
      sources: ["cve", "nvd"],
      affected: [
        { affectedData: [{ product: "Example Server", packageName: "@example/server" }] },
        { affectedData: [{ product: "Example Server", packageName: "@legacy/server" }] },
      ],
    })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software)
      .toEqual(["Example Server (@example/server)", "Example Server (@legacy/server)"]);
  });

  it.each(["n/a", "NA", "Unknown", "unspecified", "not specified", "not available", "*", "-", "", " \t "])(
    "omits the unavailable product placeholder %j",
    (product) => {
      const snapshot = buildSnapshot([cve({ affected: [{ affectedData: [{ product }] }] })], now);
      expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software).toEqual([]);
    },
  );

  it.each([undefined, "n/a", "unknown"])("falls back to packageName when product is %j", (product) => {
    const snapshot = buildSnapshot([cve({ affected: [{ affectedData: [
      { product, packageName: "@example/server" },
    ] }] })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software).toEqual(["@example/server"]);
  });

  it("falls back to affected CPEs and excludes non-vulnerable platform CPEs", () => {
    const snapshot = buildSnapshot([cve({
      affected: [{ affectedData: [{
        product: "unknown",
        cpes: ["cpe:2.3:a:example:example_server:*:*:*:*:*:*:*:*"],
      }] }],
      configurations: [{ nodes: [{ cpeMatch: [
        { vulnerable: true, criteria: "cpe:/a:example:example_client:1" },
        { vulnerable: false, criteria: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*" },
      ] }] }],
    })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software)
      .toEqual(["example server", "example client"]);
  });

  it("returns an empty list when software metadata is missing", () => {
    const snapshot = buildSnapshot([cve({
      affected: undefined,
      configurations: undefined,
      descriptions: undefined,
      sourceIdentifier: undefined,
    })], now);
    expect(snapshot.categories.flatMap((category) => category.cves)[0]?.software).toEqual([]);
  });
});

describe("highestScore", () => {
  it("uses the highest CNA/NVD v3/v4 score, preferring v4 for a tie", () => {
    expect(highestScore(cve({ metrics: {
      cvssMetricV40: [{ source: "cna", cvssData: { version: "4.0", baseScore: 9.3 } }],
      cvssMetricV31: [
        { source: "nvd", cvssData: { version: "3.1", baseScore: 8.8 } },
        { source: "other", cvssData: { version: "3.1", baseScore: 9.3 } },
      ],
    } }))).toEqual({ score: 9.3, version: "4.0", source: "cna" });
  });

  it("does not let a lower v4 score hide a higher v3 score", () => {
    expect(highestScore(cve({ metrics: {
      cvssMetricV40: [{ cvssData: { version: "4.0", baseScore: 2.1 } }],
      cvssMetricV31: [{ cvssData: { version: "3.1", baseScore: 8.1 } }],
    } }))?.score).toBe(8.1);
  });

  it.each([-1, 10.1, Number.NaN, Number.POSITIVE_INFINITY])("ignores invalid score %s", (baseScore) => {
    expect(highestScore(cve({ metrics: { cvssMetricV31: [{ cvssData: { version: "3.1", baseScore } }] } }))).toBeNull();
  });

  it("accepts a zero score", () => {
    expect(highestScore(cve({ metrics: { cvssMetricV31: [{ cvssData: { version: "3.1", baseScore: 0 } }] } }))?.score).toBe(0);
  });
});

describe("getSnapshotView", () => {
  it("withholds yesterday's verdict at UTC midnight", () => {
    const yesterday = buildSnapshot([cve()], now);
    expect(getSnapshotView(yesterday, new Date("2026-11-20T00:00:00Z"))).toEqual({
      date: "2026-11-20", status: "pending", snapshot: null,
    });
    expect(getSnapshotView(null, now).status).toBe("pending");
  });

  it("marks the last good result stale after 90 minutes", () => {
    const snapshot = buildSnapshot([cve()], now);
    expect(getSnapshotView(snapshot, new Date(now.getTime() + STALE_AFTER_MS - 1)).status).toBe("ready");
    expect(getSnapshotView(snapshot, new Date(now.getTime() + STALE_AFTER_MS))).toMatchObject({ status: "stale", snapshot });
  });
});
