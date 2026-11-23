import { describe, expect, it } from "vitest";
import { renderPage } from "../src/page";
import { buildSnapshot, getSnapshotView, STALE_AFTER_MS } from "../src/snapshot";
import { completeOsv, cve } from "./helpers";

const now = new Date("2026-11-19T09:00:00.000Z");

describe("renderPage", () => {
  it("escapes upstream descriptions before rendering HTML", () => {
    const snapshot = buildSnapshot([cve({
      descriptions: [{ lang: "en", value: '<script>alert("xss")</script> & <img src=x onerror=alert(1)>' }],
    })], now, completeOsv);
    const html = renderPage(getSnapshotView(snapshot, now));
    expect(html).toContain("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt; &amp; &lt;img");
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<img");
  });

  it("shows affected software beside the CVE ID", () => {
    const snapshot = buildSnapshot([cve({
      id: "CVE-2026-129048",
      affected: [{ affectedData: [{ product: "WP Photo Album Plus", packageName: "wp-photo-album-plus" }] }],
    })], now, completeOsv);
    const html = renderPage(getSnapshotView(snapshot, now));
    expect(html).toContain('CVE-2026-129048 <span class="cve-software">WP Photo Album Plus (wp-photo-album-plus)</span>');
  });

  it("escapes affected software names before rendering HTML", () => {
    const snapshot = buildSnapshot([cve({
      affected: [{ affectedData: [{ product: '<img src=x onerror=alert("xss")> & \'software\'' }] }],
    })], now, completeOsv);
    const html = renderPage(getSnapshotView(snapshot, now));
    expect(html).toContain('<span class="cve-software">&lt;img src=x onerror=alert(&quot;xss&quot;)&gt; &amp; &#39;software&#39;</span>');
    expect(html).not.toContain("<img");
  });

  it("labels CVEs without affected software", () => {
    const snapshot = buildSnapshot([cve({ affected: [], configurations: [] })], now, completeOsv);
    const html = renderPage(getSnapshotView(snapshot, now));
    expect(html).toContain('<span class="cve-software">Software not specified</span>');
  });

  it("includes all categories, native expandable lists, and one advisory link per CVE", () => {
    const snapshot = buildSnapshot([cve(), cve({ id: "CVE-2026-1001" })], now, completeOsv);
    const html = renderPage(getSnapshotView(snapshot, now));
    expect(html.match(/<details class="category /g)).toHaveLength(10);
    expect(html).toContain('<h2 class="verdict yes" aria-label="Today\'s answer: YES">');
    const items = html.match(/<li>[\s\S]*?<\/li>/g) ?? [];
    expect(items).toHaveLength(2);
    for (const item of items) {
      expect(item.match(/<a /g)).toHaveLength(1);
      expect(item).toContain('<div class="cve-heading"><a href="https://www.cve.org/CVERecord?id=');
    }
    expect(html).toContain("https://www.cve.org/CVERecord?id=CVE-2026-1000");
    expect(html).toContain("https://www.cve.org/CVERecord?id=CVE-2026-1001");
    expect(html).not.toContain("https://nvd.nist.gov/vuln/detail/");
    expect(html).not.toContain(">CVE record</a>");
    expect(html).toContain('href="#categories"');
  });

  it("explains original CVE Program publication and attributes all data sources", () => {
    const snapshot = buildSnapshot([cve()], now, completeOsv);
    const html = renderPage(getSnapshotView(snapshot, now));
    expect(html).toContain("first published in the CVE Program today");
    expect(html).toContain("CVEs first published today in the CVE Program");
    expect(html).toContain("official CVE Program records mirrored by CIRCL Vulnerability Lookup");
    expect(html).toContain("enrich them with NVD data by CVE ID");
    expect(html).toContain("original publication date, not its NVD publication date");
    expect(html).toContain('href="https://www.cve.org/"');
    expect(html).toContain('href="https://vulnerability.circl.lu/"');
    expect(html).toContain('href="https://nvd.nist.gov/"');
    expect(html).toContain('href="https://osv.dev/"');
    expect(html).toContain('href="https://google.github.io/osv.dev/data/"');
    expect(html).toContain("under each source's license (CC BY 4.0, CC0 1.0, Apache 2.0, or MIT)");
    expect(html).toContain("They never change the totals or the answer");
    expect(html).toContain(`<a href="/api/today.json">Today's JSON</a>`);
    expect(html).toContain(`<a href="/api/today.rss">Today's RSS</a>`);
    expect(html).toContain(`rel="alternate" type="application/rss+xml" title="Today's CVEs" href="/api/today.rss"`);
    expect(html).toContain("<p>This is an independent project and is not endorsed, certified, or supported by any of these sources.</p>");
    expect(html).not.toContain("This product uses the NVD API but is not endorsed or certified by the NVD.");
    expect(html).not.toContain("published today in NVD");
    expect(html).not.toContain("We check NVD every 30 minutes");
    expect(html).not.toContain("Days start at 00:00 UTC");
  });

  it("makes the NO verdict specific to the available scored data", () => {
    const snapshot = buildSnapshot([cve({ metrics: {} })], now, completeOsv);
    const html = renderPage(getSnapshotView(snapshot, now));
    expect(html).toContain("Today's answer: NO");
    expect(html).toContain("No High or Critical CVEs found in today&#39;s CVE Program publications yet");
    expect(html).toContain("Awaiting a score");
    expect(html).toContain("Unscored CVEs don't affect the answer");
  });

  it("keeps the author, repository, and donation footer links visible before the first refresh", () => {
    const html = renderPage(getSnapshotView(null, now));
    const footer = html.match(/<footer>[\s\S]*?<\/footer>/)?.[0] ?? "";
    expect(html).toContain("CHECKING");
    expect(footer).toContain('Made by <a href="https://github.com/gsilvapt" rel="noopener noreferrer">gsilvapt</a>');
    expect(footer).toContain('<a href="https://github.com/gsilvapt/isthereacvetoday.com" rel="noopener noreferrer">Contribute on GitHub</a>');
    expect(footer).toContain('<a href="https://ko-fi.com/gsilvapt" rel="noopener noreferrer">Donate on Ko-fi</a>');
    expect(html).not.toContain('class="category quiet"');
  });

  it.each([0, STALE_AFTER_MS])("notes incomplete OSV package data %i ms after the refresh", (age) => {
    const note = '<p class="freshness">OSV package names may be incomplete.</p>';
    const later = new Date(now.getTime() + age);
    expect(renderPage(getSnapshotView(buildSnapshot([cve()], now, completeOsv), later))).not.toContain("OSV package names may be incomplete");
    const html = renderPage(getSnapshotView(buildSnapshot([cve()], now, { complete: false, through: null }), later));
    expect(html.match(/OSV package names may be incomplete/g)).toHaveLength(1);
    expect(html).toContain(note);
  });

  it("renders a snapshot stored before OSV enrichment without an OSV note", () => {
    const { osv: _osv, ...stored } = buildSnapshot([cve()], now, completeOsv);
    const html = renderPage(getSnapshotView(stored, now));
    expect(html).toContain("Today's answer: YES");
    expect(html).not.toContain("OSV package names may be incomplete");
  });
});
