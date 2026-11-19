import { describe, expect, it } from "vitest";
import { renderRss } from "../src/rss";
import type { Snapshot, ListedCve } from "../src/types";

const entry: ListedCve = {
  id: "CVE-2026-1000", publishedAt: "2026-11-19T08:00:00Z", sources: ["cve"],
  severity: "HIGH", score: 8.1, version: "3.1", source: "test",
  software: ["A & B <tool>"], summary: "<script>alert(1)</script> & test\u0000",
};
const snapshot: Snapshot = {
  date: "2026-11-19", updatedAt: "2026-11-19T09:00:00Z", verdict: "YES",
  totals: { published: 1, high: 1, critical: 0, unscored: 0 },
  categories: [{ id: "test", name: "Tools & libraries", high: 1, critical: 0, maxScore: 8.1, cves: [entry] }],
};

describe("RSS rendering", () => {
  it("escapes XML and HTML descriptions, preserves stable IDs and formats dates", () => {
    const xml = renderRss({ date: snapshot.date, status: "ready", snapshot });
    expect(xml).toContain('<rss version="2.0"');
    expect(xml).toContain("A &amp; B &lt;tool&gt;");
    expect(xml).toContain("&amp;lt;script&amp;gt;");
    expect(xml).not.toContain("<script>");
    expect(xml).not.toContain("\u0000");
    expect(xml).toContain("<category>Tools &amp; libraries</category>");
    expect(xml).toContain("<pubDate>Thu, 19 Nov 2026 08:00:00 GMT</pubDate>");
    expect(xml).toContain('<guid isPermaLink="false">CVE-2026-1000</guid>');
    expect(xml).toContain("<lastBuildDate>Thu, 19 Nov 2026 09:00:00 GMT</lastBuildDate>");
  });

  it("renders a successful empty feed without fictitious items", () => {
    const xml = renderRss({ date: snapshot.date, status: "ready", snapshot: { ...snapshot, categories: [], verdict: "NO" } });
    expect(xml).not.toContain("<item>");
    expect(xml).toContain("</rss>");
  });
});
