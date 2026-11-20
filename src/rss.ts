import type { SnapshotView } from "./types";

// XML 1.0 excludes control characters and unpaired UTF-16 surrogates.
function escapeXml(value: string): string {
  return value.replace(/[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/gu, "")
    .replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;",
    })[character]!);
}

// RSS readers may interpret description contents as HTML. Escape the plain
// text for that context as well as the enclosing XML document.
function description(value: string): string {
  return escapeXml(escapeXml(value));
}

export function renderRss(view: SnapshotView, feedUrl: URL): string {
  const { snapshot } = view;
  const items = (snapshot?.categories ?? []).flatMap((category) =>
    category.cves.map((cve) => ({ category: category.name, cve })))
    .sort((a, b) => Date.parse(b.cve.publishedAt) - Date.parse(a.cve.publishedAt)
      || a.cve.id.localeCompare(b.cve.id));
  const status = view.status === "stale" ? " Stale snapshot; last successful refresh shown."
    : !snapshot ? " Current data is unavailable; retry later." : "";
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Is There a CVE Today?</title>
    <link>${escapeXml(feedUrl.origin)}/</link>
    <atom:link href="${escapeXml(feedUrl.origin + feedUrl.pathname)}" rel="self" type="application/rss+xml" />
    <description>${escapeXml(`High and Critical CVEs first published today (UTC).${status}`)}</description>
    <language>en</language>
    ${snapshot ? `<lastBuildDate>${new Date(snapshot.updatedAt).toUTCString()}</lastBuildDate>` : ""}
    ${items.map(({ category, cve }) => `<item>
      <title>${escapeXml(`${cve.id} [${cve.severity} ${cve.score.toFixed(1)}] ${cve.software?.join("; ") || "Unknown"}`)}</title>
      <link>https://www.cve.org/CVERecord?id=${encodeURIComponent(cve.id)}</link>
      <guid isPermaLink="false">${escapeXml(cve.id)}</guid>
      <pubDate>${new Date(cve.publishedAt).toUTCString()}</pubDate>
      <category>${escapeXml(category)}</category>
      <category>${cve.severity}</category>
      <description>${description(`${cve.summary} (CVSS v${cve.version}: ${cve.score.toFixed(1)})`)}</description>
    </item>`).join("\n")}
  </channel>
</rss>`;
}
