import type { CategorySnapshot, SnapshotView } from "./types";
import styles from "./styles.css";

export function renderPage(view: SnapshotView): string {
  const { snapshot } = view;
  const verdict = snapshot?.verdict ?? (view.status === "unavailable" ? "UNKNOWN" : "CHECKING");
  const total = snapshot ? snapshot.totals.critical + snapshot.totals.high : 0;
  const description = snapshot
    ? total > 0
      ? `${total} High or Critical ${total === 1 ? "vulnerability" : "vulnerabilities"} first published in the CVE Program today. There goes the quiet day.`
      : "No High or Critical CVEs found in today's CVE Program publications yet. Enjoy the quiet while it lasts."
    : "No verdict until we have today's data. A quiet feed is not the same as a safe internet.";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="A daily check for High and Critical CVEs, grouped by technology. Updated every 30 minutes with CVE Program records, NVD enrichment, and OSV package names.">
  <meta name="color-scheme" content="light dark">
  <meta property="og:title" content="Is There a CVE Today? ${verdict}">
  <meta property="og:description" content="${escapeHtml(description)}">
  <link rel="alternate" type="application/rss+xml" title="Today's CVEs" href="/api/today.rss">
  <title>${verdict} | Is There a CVE Today?</title>
  <style>${styles}</style>
</head>
<body>
  <a class="skip-link" href="#categories">Skip to categories</a>
  <div class="shell">
    <header class="masthead">
      <a class="brand" href="/" aria-label="Is There a CVE Today? Home"><span aria-hidden="true">[ ! ]</span> THE DAILY CVE CHECK</a>
      <a class="donate" href="https://ko-fi.com/gsilvapt" rel="noopener noreferrer">Donate <span aria-hidden="true">↗</span></a>
    </header>
    <main>
      <section class="hero" aria-labelledby="question">
        <p class="eyebrow"><time datetime="${view.date}">${view.date}</time> / UTC / SAME INTERNET, NEW DAY</p>
        <h1 id="question">Is There a CVE Today?</h1>
        <h2 class="verdict ${verdict.toLowerCase()}" aria-label="Today's answer: ${verdict}">${verdict}<span aria-hidden="true">${verdict === "YES" || verdict === "NO" ? "." : "..."}</span></h2>
        <p class="intro">${escapeHtml(description)}</p>
        ${renderFreshness(view)}
        <p class="scope">We're counting <strong>High (7.0-8.9)</strong> and <strong>Critical (9.0-10.0)</strong> CVEs first published today in the CVE Program, not every vulnerability ever discovered.</p>
      </section>
      ${snapshot ? `
      <dl class="totals" aria-label="Today's totals">
        <div><dt>Critical</dt><dd class="critical-text">${snapshot.totals.critical}</dd></div>
        <div><dt>High</dt><dd>${snapshot.totals.high}</dd></div>
        <div><dt>Awaiting a score</dt><dd>${snapshot.totals.unscored}</dd></div>
        <div><dt>Published in total</dt><dd>${snapshot.totals.published}</dd></div>
      </dl>` : ""}
      <section id="categories" aria-labelledby="category-heading">
        <div class="section-heading"><h2 id="category-heading">Today's damage, by technology.</h2><span>RULES ONLY. NO AI.</span></div>
        ${snapshot ? `<p class="section-note">Open a category for the CVEs. Each CVE appears in one category.</p>
        <div class="categories">${snapshot.categories.map(renderCategory).join("")}</div>`
          : `<p class="empty-state">${view.status === "unavailable" ? "The stored result is unavailable. Please try again later." : "Waiting for today's first successful refresh. Check back after the next half-hour."}</p>`}
      </section>
      <section class="method" aria-labelledby="method-heading">
        <h2 id="method-heading">What counts?</h2>
        <p>YES means at least one CVE first published today in the CVE Program has a CVSS v3 or v4 base score of 7.0 or higher. We use the highest available score, whether supplied by NVD or a contributing organization. Rejected records are excluded.</p>
        <p>We check official CVE Program records mirrored by CIRCL Vulnerability Lookup every 30 minutes and enrich them with NVD data by CVE ID. The publication day comes from the CVE record's original publication date, not its NVD publication date. New records and scores can arrive late. Unscored CVEs don't affect the answer. Package names can also come from OSV advisories that list the CVE as an alias. They never change the totals or the answer, and can lag behind. Categories use product names, package registries, a few specialist publishers, and keyword rules. They can be wrong.</p>
        <p>Sources: <a href="https://www.cve.org/" rel="noopener noreferrer">CVE Program</a>, <a href="https://vulnerability.circl.lu/" rel="noopener noreferrer">CIRCL Vulnerability Lookup</a>, <a href="https://nvd.nist.gov/" rel="noopener noreferrer">National Vulnerability Database</a>, and <a href="https://osv.dev/" rel="noopener noreferrer">OSV</a>. <a href="/api/today.json">Today's JSON</a> · <a href="/api/today.rss">Today's RSS</a>.</p>
        <p>OSV collects package data from package-registry advisory databases, including GitHub, PyPI, Go, and RustSec. We use only CVE aliases and package names, under each source's license (CC BY 4.0, CC0 1.0, Apache 2.0, or MIT). See <a href="https://google.github.io/osv.dev/data/" rel="noopener noreferrer">OSV data sources and licenses</a>.</p>
        <p>This is an independent project and is not endorsed, certified, or supported by any of these sources.</p>
      </section>
    </main>
    <footer>
      <p>Made by <a href="https://github.com/gsilvapt" rel="noopener noreferrer">gsilvapt</a></p>
      <p>A small project. A very big attack surface.</p>
      <a href="https://github.com/gsilvapt/isthereacvetoday.com" rel="noopener noreferrer">Contribute on GitHub</a>
      <a href="https://ko-fi.com/gsilvapt" rel="noopener noreferrer">Donate on Ko-fi</a>
    </footer>
  </div>
</body>
</html>`;
}

function renderFreshness(view: SnapshotView): string {
  if (!view.snapshot) return "";
  const updatedAt = view.snapshot.updatedAt;
  const timestamp = `<time datetime="${escapeHtml(updatedAt)}">${escapeHtml(updatedAt.slice(11, 16))} UTC</time>`;
  const osvNote = view.snapshot.osv?.complete !== false ? "" : `\n        <p class="freshness">OSV package names may be incomplete.</p>`;
  if (view.status === "stale") {
    return `<p class="freshness stale" role="status">Stale data. Last successful check: ${timestamp}. Showing the last known result.</p>${osvNote}`;
  }
  return `<p class="freshness"><span class="dot" aria-hidden="true"></span> Last checked ${timestamp} / refreshes every 30 min</p>${osvNote}`;
}

function renderCategory(category: CategorySnapshot): string {
  const count = category.critical + category.high;
  const items = category.cves.map((cve) => `<li>
    <div class="cve-heading"><a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(cve.id)}" rel="noopener noreferrer">${escapeHtml(cve.id)} <span class="cve-software">${escapeHtml(cve.software.join("; ") || "Software not specified")}</span></a><span class="severity ${cve.severity.toLowerCase()}">${cve.severity} ${cve.score.toFixed(1)}</span></div>
    <p>${escapeHtml(cve.summary)}</p>
    <small>CVSS v${escapeHtml(cve.version)}</small>
  </li>`).join("");

  return `<details class="category ${count ? "affected" : "quiet"}" id="${escapeHtml(category.id)}">
    <summary>
      <span class="category-top"><span class="category-name">${escapeHtml(category.name)}</span><span class="category-answer">${count ? "YES" : "NO"}</span></span>
      <span class="category-count">${count}<span> ${count === 1 ? "CVE" : "CVEs"}</span></span>
      <span class="category-meta">${category.critical} critical / ${category.high} high${category.maxScore === null ? "" : ` / max ${category.maxScore.toFixed(1)}`}</span>
      <span class="expand-hint">${count ? "View CVEs +" : "No High or Critical CVEs"}</span>
    </summary>
    ${count ? `<ul class="cve-list">${items}</ul>` : `<p class="quiet-note">None found in this category in the last successful check.</p>`}
  </details>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]!);
}
