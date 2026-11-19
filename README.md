# Is There a CVE Today?

A daily check for newly published High and Critical security vulnerabilities, grouped by technology. Each entry shows the affected software, severity, and a link to its CVE record.

[Website](https://isthereacvetoday.com) 

## What counts?

- YES means at least one CVE first published today has a CVSS v3 or v4 base score of 7.0 or higher. High starts at 7.0; Critical starts at 9.0.
- NO means none qualified in the last successful check. Lower-severity and unscored CVEs do not affect the answer.
- Today means the current UTC day, based on the CVE Program's original publication date.

Missing data never means NO. The page shows CHECKING before the first successful refresh of the day, UNKNOWN if stored data cannot be read, and a warning when the current day's result is stale.

## Data and limitations

The site checks [CVE Program](https://www.cve.org/) records through [CIRCL Vulnerability Lookup](https://vulnerability.circl.lu/) every 30 minutes and enriches them with [NVD](https://nvd.nist.gov/) data. Records are matched by CVE ID and counted once. Rejected records are excluded, and the highest available valid CVSS v3/v4 base score determines severity.

Feeds and scores can arrive late. Counts reflect the available data at the last successful check, and technology categories are best-effort rules. CVEs scored after their publication day do not appear on a later day's page. This is a daily overview, not a security monitoring service or a guarantee that your software is safe.

Built with TypeScript on Cloudflare Workers and KV. Pages are server-rendered HTML and CSS, with no client-side JavaScript, analytics, external fonts, or runtime packages.

## Contributing

Bug reports, category corrections, documentation fixes, and pull requests are welcome. [Open an issue](https://github.com/gsilvapt/isthereacvetoday.com/issues) or read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup and checks. Local development needs Node.js and pnpm, but no Cloudflare account.

Maintained by [gsilvapt](https://github.com/gsilvapt). [Support the project](https://ko-fi.com/gsilvapt).

This product uses the NVD API but is not endorsed or certified by the NVD, nor any other company or service.
