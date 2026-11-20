# Is There a CVE Today?

A daily check for newly published High and Critical security vulnerabilities, grouped by technology. Each entry shows the affected software, severity, and a link to its CVE record.

[Website](https://isthereacvetoday.com) 

## API and RSS

- [JSON snapshot](https://isthereacvetoday.com/api/today.json)
- [RSS 2.0 feed](https://isthereacvetoday.com/api/today.rss)

Subscribe to the RSS URL in any feed reader. Each High or Critical CVE has a stable GUID based on its CVE ID. The feed contains the current UTC day's entries only, uses the same snapshot as the JSON API, and returns HTTP 503 if today's data is not available. Same-day stale data remains visible and is labeled in the feed description.

## What counts?

- YES means at least one CVE first published today has a CVSS v3 or v4 base score of 7.0 or higher. High starts at 7.0; Critical starts at 9.0.
- NO means none qualified in the last successful check. Lower-severity and unscored CVEs do not affect the answer.
- Today means the current UTC day, based on the CVE Program's original publication date.

Missing data never means NO. The page shows CHECKING before the first successful refresh of the day, UNKNOWN if stored data cannot be read, and a warning when the current day's result is stale.

## Data and limitations

The site checks [CVE Program](https://www.cve.org/) records through [CIRCL Vulnerability Lookup](https://vulnerability.circl.lu/) every 30 minutes and enriches them with [NVD](https://nvd.nist.gov/) data. Records are matched by CVE ID and counted once. Rejected records are excluded, and the highest available valid CVSS v3/v4 base score determines severity.

[OSV](https://osv.dev/) adds affected package names to CVEs published today, matched by the CVE ID listed as an advisory alias. Only package-registry ecosystems such as npm, PyPI, Maven, Go, and crates.io are used. OSV never adds CVEs or changes the totals or the YES/NO answer, but its package names can move a CVE into the Open-Source Libraries category.

The site reads OSV's change list of recently modified advisories, starting one hour before today's UTC midnight. Advisories last changed before then are not fetched, so their package names are missing. The data can also lag or be incomplete. The page notes this, and the API reports it in the `osv` field. `osv.complete` is true when every package-registry change-list entry from one hour before today's UTC midnight up to the last successful check was processed. `osv.through` is the newest processed change-list timestamp, or null if none was processed yet.

The OSV data used here comes from these advisory databases, under their licenses. Only CVE aliases and affected package names are used. See [OSV data sources](https://google.github.io/osv.dev/data/) for details.

- [GitHub Advisory Database](https://github.com/github/advisory-database) ([CC BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md))
- [PyPI Advisory Database](https://github.com/pypa/advisory-database) ([CC BY 4.0](https://github.com/pypa/advisory-database/blob/main/LICENSE))
- [Go Vulnerability Database](https://github.com/golang/vulndb) ([CC BY 4.0](https://github.com/golang/vulndb#license))
- [Erlang Ecosystem Foundation CNA](https://cna.erlef.org/) ([CC BY 4.0](https://cna.erlef.org/data-licensing/))
- [Julia Security Advisories](https://github.com/JuliaLang/SecurityAdvisories.jl) ([CC BY 4.0](https://github.com/JuliaLang/SecurityAdvisories.jl/blob/main/LICENSE.md))
- [RustSec Advisory Database](https://github.com/RustSec/advisory-db) ([CC0 1.0](https://github.com/rustsec/advisory-db/blob/main/LICENSE.txt))
- [Haskell Security Advisories](https://github.com/haskell/security-advisories) ([CC0 1.0](https://github.com/haskell/security-advisories/blob/main/LICENSE.txt))
- [OCaml opam security advisories](https://github.com/ocaml/security-advisories) ([CC0 1.0](https://github.com/ocaml/security-advisories/blob/main/LICENSE.txt))
- [R Consortium Advisory Database](https://github.com/RConsortium/r-advisory-database) ([Apache 2.0](https://github.com/RConsortium/r-advisory-database/blob/main/LICENSE))
- [Drupal Advisory Database](https://github.com/DrupalSecurityTeam/drupal-advisory-database) ([MIT](https://github.com/DrupalSecurityTeam/drupal-advisory-database/blob/main/LICENSE))

Feeds and scores can arrive late. Counts reflect the available data at the last successful check, and technology categories are best-effort rules. CVEs scored after their publication day do not appear on a later day's page. This is a daily overview, not a security monitoring service or a guarantee that your software is safe.

Built with TypeScript on Cloudflare Workers and KV. Pages are server-rendered HTML and CSS, with no client-side JavaScript, analytics, external fonts, or runtime packages.

## Contributing

Bug reports, category corrections, documentation fixes, and pull requests are welcome. [Open an issue](https://github.com/gsilvapt/isthereacvetoday.com/issues) or read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup and checks. Local development needs Node.js and pnpm, but no Cloudflare account.

Maintainer deployment instructions are in [Deploying from GitHub](docs/deployment.md).

Maintained by [gsilvapt](https://github.com/gsilvapt). [Support the project](https://ko-fi.com/gsilvapt).

This product uses the NVD API but is not endorsed or certified by the NVD, nor any other company or service.
