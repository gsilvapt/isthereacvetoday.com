# Project guide

This is a TypeScript Cloudflare Worker that reports whether any High or Critical CVEs were first published today, in UTC. It serves HTML and a JSON snapshot from KV. Read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup and contribution rules.

## Code map

- `src/index.ts`: HTTP routes, security headers, edge caching, and scheduled refresh. `refreshSnapshot` fetches both feeds, merges records, builds a snapshot, and writes KV only after success.
- `src/cve.ts`: CVE Program records from CIRCL's `cvelistv5` mirror, validation, latest-revision deduplication, and NVD enrichment by uppercase CVE ID.
- `src/nvd.ts`: paginated NVD client with request timeouts and rate-limit spacing.
- `src/snapshot.ts`: CVSS selection, UTC-day filtering, totals, affected software labels, and freshness. The KV key is `today`.
- `src/classify.ts`: category definitions and ordered classification rules.
- `src/page.ts` and `src/styles.css`: escaped server-rendered HTML and inline CSS. Expandable lists use native `<details>` elements.
- `src/types.ts`: source record types, snapshots, freshness views, and Worker bindings.
- `test/`: Vitest tests matching the source modules. Reuse the record factories in `test/helpers.ts` and the public fixtures in `test/fixtures/`.
- `wrangler.jsonc`: Worker entry point, CSS text imports, the `CVE_STATUS` KV binding, and the `*/30 * * * *` cron schedule. `NVD_API_KEY` is an optional secret.
- `scripts/deploy.ts`: environment validation, temporary private deployment config, optional runtime secret upload, and cleanup. Use `pnpm run deploy` rather than a bare Wrangler deployment.
- `.github/workflows/deploy.yml`: checks for `src/**` changes and production deployment only after a checked push to `main`. Pull requests never receive deployment credentials.
- `docs/deployment.md`: required GitHub secrets and local deployment setup. Keep account and namespace identifiers in environment configuration, not tracked files.

## Data invariants

- Determine publication day only from CVE Program `cveMetadata.datePublished`. Normalize timestamps to UTC, exclude future records, and never substitute reservation, disclosure, revision, mirror-ingestion, or NVD dates.
- Count canonical uppercase CVE IDs once across sources and packages. Separate IDs stay separate. NVD-only records cannot establish CVE publication or enter the totals.
- Use the latest authoritative CVE revision and exclude rejections. Missing required dates, conflicting states at the same revision, invalid responses, or incomplete pagination must fail the refresh rather than publish a guessed or partial result.
- Select the highest valid CVSS 4.0, 3.1, or 3.0 base score across source metrics. Prefer the newer version on a tie and preserve score provenance. High is `>= 7` and `< 9`; Critical is `>= 9`. Missing or v2-only scores are unscored, not zero.
- YES requires at least one High or Critical record. A successfully fetched day with no qualifying records is NO. Missing data must never produce NO.
- Assign each listed CVE one category. Classification precedence is specialist publisher, affected product/vulnerable CPE, description, coarse CPE type, then Other. Generic vulnerability terms must not imply a product category.
- Preserve distinct affected package names, merge duplicate software labels, and fall back to vulnerable CPEs when names are absent. Show an explicit unknown-software label if no name is available. Keep one CVE Program record link per card and escape all upstream text.

## Storage and request behavior

- Only scheduled refreshes fetch upstream data. Visitor requests must not trigger refreshes or control upstream queries. The `/__scheduled` test endpoint belongs to local Wrangler, not the application's public routes.
- Replace the complete snapshot in one KV write with a 24-hour expiration. On failure, retain the previous value without extending its lifetime.
- Withhold prior-day snapshots. Same-day snapshots become stale after 90 minutes and remain visible with a warning.
- `GET /` serves HTML; `GET /api/today.json` serves the snapshot with `ready`, `stale`, `pending`, or `unavailable` status. Both support HEAD. The API returns HTTP 503 and a null verdict when no current result exists.
- Cache ready responses for at most five minutes, never past UTC midnight or the staleness threshold. Query strings do not create distinct cache keys. Pending, stale, and unavailable responses use `no-store`.
- Preserve bounded pagination, request timeouts, and rate-limit spacing. The project targets Workers Free. Local tests and builds do not establish production CPU compliance.

## Making changes

Use the Node.js and pnpm versions specified in `package.json`. Keep strict TypeScript, the dependency-free runtime, and the HTML/CSS-only interface. Follow existing modules and test helpers before introducing new abstractions or dependencies.

Run these checks for code changes:

```sh
pnpm test
pnpm typecheck
pnpm build
```

Tests mock network calls and storage. Add or extend regression tests for behavior changes. `pnpm build` is a Wrangler dry run, not a deployment. Do not deploy or change remote Cloudflare resources unless explicitly requested.

Keep the README focused on the public project and CONTRIBUTING focused on contributors. These files and this guide must contain only public project information, never credentials, account identifiers, private context, internal tracking, or session notes. Do not commit local state, logs, or generated output.
