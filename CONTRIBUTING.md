# Contributing

This is a small project built to stay within Cloudflare Workers Free. Keep changes focused, dependencies few, and upstream requests bounded.

## Bugs and feature requests

Open an issue in the [project repository](https://github.com/gsilvapt/isthereacvetoday.com).

For a bug, include what happened, what you expected, and how to reproduce it. For incorrect CVE results, include the CVE ID, the date you checked, and links to the source records. Screenshots help with layout problems. Never attach API keys, tokens, or local credential files.

Discuss new data sources, dependencies, or larger changes before building them. Data published by an upstream source can be delayed or incorrect. Distinguish a source-data problem from a dashboard bug.

## Development

Fork the repository and create a focused topic branch. Use Node.js 22.12+ and pnpm 12.5.1.

```sh
pnpm install
pnpm dev
```

Wrangler prints the local URL. KV is emulated in `.wrangler/state/`; development does not need Cloudflare credentials or a deployment. The page shows CHECKING until the first successful data refresh.

Wrangler does not run cron automatically during development. To populate local KV, request the scheduled-event endpoint at the URL Wrangler printed. For example, if it prints `http://localhost:8787`:

```sh
curl 'http://localhost:8787/__scheduled?cron=*/30+*+*+*+*'
```

Reload the page after the request finishes. This fetches live CVE Program and NVD data, so avoid repeatedly triggering it. The endpoint is local-only and is not exposed by the deployed application. Local snapshots persist between runs and expire 24 hours after the last successful refresh.

An NVD API key is optional. To use one, request a [free key](https://nvd.nist.gov/developers/request-an-api-key), copy `.dev.vars.example` to `.dev.vars`, and set `NVD_API_KEY` there. Never commit `.dev.vars`.

## Data rules

Preserve these rules when changing ingestion, aggregation, or presentation:

- Determine the publication day from CVE Program `cveMetadata.datePublished`. Do not substitute reservation, disclosure, update, NVD ingestion, or advisory dates. Use UTC internally.
- Join and count by canonical CVE ID. Multiple sources or affected packages must not create duplicate CVE counts. Separate CVE IDs remain separate even when one advisory covers both.
- Exclude rejected records. Do not guess publication dates or publish incomplete pagination as a complete result.
- Use valid CVSS v3/v4 base scores. Preserve the selected score's source. Missing scores remain unscored, not zero. EPSS is not a CVSS severity score.
- Keep affected software names visible, with one advisory link per card. Escape all upstream text before rendering HTML.
- Keep browser requests independent of upstream APIs. Only the scheduled refresh fetches source data. Failed refreshes retain the last good snapshot without extending its 24-hour KV lifetime.

New feeds need explicit field precedence, alias handling, attribution, licensing review, and failure behavior. Overlapping sources must not inflate CVE counts.

## Tests and resource limits

Before submitting a pull request, run:

```sh
pnpm test
pnpm typecheck
pnpm build
```

`pnpm build` is a dry run, not a deployment. Add regression tests for behavior changes. Mock network calls and storage in unit tests. Keep fixtures small, use public data, and document their source. For UI changes, check narrow and wide viewports and include screenshots in the pull request.

Use `pnpm test:watch` while working. The existing fixtures are reduced public records fetched on 2026-11-19:

- `test/fixtures/nvd-sample.json` contains five NVD records from the previous UTC day. Unused fields are omitted and the last two descriptions shortened. `totalResults` is the upstream count, not the fixture length. Its NVD dates do not establish CVE publication dates.
- `test/fixtures/cve-photo-album.json` contains the CVE Program record for `CVE-2026-129048`, whose reservation, disclosure, and publication dates differ. Publication-day tests use only `cveMetadata.datePublished`.

Keep the 30-minute schedule, rate-limit spacing, bounded pagination, and 24-hour KV expiration intact unless the change explicitly revisits them. Page caching is shorter than KV retention and must not serve yesterday's verdict today.

The current clients cap pagination at 20 requests per feed. Changes that increase parsing, rendering, or upstream work need measurements on Cloudflare before deployment. Local response durations and successful builds do not prove production CPU compliance. Check the current [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) and [KV limits](https://developers.cloudflare.com/kv/platform/limits/) when changing resource use.

## GitHub deployments

Source changes under `src/` run checks on pull requests and deploy after a push to `main`. Changes outside `src/` do not trigger the workflow. Production deployment requires GitHub environment secrets and uses a temporary private configuration; account and namespace IDs do not belong in the tracked config. See [deployment setup](docs/deployment.md).

## Pull requests

Target `main`. Explain the change, why it is needed, and how you tested it. Link related issues. Keep unrelated cleanup separate and use concise [Conventional Commit](https://www.conventionalcommits.org/) messages, such as `fix: exclude previously published CVEs`.

Do not include `.dev.vars`, `.env` files, local KV data, logs, `node_modules/`, or generated `dist/` files. 

For a suspected security flaw in this website, do not post credentials or unpublished exploit details in a public issue. Ask the maintainer for a private reporting channel first.
