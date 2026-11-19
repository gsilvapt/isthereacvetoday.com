# Deploying from GitHub

The source workflow checks pull requests that change `src/**`. After the checks pass, source changes pushed to `main` deploy to production.

Documentation, tests, deployment tooling, workflow files, configuration, and dependency-only changes do not trigger this workflow. A push containing both source and non-source changes does trigger it. There is no manual or scheduled deployment trigger. Configuration or secret changes take effect on the next source-triggered deployment, or through an explicit local deployment.

The workflow does not change ingestion: the Worker still refreshes data on its 30-minute Cloudflare cron.

## GitHub setup

Create a GitHub environment named `production` under repository **Settings > Environments**. Restrict deployment branches to `main`. Add any approval requirements you want before a deployment can proceed.

Add these environment secrets, or use repository Actions secrets with the same names:

| Secret | Required | Purpose |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | Yes | Authenticate non-interactive Worker deployments. |
| `CLOUDFLARE_ACCOUNT_ID` | Yes | Select the account that owns the Worker and KV namespace. |
| `CLOUDFLARE_KV_NAMESPACE_ID` | Yes | Bind `CVE_STATUS` to the existing production namespace. |
| `NVD_API_KEY` | No | Add or update the Worker's NVD API key. Omit it to preserve the existing Worker secret. |

Create a dedicated Cloudflare API token using the **Edit Cloudflare Workers** template. Restrict it to the intended account and zone. It needs to deploy the Worker, use its KV binding, and manage its custom-domain route. Do not use a global API key or copy a local Wrangler OAuth token into GitHub.

For environment secrets, the GitHub CLI can prompt for each value without placing it in shell history:

```sh
gh secret set CLOUDFLARE_API_TOKEN --env production
gh secret set CLOUDFLARE_ACCOUNT_ID --env production
gh secret set CLOUDFLARE_KV_NAMESPACE_ID --env production
```

Set `NVD_API_KEY` the same way only if you want deployments to manage it. Removing the GitHub secret does not delete an existing NVD key from Cloudflare. Delete that Worker secret explicitly if needed.

Credentials are supplied only to the deployment step. Pull-request checks never receive Cloudflare secrets, and pull requests cannot deploy. Deployments use a read-only GitHub token, disable persisted checkout credentials, pin actions to commit SHAs, and serialize workflows for each branch so a slower check run cannot deploy over a newer run.

## Private deployment configuration

The tracked `wrangler.jsonc` contains the public application settings and a local-development KV binding, but no real account or namespace IDs.

`pnpm run deploy` reads the required IDs from environment variables and generates an ignored, temporary `.wrangler.production-*.jsonc` beside the base config. This preserves relative source paths and binds the existing namespace instead of provisioning a fresh one. Missing or malformed IDs fail before Wrangler runs.

The helper also keeps `workers.dev`, version URLs, and custom-domain previews disabled. Deployment IDs and keys are masked in GitHub logs, including normalized values. If an NVD key is supplied, it is written to a separate temporary JSON secrets file and passed to Wrangler's additive secret upload. Deployment files use owner-only permissions and are removed after success or failure. They are not uploaded as workflow artifacts or committed to Git.

Use `pnpm run deploy`, not a bare `wrangler deploy`, for production. The explicit `run` also avoids pnpm's built-in workspace deployment command. The generic development config intentionally does not identify production storage.

## Local deployment

Copy `.env.example` to `.env.production` and fill in the account and existing KV namespace IDs. The file is Git-ignored. Local deployments can use `pnpm exec wrangler login` instead of an API token. CI requires an API token and never uses the interactive login flow.

```sh
pnpm install
pnpm test
pnpm typecheck
pnpm build
pnpm run deploy --dry-run
```

After reviewing the dry run, run `pnpm run deploy` to publish. Existing process environment variables take precedence over `.env.production` values.

Tests and dry runs do not establish compliance with production CPU limits. Keep pagination, rate limits, the 30-minute ingestion schedule, and the 24-hour snapshot expiration intact when changing deployment settings.
