import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import type { Unstable_RawConfig } from "wrangler";

const require = createRequire(import.meta.url);
const { experimental_readRawConfig } = require("wrangler") as typeof import("wrangler");

type Environment = Record<string, string | undefined>;
type WranglerRunner = (args: string[], environment: Environment) => Promise<number>;

export async function deploy(
  environment: Environment = process.env,
  dryRun = false,
  runWrangler: WranglerRunner = executeWrangler,
): Promise<void> {
  const { rawConfig } = experimental_readRawConfig({ config: "wrangler.jsonc" });
  const config = productionConfig(rawConfig, environment);
  const token = environment.CLOUDFLARE_API_TOKEN?.trim();
  const inCI = environment.GITHUB_ACTIONS === "true" || ["true", "1"].includes(environment.CI ?? "");
  if (inCI && !token) {
    throw new Error("CLOUDFLARE_API_TOKEN is required in CI.");
  }

  const childEnvironment = { ...environment };
  if (token) childEnvironment.CLOUDFLARE_API_TOKEN = token;
  else delete childEnvironment.CLOUDFLARE_API_TOKEN;
  const nvdKey = environment.NVD_API_KEY?.trim();
  if (environment.GITHUB_ACTIONS === "true") {
    for (const value of [config.account_id, ...config.kv_namespaces!.map((namespace) => namespace.id), token, nvdKey]) {
      if (!value) continue;
      const escaped = value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
      console.log(`::add-mask::${escaped}`);
    }
  }

  // Keep generated files beside the base config so relative module paths stay valid.
  const prefix = resolve(`.wrangler.production-${randomUUID()}`);
  const configPath = `${prefix}.jsonc`;
  const files: string[] = [];
  try {
    await writeFile(configPath, JSON.stringify(config, null, 2), { mode: 0o600, flag: "wx" });
    files.push(configPath);
    const args = ["deploy", "--config", configPath, "--strict"];
    if (dryRun) args.push("--dry-run");

    if (nvdKey) {
      const secretsPath = `${prefix}.secrets.json`;
      await writeFile(secretsPath, JSON.stringify({ NVD_API_KEY: nvdKey }), { mode: 0o600, flag: "wx" });
      files.push(secretsPath);
      args.push("--secrets-file", secretsPath);
    }

    const exitCode = await runWrangler(args, childEnvironment);
    if (exitCode !== 0) throw new Error(`Wrangler deployment failed with exit code ${exitCode}.`);
  } finally {
    await Promise.all(files.map((file) => rm(file, { force: true })));
  }
}

export function productionConfig(base: Unstable_RawConfig, environment: Environment): Unstable_RawConfig {
  const accountId = requiredId(environment, "CLOUDFLARE_ACCOUNT_ID");
  const namespaceId = requiredId(environment, "CLOUDFLARE_KV_NAMESPACE_ID");
  if (!base.kv_namespaces?.some((namespace) => namespace.binding === "CVE_STATUS")) {
    throw new Error("wrangler.jsonc must declare the CVE_STATUS KV binding.");
  }

  return {
    ...base,
    account_id: accountId,
    workers_dev: false,
    preview_urls: false,
    kv_namespaces: base.kv_namespaces.map((namespace) => {
      if (namespace.binding === "CVE_STATUS") return { ...namespace, id: namespaceId };
      if (!namespace.id) throw new Error(`Missing deployment ID for KV binding ${namespace.binding}.`);
      return { ...namespace };
    }),
    routes: base.routes?.map((route) => typeof route === "object" && route.custom_domain
      ? { ...route, previews_enabled: false }
      : route),
  };
}

function requiredId(environment: Environment, name: string): string {
  const value = environment[name]?.trim();
  if (!value || !/^[a-f0-9]{32}$/i.test(value)) {
    throw new Error(`${name} must be set to a 32-character hexadecimal ID.`);
  }
  return value.toLowerCase();
}

async function executeWrangler(args: string[], environment: Environment): Promise<number> {
  const cli = join(dirname(require.resolve("wrangler/package.json")), "bin", "wrangler.js");
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: "inherit", env: environment });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) reject(new Error(`Wrangler terminated with signal ${signal}.`));
      else resolve(code ?? 1);
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.some((arg) => arg !== "--dry-run")) throw new Error("Only --dry-run is supported.");
    await deploy(process.env, args.includes("--dry-run"));
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Deployment failed.");
    process.exitCode = 1;
  }
}
