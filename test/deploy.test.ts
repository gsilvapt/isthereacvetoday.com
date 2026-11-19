import { readFile, stat } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { deploy, productionConfig } from "../scripts/deploy";

const base = {
  name: "example-worker",
  main: "src/index.ts",
  workers_dev: false,
  preview_urls: false,
  routes: [{ pattern: "example.com", custom_domain: true }],
  kv_namespaces: [{ binding: "CVE_STATUS" }],
  triggers: { crons: ["*/30 * * * *"] },
};

const environment = {
  CLOUDFLARE_ACCOUNT_ID: "a".repeat(32),
  CLOUDFLARE_KV_NAMESPACE_ID: "b".repeat(32),
};

describe("productionConfig", () => {
  it("injects deployment metadata without changing the public config", () => {
    const config = productionConfig(base, environment);
    expect(config.account_id).toBe(environment.CLOUDFLARE_ACCOUNT_ID);
    expect(config.kv_namespaces).toEqual([{ binding: "CVE_STATUS", id: environment.CLOUDFLARE_KV_NAMESPACE_ID }]);
    expect(config.main).toBe("src/index.ts");
    expect(config.triggers).toEqual({ crons: ["*/30 * * * *"] });
    expect(base).not.toHaveProperty("account_id");
    expect(base.kv_namespaces).toEqual([{ binding: "CVE_STATUS" }]);
  });

  it.each(["CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_KV_NAMESPACE_ID"])("fails closed when %s is missing", (name) => {
    expect(() => productionConfig(base, { ...environment, [name]: undefined })).toThrow(name);
    expect(() => productionConfig(base, { ...environment, [name]: " " })).toThrow(name);
  });

  it.each(["short", "g".repeat(32), "a".repeat(33), "not-an-id"])("rejects invalid metadata %s", (value) => {
    expect(() => productionConfig(base, { ...environment, CLOUDFLARE_KV_NAMESPACE_ID: value })).toThrow("CLOUDFLARE_KV_NAMESPACE_ID");
  });

  it("does not fall back to an ID embedded in the base config", () => {
    const embedded = { ...base, kv_namespaces: [{ binding: "CVE_STATUS", id: "c".repeat(32) }] };
    expect(() => productionConfig(embedded, { ...environment, CLOUDFLARE_KV_NAMESPACE_ID: "" })).toThrow("CLOUDFLARE_KV_NAMESPACE_ID");
  });

  it("does not copy deployment tokens or runtime secrets into config", () => {
    const config = productionConfig(base, { ...environment, CLOUDFLARE_API_TOKEN: "test-token", NVD_API_KEY: "test-key" });
    expect(JSON.stringify(config)).not.toContain("test-token");
    expect(JSON.stringify(config)).not.toContain("test-key");
  });

  it("keeps all project worker/preview URLs disabled", () => {
    const config = productionConfig({ ...base, workers_dev: true, preview_urls: true, routes: [
      { pattern: "example.com", custom_domain: true, previews_enabled: true },
    ] }, environment);
    expect(config.workers_dev).toBe(false);
    expect(config.preview_urls).toBe(false);
    expect(config.routes?.[0]).toMatchObject({ previews_enabled: false });
  });

  it("requires the expected binding and refuses to auto-provision other namespaces", () => {
    expect(() => productionConfig({ ...base, kv_namespaces: [] }, environment)).toThrow("CVE_STATUS");
    expect(() => productionConfig({ ...base, kv_namespaces: [...base.kv_namespaces, { binding: "OTHER" }] }, environment)).toThrow("OTHER");
  });
});

describe("deploy", () => {
  it("generates a private config, forwards dry-run, and cleans up", async () => {
    let configPath = "";
    const run = vi.fn(async (args: string[]) => {
      configPath = args[args.indexOf("--config") + 1]!;
      expect(args).toContain("--dry-run");
      expect(args).toContain("--strict");
      expect(args).not.toContain("--secrets-file");
      const config = JSON.parse(await readFile(configPath, "utf8"));
      expect(config.account_id).toBe(environment.CLOUDFLARE_ACCOUNT_ID);
      expect(config.kv_namespaces[0].id).toBe(environment.CLOUDFLARE_KV_NAMESPACE_ID);
      expect((await stat(configPath)).mode & 0o777).toBe(0o600);
      return 0;
    });
    await deploy(environment, true, run);
    expect(run).toHaveBeenCalledOnce();
    await expect(readFile(configPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each([{ GITHUB_ACTIONS: "true" }, { CI: "true" }, { CI: "1" }])("requires a token in CI before invoking Wrangler: %j", async (ci) => {
    const run = vi.fn();
    await expect(deploy({ ...environment, ...ci }, false, run)).rejects.toThrow("CLOUDFLARE_API_TOKEN");
    expect(run).not.toHaveBeenCalled();
  });

  it("masks normalized deployment values before invoking Wrangler on GitHub", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await deploy({
        ...environment,
        CLOUDFLARE_ACCOUNT_ID: "A".repeat(32),
        GITHUB_ACTIONS: "true",
        CLOUDFLARE_API_TOKEN: " test-token ",
        NVD_API_KEY: "test%key\nvalue",
      }, false, async () => {
        expect(log).toHaveBeenCalledWith(`::add-mask::${"a".repeat(32)}`);
        expect(log).toHaveBeenCalledWith(`::add-mask::${"b".repeat(32)}`);
        expect(log).toHaveBeenCalledWith("::add-mask::test-token");
        expect(log).toHaveBeenCalledWith("::add-mask::test%25key%0Avalue");
        return 0;
      });
    } finally {
      log.mockRestore();
    }
  });

  it("leaves existing runtime secrets alone when no NVD key is supplied", async () => {
    const run = vi.fn(async (args: string[], childEnvironment: Record<string, string | undefined>) => {
      expect(args).not.toContain("--secrets-file");
      expect(childEnvironment).not.toHaveProperty("CLOUDFLARE_API_TOKEN");
      return 0;
    });
    await deploy({ ...environment, NVD_API_KEY: " ", CLOUDFLARE_API_TOKEN: "" }, false, run);
  });

  it("uploads an optional NVD key through a separate private file and removes it on failure", async () => {
    let configPath = "";
    let secretsPath = "";
    const run = vi.fn(async (args: string[], childEnvironment: Record<string, string | undefined>) => {
      configPath = args[args.indexOf("--config") + 1]!;
      secretsPath = args[args.indexOf("--secrets-file") + 1]!;
      expect(JSON.parse(await readFile(secretsPath, "utf8"))).toEqual({ NVD_API_KEY: "test-key" });
      expect((await stat(secretsPath)).mode & 0o777).toBe(0o600);
      expect(await readFile(configPath, "utf8")).not.toContain("test-key");
      expect(childEnvironment.CLOUDFLARE_API_TOKEN).toBe("test-token");
      return 1;
    });
    await expect(deploy({ ...environment, CI: "true", CLOUDFLARE_API_TOKEN: "test-token", NVD_API_KEY: "test-key" }, false, run))
      .rejects.toThrow("exit code 1");
    await expect(readFile(configPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(secretsPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("cleans up when the Wrangler process cannot start", async () => {
    let configPath = "";
    await expect(deploy(environment, false, async (args) => {
      configPath = args[args.indexOf("--config") + 1]!;
      throw new Error("spawn failed");
    })).rejects.toThrow("spawn failed");
    await expect(readFile(configPath)).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("workflow contract", () => {
  it("keeps checks source-only and deployment restricted to a checked main push", async () => {
    const workflow = await readFile(".github/workflows/deploy.yml", "utf8");
    expect(workflow.match(/paths: \['src\/\*\*'\]/g)).toHaveLength(2);
    expect(workflow).not.toMatch(/pull_request_target:|workflow_dispatch:|schedule:/);
    expect(workflow).toContain("needs: check");
    expect(workflow).toContain("github.event_name == 'push' && github.ref == 'refs/heads/main'");
    expect(workflow).toContain("contents: read");
    expect(workflow).toContain("cancel-in-progress: false");
    expect(workflow).toContain("run: pnpm run deploy");
  });

  it("does not embed account or namespace identifiers in tracked configuration", async () => {
    const config = await readFile("wrangler.jsonc", "utf8");
    expect(config).not.toMatch(/"account_id"|"id"\s*:/);
  });
});
