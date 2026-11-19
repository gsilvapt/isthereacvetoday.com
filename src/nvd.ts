import type { NvdCve } from "./types";

const API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE = 2000;
// Leave room for the CVE Program feed in the same scheduled invocation.
const MAX_PAGES = 20;

export async function fetchTodaysCves(now: Date, apiKey?: string): Promise<NvdCve[]> {
  const url = new URL(API_URL);
  url.searchParams.set("pubStartDate", `${now.toISOString().slice(0, 10)}T00:00:00.000Z`);
  url.searchParams.set("pubEndDate", now.toISOString());
  url.searchParams.set("resultsPerPage", String(PAGE_SIZE));
  url.searchParams.set("noRejected", "");

  const cves = new Map<string, NvdCve>();
  const headers = apiKey ? { apiKey } : undefined;
  let startIndex = 0;

  for (let page = 0; page < MAX_PAGES; page++) {
    if (page > 0) {
      await new Promise((resolve) => setTimeout(resolve, apiKey ? 650 : 6500));
    }

    url.searchParams.set("startIndex", String(startIndex));
    const response = await fetch(url, {
      headers,
      redirect: "manual",
      signal: AbortSignal.timeout(25_000),
    });

    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`NVD request failed (HTTP ${response.status})`);
    }

    const data: unknown = await response.json();
    assertNvdPage(data, startIndex);
    for (const { cve } of data.vulnerabilities) {
      cves.set(cve.id, cve);
    }

    startIndex += data.vulnerabilities.length;
    if (startIndex >= data.totalResults) return [...cves.values()];
    if (data.vulnerabilities.length === 0) {
      throw new Error("NVD returned an incomplete page");
    }
  }

  // Never publish a partial day as a complete result if upstream pagination changes.
  throw new Error("NVD pagination exceeded the free-tier subrequest budget");
}

function assertNvdPage(data: unknown, startIndex: number): asserts data is {
  startIndex: number;
  totalResults: number;
  vulnerabilities: { cve: NvdCve }[];
} {
  if (
    !isObject(data) ||
    data.startIndex !== startIndex ||
    !Number.isSafeInteger(data.totalResults) ||
    (data.totalResults as number) < 0 ||
    !Array.isArray(data.vulnerabilities)
  ) {
    throw new Error("NVD returned an invalid response");
  }

  for (const entry of data.vulnerabilities) {
    if (
      !isObject(entry) ||
      !isObject(entry.cve) ||
      typeof entry.cve.id !== "string" ||
      !/^CVE-\d{4}-\d{4,}$/.test(entry.cve.id) ||
      typeof entry.cve.published !== "string" ||
      !Number.isFinite(Date.parse(`${entry.cve.published.replace(/Z$/, "")}Z`))
    ) {
      throw new Error("NVD returned an invalid CVE record");
    }
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
