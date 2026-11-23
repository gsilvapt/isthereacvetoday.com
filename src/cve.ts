import type { Cve, CveRecord, NvdCve, OsvRecord } from "./types";

const API_URL = "https://vulnerability.circl.lu/api/vulnerability/";
const PAGE_SIZE = 100;
const MAX_PAGES = 20;

export async function fetchCveRecords(now: Date): Promise<CveRecord[]> {
  const url = new URL(API_URL);
  url.searchParams.set("source", "cvelistv5");
  url.searchParams.set("since", `${now.toISOString().slice(0, 10)}T00:00:00Z`);
  url.searchParams.set("date_sort", "published");
  url.searchParams.set("sort_order", "desc");
  url.searchParams.set("per_page", String(PAGE_SIZE));
  const records: CveRecord[] = [];

  for (let page = 1; page <= MAX_PAGES; page++) {
    // CIRCL's anonymous API allows 20 requests per minute.
    if (page > 1) await new Promise((resolve) => setTimeout(resolve, 3100));
    url.searchParams.set("page", String(page));
    const response = await fetch(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "IsThereACVEToday/0.1 (+https://github.com/gsilvapt)",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(25_000),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`CVE feed request failed (HTTP ${response.status})`);
    }

    const data: unknown = await response.json();
    if (!Array.isArray(data) || data.length > PAGE_SIZE) {
      throw new Error("CVE feed returned an invalid page");
    }
    for (const record of data) {
      assertCveRecord(record);
      records.push(record);
    }
    if (data.length < PAGE_SIZE) return records;
  }

  throw new Error("CVE feed pagination exceeded the free-tier subrequest budget");
}

export function mergeCveRecords(records: CveRecord[], nvdCves: NvdCve[], osvRecords: OsvRecord[]): Cve[] {
  const nvdById = new Map(nvdCves.map((cve) => [cve.id.toUpperCase(), cve]));
  const osvPackagesById = new Map<string, { packageName: string }[]>();
  for (const record of osvRecords) {
    for (const id of record.cves) {
      osvPackagesById.set(id, [...(osvPackagesById.get(id) ?? []), ...record.packages.map(({ name }) => ({ packageName: name }))]);
    }
  }
  const latestRecords = new Map<string, { record: CveRecord; revisedAt: number }>();
  for (const record of records) {
    const id = record.cveMetadata.cveId.toUpperCase();
    const revisedAt = parseTimestamp(record.cveMetadata.dateUpdated ?? record.cveMetadata.datePublished);
    if (!Number.isFinite(revisedAt)) throw new Error("CVE feed record is missing a usable revision date");
    const previous = latestRecords.get(id);
    if (previous && revisedAt === previous.revisedAt && record.cveMetadata.state !== previous.record.cveMetadata.state) {
      throw new Error("CVE feed returned conflicting states for the same revision");
    }
    if (!previous || revisedAt >= previous.revisedAt) {
      latestRecords.set(id, { record, revisedAt });
    }
  }

  const cves: Cve[] = [];
  for (const [id, { record }] of latestRecords) {
    const metadata = record.cveMetadata;
    if (metadata.state === "REJECTED") continue;
    const nvd = nvdById.get(id);
    const cna = record.containers!.cna!;
    const metrics: NonNullable<Cve["metrics"]> = {};
    for (const [key, entries] of Object.entries(nvd?.metrics ?? {})) {
      metrics[key] = [...entries];
    }
    for (const container of [cna, ...(record.containers?.adp ?? [])]) {
      const source = container.providerMetadata?.orgId ?? container.providerMetadata?.shortName ?? metadata.assignerOrgId;
      for (const metric of container.metrics ?? []) {
        for (const [rawKey, key] of [
          ["cvssV4_0", "cvssMetricV40"],
          ["cvssV3_1", "cvssMetricV31"],
          ["cvssV3_0", "cvssMetricV30"],
        ] as const) {
          const cvssData = metric[rawKey];
          if (cvssData) (metrics[key] ??= []).push({ source, cvssData });
        }
      }
    }

    const sources: Cve["sources"] = nvd ? ["cve", "nvd"] : ["cve"];
    const affected: NonNullable<Cve["affected"]> = [{ affectedData: cna.affected }, ...(nvd?.affected ?? [])];
    // Advisories from several databases often alias the same CVE. The software labels merge repeated names.
    const osvPackages = osvPackagesById.get(id) ?? [];
    if (osvPackages.length) {
      sources.push("osv");
      affected.push({ affectedData: osvPackages });
    }

    cves.push({
      id,
      publishedAt: new Date(parseTimestamp(metadata.datePublished)).toISOString(),
      sources,
      sourceIdentifier: nvd?.sourceIdentifier ?? cna.providerMetadata?.orgId ?? metadata.assignerOrgId,
      vulnStatus: metadata.state,
      descriptions: cna.descriptions?.some((entry) => entry.lang === "en") ? cna.descriptions : nvd?.descriptions,
      affected,
      configurations: nvd?.configurations,
      metrics,
    });
  }
  return cves;
}

function assertCveRecord(value: unknown): asserts value is CveRecord {
  if (!isObject(value) || !isObject(value.cveMetadata)) {
    throw new Error("CVE feed returned an invalid record");
  }
  const metadata = value.cveMetadata;
  if (typeof metadata.cveId !== "string" || !/^CVE-\d{4}-\d{4,}$/i.test(metadata.cveId) ||
    (metadata.state !== "PUBLISHED" && metadata.state !== "REJECTED") ||
    !Number.isFinite(parseTimestamp(metadata.dateUpdated ?? metadata.datePublished)) ||
    (metadata.dateUpdated !== undefined && !Number.isFinite(parseTimestamp(metadata.dateUpdated)))) {
    throw new Error("CVE feed returned invalid record metadata");
  }
  if (metadata.state === "PUBLISHED" && (
    !Number.isFinite(parseTimestamp(metadata.datePublished)) ||
    !isObject(value.containers) || !isObject(value.containers.cna)
  )) {
    throw new Error("CVE feed record is missing its original publication date or CNA data");
  }
}

function parseTimestamp(value: unknown): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T/.test(value)) return Number.NaN;
  return Date.parse(/(?:z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
