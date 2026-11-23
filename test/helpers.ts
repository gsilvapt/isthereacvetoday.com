import type { Cve, NvdCve, Snapshot } from "../src/types";

export const completeOsv: Snapshot["osv"] = { complete: true, through: "2026-11-19T08:30:00.000000000Z" };

export function cve(overrides: Partial<Cve> = {}): Cve {
  return {
    id: "CVE-2026-1000",
    publishedAt: "2026-11-19T08:00:00.000Z",
    sources: ["cve"],
    sourceIdentifier: "test@example.com",
    descriptions: [{ lang: "en", value: "An issue in an unknown product." }],
    metrics: { cvssMetricV31: [{ source: "test@example.com", cvssData: { version: "3.1", baseScore: 8.1 } }] },
    ...overrides,
  };
}

export function nvdCve(overrides: Partial<NvdCve> = {}): NvdCve {
  const { publishedAt: _publishedAt, sources: _sources, ...metadata } = cve();
  return {
    ...metadata,
    published: "2026-11-19T08:00:00.000",
    ...overrides,
  };
}
