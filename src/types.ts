export interface Env {
  CVE_STATUS: KVNamespace;
  NVD_API_KEY?: string;
}

export interface NvdCve {
  id: string;
  sourceIdentifier?: string;
  published: string;
  vulnStatus?: string;
  descriptions?: { lang: string; value: string }[];
  affected?: {
    affectedData?: { vendor?: string; product?: string; packageName?: string; cpes?: string[] }[];
  }[];
  metrics?: Record<string, {
    source?: string;
    cvssData?: { version?: string; baseScore?: number };
  }[]>;
  configurations?: {
    nodes?: {
      cpeMatch?: { vulnerable: boolean; criteria: string }[];
    }[];
  }[];
}

export interface Cve extends Omit<NvdCve, "published"> {
  publishedAt: string;
  sources: ("cve" | "nvd" | "osv")[];
}

export interface CveRecord {
  cveMetadata: {
    cveId: string;
    state: string;
    datePublished?: string;
    dateUpdated?: string;
    assignerOrgId?: string;
  };
  containers?: {
    cna?: CveContainer;
    adp?: CveContainer[];
  };
}

interface CveContainer {
  providerMetadata?: { orgId?: string; shortName?: string };
  descriptions?: NvdCve["descriptions"];
  affected?: NonNullable<NvdCve["affected"]>[number]["affectedData"];
  metrics?: Partial<Record<"cvssV4_0" | "cvssV3_1" | "cvssV3_0", {
    version?: string;
    baseScore?: number;
  }>>[];
}

export interface OsvRecord {
  id: string;
  modified: string;
  cves: string[];
  packages: { ecosystem: string; name: string }[];
}

export interface OsvState {
  date: string;
  cursor: string | null;
  gap: boolean;
  records: OsvRecord[];
}

export interface CvssScore {
  score: number;
  version: string;
  source: string;
}

export interface ListedCve extends CvssScore {
  id: string;
  publishedAt: string;
  sources: Cve["sources"];
  severity: "HIGH" | "CRITICAL";
  software: string[];
  summary: string;
}

export interface CategorySnapshot {
  id: string;
  name: string;
  critical: number;
  high: number;
  maxScore: number | null;
  cves: ListedCve[];
}

export interface Snapshot {
  date: string;
  updatedAt: string;
  verdict: "YES" | "NO";
  totals: { published: number; critical: number; high: number; unscored: number };
  categories: CategorySnapshot[];
  // Absent from snapshots stored before OSV enrichment existed.
  osv?: { complete: boolean; through: string | null };
}

export interface SnapshotView {
  date: string;
  status: "ready" | "stale" | "pending" | "unavailable";
  snapshot: Snapshot | null;
}
