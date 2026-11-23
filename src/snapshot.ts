import { CATEGORIES, classify } from "./classify";
import type { Cve, CvssScore, Snapshot, SnapshotView } from "./types";

export const SNAPSHOT_KEY = "today";
export const STALE_AFTER_MS = 90 * 60 * 1000;

export function buildSnapshot(cves: Cve[], now: Date, osv: Snapshot["osv"]): Snapshot {
  const snapshot: Snapshot = {
    date: now.toISOString().slice(0, 10),
    updatedAt: now.toISOString(),
    verdict: "NO",
    totals: { published: 0, critical: 0, high: 0, unscored: 0 },
    categories: CATEGORIES.map((category) => ({
      ...category, critical: 0, high: 0, maxScore: null, cves: [],
    })),
    osv,
  };
  const startOfDay = Date.parse(`${snapshot.date}T00:00:00.000Z`);
  const seen = new Set<string>();

  for (const cve of cves) {
    const publishedAt = Date.parse(cve.publishedAt);
    if (
      cve.vulnStatus?.toLowerCase() === "rejected" ||
      !Number.isFinite(publishedAt) || publishedAt < startOfDay || publishedAt > now.getTime() ||
      seen.has(cve.id)
    ) continue;

    seen.add(cve.id);
    snapshot.totals.published++;
    const score = highestScore(cve);
    if (!score) {
      snapshot.totals.unscored++;
      continue;
    }
    if (score.score < 7) continue;

    const severity = score.score >= 9 ? "CRITICAL" : "HIGH";
    const categoryId = classify(cve);
    const category = snapshot.categories.find((entry) => entry.id === categoryId)!;
    category.cves.push({
      id: cve.id,
      publishedAt: new Date(publishedAt).toISOString(),
      sources: cve.sources,
      severity,
      software: affectedSoftware(cve),
      ...score,
      summary: (cve.descriptions?.find((entry) => entry.lang === "en")?.value ?? "No English description available.")
        .replace(/\s+/g, " ").trim().slice(0, 600),
    });
    category.maxScore = Math.max(category.maxScore ?? 0, score.score);
    if (severity === "CRITICAL") {
      category.critical++;
      snapshot.totals.critical++;
    } else {
      category.high++;
      snapshot.totals.high++;
    }
  }

  for (const category of snapshot.categories) {
    category.cves.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  }
  if (snapshot.totals.critical + snapshot.totals.high > 0) snapshot.verdict = "YES";
  return snapshot;
}

export function getSnapshotView(snapshot: Snapshot | null, now: Date): SnapshotView {
  const date = now.toISOString().slice(0, 10);
  if (!snapshot || snapshot.date !== date) return { date, status: "pending", snapshot: null };
  const age = now.getTime() - Date.parse(snapshot.updatedAt);
  return { date, status: age >= STALE_AFTER_MS ? "stale" : "ready", snapshot };
}

export function highestScore(cve: Cve): CvssScore | null {
  let highest: CvssScore | null = null;
  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]) {
    for (const metric of cve.metrics?.[key] ?? []) {
      const score = metric.cvssData?.baseScore;
      const version = metric.cvssData?.version;
      if (
        typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 10 &&
        typeof version === "string" && ["4.0", "3.1", "3.0"].includes(version) &&
        (!highest || score > highest.score)
      ) {
        highest = { score, version, source: metric.source ?? cve.sourceIdentifier ?? "Unknown" };
      }
    }
  }
  return highest;
}

function affectedSoftware(cve: Cve): string[] {
  const software: { product: string; packageName: string }[] = [];
  const cpes: string[] = [];
  const unspecified = /^(?:n\/?a|unknown|unspecified|not specified|not available|\*|-)$/i;

  for (const affected of cve.affected ?? []) {
    for (const entry of affected.affectedData ?? []) {
      const product = entry.product?.replace(/\s+/g, " ").trim() ?? "";
      const packageName = entry.packageName?.trim() ?? "";
      const validProduct = product && !unspecified.test(product) ? product : "";
      const validPackage = packageName && !unspecified.test(packageName) ? packageName : "";
      cpes.push(...(entry.cpes ?? []));
      if (!validProduct && !validPackage) continue;
      const existing = software.find((item) =>
        (validPackage && item.packageName.toLowerCase() === validPackage.toLowerCase()) ||
        (validProduct && item.product.toLowerCase() === validProduct.toLowerCase() && (!validPackage || !item.packageName)) ||
        // OSV supplies bare package names, which often repeat a CNA product name.
        (!validProduct && !item.packageName && item.product.toLowerCase() === validPackage.toLowerCase()),
      );
      if (existing) {
        existing.product ||= validProduct;
        existing.packageName ||= validPackage;
      } else {
        software.push({ product: validProduct, packageName: validPackage });
      }
    }
  }
  if (software.length) {
    return software.map(({ product, packageName }) =>
      product && packageName && product.toLowerCase() !== packageName.toLowerCase()
        ? `${product} (${packageName})`
        : product || packageName,
    );
  }

  const names = new Map<string, string>();
  for (const configuration of cve.configurations ?? []) {
    for (const node of configuration.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        if (match.vulnerable) cpes.push(match.criteria);
      }
    }
  }
  for (const cpe of cpes) {
    const product = cpe.split(":")[cpe.startsWith("cpe:2.3:") ? 4 : 3]?.replaceAll("_", " ").trim();
    if (product && !unspecified.test(product)) names.set(product.toLowerCase(), product);
  }
  return [...names.values()];
}
