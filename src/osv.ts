import type { OsvRecord, OsvState } from "./types";

export const OSV_STATE_KEY = "osv";
const BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";
// The full change list is about 160 MB. Its newest-first head covers recent changes, and reading
// stops at the scan bound, so typical runs decode only a few lines of this range.
const CHANGE_LIST_BYTES = 2 * 1024 * 1024;
// OSV can export a record minutes after its modified time, below a cursor that already passed it.
const LOOKBACK_MS = 60 * 60 * 1000;
// Each run makes one change-list read plus at most this many record fetches.
export const MAX_OSV_RECORDS = 9;
// Workers allow six open connections per request, and the CVE and NVD clients may hold two.
const CONCURRENT_RECORDS = 4;
// Package registries only, limited to sources published under CC-BY 4.0, CC0, MIT, or Apache 2.0.
const REGISTRY_ECOSYSTEMS = new Set([
  "crates.io", "CRAN", "GitHub Actions", "Go", "Hackage", "Hex", "Julia", "Maven",
  "npm", "NuGet", "opam", "Packagist", "Pub", "PyPI", "RubyGems", "SwiftURL",
]);

interface ChangeEntry {
  modified: string;
  ecosystem: string;
  id: string;
}

interface OsvSource {
  id: string;
  modified: string;
  withdrawn?: string;
  aliases?: string[];
  affected?: { package?: { ecosystem: string; name: string } }[];
}

// OSV only enriches the snapshot, so its failures keep the earlier state rather than failing the refresh.
export async function refreshOsv(kv: KVNamespace, now: Date): Promise<{
  state: OsvState;
  complete: boolean;
  updated: boolean;
}> {
  const date = now.toISOString().slice(0, 10);
  let state: OsvState;
  try {
    state = parseOsvState(await kv.get(OSV_STATE_KEY), date);
  } catch (error) {
    console.warn("OSV state read failed; publishing without OSV packages", error);
    return { state: parseOsvState(null, date), complete: false, updated: false };
  }

  try {
    const changes = await fetchOsvChanges(now, state.cursor, new Map(state.records.map(({ id, modified }) => [id, modified])));
    const records = new Map(state.records.map((record) => [record.id, record]));
    for (const record of changes.records) records.set(record.id, record);
    // Changes that fell out of the change-list head cannot be recovered later today.
    const gap = state.gap || changes.gap;
    return {
      state: { date, cursor: changes.cursor, gap, records: [...records.values()] },
      complete: !gap && !changes.partial,
      updated: true,
    };
  } catch (error) {
    console.warn("OSV refresh failed; keeping earlier OSV packages", error);
    return { state, complete: false, updated: false };
  }
}

export async function fetchOsvChanges(now: Date, cursor: string | null, known: ReadonlyMap<string, string>): Promise<{
  records: OsvRecord[];
  cursor: string | null;
  partial: boolean;
  gap: boolean;
}> {
  const cursorKey = cursor === null ? null : timestampKey(cursor);
  if (cursorKey === undefined) throw new Error("OSV cursor is invalid");
  // Starting before midnight also catches records changed shortly before it but exported after it.
  const midnight = `${now.toISOString().slice(0, 10)}T00:00:00.000000000Z`;
  const from = cursorKey !== null && cursorKey > midnight ? cursorKey : midnight;
  const after = `${new Date(Date.parse(`${from.slice(0, 19)}Z`) - LOOKBACK_MS).toISOString().slice(0, 19)}${from.slice(19)}`;
  const nowKey = timestampKey(now.toISOString())!;

  // GCS allows an hour of caching. A per-run query string keeps any cache from serving an older copy.
  const query = `?t=${now.getTime()}`;
  const { entries, gap } = await fetchChangeList(after, query);
  const visible = entries.filter((entry) => entry.modified <= nowKey);
  // Records with several ecosystems are stored once per ecosystem directory. Keep the newest copy.
  const ids = new Set<string>();
  const eligible: ChangeEntry[] = [];
  for (const entry of visible) {
    const knownModified = known.get(entry.id);
    // A known record's newer copy must replace it even from another directory, such as [EMPTY] once it lists
    // no packages. OpenSSF malicious-package reports (MAL-) carry no CVE aliases, so they would only use up the cap.
    if (ids.has(entry.id) ||
      (knownModified === undefined && (!REGISTRY_ECOSYSTEMS.has(entry.ecosystem) || entry.id.startsWith("MAL-")))) continue;
    ids.add(entry.id);
    if (knownModified === undefined || knownModified < entry.modified) eligible.push(entry);
  }
  eligible.reverse();

  const batch = eligible.slice(0, MAX_OSV_RECORDS);
  const records: OsvRecord[] = [];
  let failed: number | undefined;
  for (let start = 0; start < batch.length; start += CONCURRENT_RECORDS) {
    const results = await Promise.allSettled(batch.slice(start, start + CONCURRENT_RECORDS).map((entry) => fetchRecord(entry, query)));
    for (const [index, result] of results.entries()) {
      if (result.status === "fulfilled") {
        records.push(result.value);
      } else {
        failed ??= start + index;
        console.warn(`OSV record ${batch[start + index]!.id} failed; retrying next run`, result.reason);
      }
    }
  }

  // The cursor stops before the first unprocessed entry. The lookback re-scans the cursor's own timestamp,
  // so unprocessed entries sharing it are not skipped.
  const partial = failed !== undefined || eligible.length > batch.length;
  const newest = partial ? batch[(failed ?? batch.length) - 1]?.modified : visible[0]?.modified;
  return { records, cursor: newest && (cursorKey === null || newest > cursorKey) ? newest : cursorKey, partial, gap };
}

function parseOsvState(text: string | null, date: string): OsvState {
  if (text !== null) {
    try {
      const state: unknown = JSON.parse(text);
      assertOsvState(state);
      if (state.date === date) return state;
    } catch (error) {
      // Keeping an unreadable value would block OSV until it expires. Rescanning the day recovers
      // whatever the change-list head still covers, and reports a gap otherwise.
      console.warn("Discarding invalid OSV state", error);
    }
  }
  return { date, cursor: null, gap: false, records: [] };
}

async function fetchChangeList(after: string, query: string): Promise<{ entries: ChangeEntry[]; gap: boolean }> {
  const response = await fetch(`${BASE_URL}/modified_id.csv${query}`, {
    headers: { Range: `bytes=0-${CHANGE_LIST_BYTES - 1}` },
    redirect: "manual",
    signal: AbortSignal.timeout(25_000),
  });
  // Any other success status would stream the whole file.
  if (response.status !== 206) {
    await response.body?.cancel();
    throw new Error(`OSV change list request failed (HTTP ${response.status})`);
  }

  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  const entries: ChangeEntry[] = [];
  let previous: string | undefined;
  let rest = "";
  try {
    // The range usually ends mid-line, so the text after the final newline is dropped.
    for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
      const lines = (rest + decoder.decode(chunk.value, { stream: true })).split("\n");
      rest = lines.pop()!;
      for (const line of lines) {
        const match = /^([^,]+),([^,/]+)\/([^,/]+)$/.exec(line);
        const modified = timestampKey(match?.[1]);
        if (!match || !modified) throw new Error("OSV change list returned a malformed line");
        if (previous && modified > previous) throw new Error("OSV change list is out of order");
        previous = modified;
        if (modified <= after) return { entries, gap: false };
        entries.push({ modified, ecosystem: match[2]!, id: match[3]! });
      }
    }
  } finally {
    // Stops the download once the scan reaches its bound.
    await reader.cancel();
  }
  if (previous === undefined) throw new Error("OSV change list returned no complete lines");
  return { entries, gap: true };
}

async function fetchRecord(entry: ChangeEntry, query: string): Promise<OsvRecord> {
  const response = await fetch(`${BASE_URL}/${encodeURIComponent(entry.ecosystem)}/${encodeURIComponent(entry.id)}.json${query}`, {
    redirect: "manual",
    signal: AbortSignal.timeout(25_000),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`OSV record request failed (HTTP ${response.status})`);
  }

  const record: unknown = await response.json();
  assertOsvRecord(record, entry);
  const cves = new Set<string>();
  const packages = new Map<string, OsvRecord["packages"][number]>();
  // A withdrawn record is kept with nothing to add, so it replaces any copy stored earlier today.
  if (record.withdrawn === undefined) {
    for (const id of [record.id, ...(record.aliases ?? [])]) {
      if (/^CVE-\d{4}-\d{4,}$/i.test(id)) cves.add(id.toUpperCase());
    }
    for (const { package: affected } of record.affected ?? []) {
      if (affected && REGISTRY_ECOSYSTEMS.has(affected.ecosystem)) {
        packages.set(`${affected.ecosystem}\n${affected.name}`, { ecosystem: affected.ecosystem, name: affected.name });
      }
    }
  }
  return {
    id: record.id,
    // The record can change between listing and fetching. Its own time keeps the newer copy known.
    modified: timestampKey(record.modified)!,
    cves: [...cves],
    packages: [...packages.values()],
  };
}

function assertOsvRecord(value: unknown, entry: ChangeEntry): asserts value is OsvSource {
  if (!isObject(value) || value.id !== entry.id || (timestampKey(value.modified) ?? "") < entry.modified ||
    (value.withdrawn !== undefined && !timestampKey(value.withdrawn)) ||
    (value.aliases !== undefined && (!Array.isArray(value.aliases) || !value.aliases.every((alias) => typeof alias === "string"))) ||
    (value.affected !== undefined && (!Array.isArray(value.affected) || !value.affected.every(isAffected)))) {
    throw new Error("OSV returned an invalid record");
  }
}

function assertOsvState(value: unknown): asserts value is OsvState {
  if (!isObject(value) || typeof value.date !== "string" || typeof value.gap !== "boolean" ||
    (value.cursor !== null && timestampKey(value.cursor) !== value.cursor) ||
    !Array.isArray(value.records) || !value.records.every(isStoredRecord)) {
    throw new Error("OSV state is invalid");
  }
}

function isStoredRecord(value: unknown): boolean {
  return isObject(value) && typeof value.id === "string" && timestampKey(value.modified) === value.modified &&
    Array.isArray(value.cves) && value.cves.every((id) => typeof id === "string" && /^CVE-\d{4}-\d{4,}$/.test(id)) &&
    Array.isArray(value.packages) && value.packages.every(isPackage);
}

function isAffected(value: unknown): boolean {
  return isObject(value) && (value.package === undefined || isPackage(value.package));
}

function isPackage(value: unknown): boolean {
  return isObject(value) && typeof value.ecosystem === "string" && typeof value.name === "string";
}

// Fractions vary in length, and Date.parse would drop nanoseconds, so ordering uses padded strings.
function timestampKey(value: unknown): string | undefined {
  const match = typeof value === "string" ? /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value) : null;
  if (!match || !Number.isFinite(Date.parse(`${match[1]}Z`))) return undefined;
  return `${match[1]}.${(match[2] ?? "").padEnd(9, "0")}Z`;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
