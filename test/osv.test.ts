import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchOsvChanges, MAX_OSV_RECORDS, OSV_STATE_KEY, refreshOsv } from "../src/osv";
import type { OsvState } from "../src/types";
import fixture from "./fixtures/osv-records.json";

const now = new Date("2026-11-20T10:00:00.000Z");
const stop = "2026-11-19T22:00:00Z,PyPI/GHSA-before-scan";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function at(minute: number, path = `PyPI/GHSA-${minute}`): string {
  return `2026-11-20T09:${String(minute).padStart(2, "0")}:00Z,${path}`;
}

// Serves the change list with a cut-off final line, and a valid record for each listed path unless overridden.
function stubOsv(lines: string[], records: Record<string, unknown> = {}) {
  const fetchMock = vi.fn().mockImplementation(async (url: string) => {
    const path = decodeURIComponent(new URL(url).pathname.slice(1));
    if (path === "modified_id.csv") {
      return new Response(`${lines.join("\n")}\n2026-11-19T21:00:00.1`, { status: 206 });
    }
    if (path in records) {
      const record = records[path];
      return record instanceof Response ? record : Response.json(record);
    }
    const line = lines.find((entry) => `${entry.split(",")[1]}.json` === path);
    if (!line) return new Response("missing", { status: 404 });
    const [modified, listed] = line.split(",");
    return Response.json({ id: listed!.split("/")[1], modified, affected: [] });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function fetchedPaths(fetchMock: ReturnType<typeof stubOsv>): string[] {
  return fetchMock.mock.calls.slice(1).map(([url]) => decodeURIComponent(new URL(url).pathname.slice(1)));
}

describe("fetchOsvChanges", () => {
  it("reads only the change-list head and compacts registry records", async () => {
    const fetchMock = stubOsv([...fixture.changeList, stop], { "Hex/EEF-CVE-2026-49757.json": fixture.hex });
    expect(await fetchOsvChanges(now, null, new Map())).toEqual({
      records: [{
        id: "EEF-CVE-2026-49757",
        modified: "2026-11-20T09:00:02.794847920Z",
        cves: ["CVE-2026-49757"],
        packages: [{ ecosystem: "Hex", name: "ash_authentication" }],
      }],
      cursor: "2026-11-20T09:00:02.794847920Z",
      partial: false,
      gap: false,
    });
    const [url, options] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv?t=${now.getTime()}`);
    expect(options.headers).toEqual({ Range: "bytes=0-2097151" });
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(options.redirect).toBe("manual");
    expect(fetchMock.mock.calls[1]![0]).toBe(`https://osv-vulnerabilities.storage.googleapis.com/Hex/EEF-CVE-2026-49757.json?t=${now.getTime()}`);
    expect(fetchMock.mock.calls[1]![1].redirect).toBe("manual");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([200, 301, 404, 416, 500])("rejects change-list HTTP %s without reading the body", async (status) => {
    const cancel = vi.fn();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(new ReadableStream({ cancel }), { status })));
    await expect(fetchOsvChanges(now, null, new Map())).rejects.toThrow(`HTTP ${status}`);
    expect(cancel).toHaveBeenCalled();
  });

  it("decodes lines split across chunks and stops reading at the scan bound", async () => {
    const encoder = new TextEncoder();
    const chunks = [at(10).slice(0, 25), `${at(10).slice(25)}\n${at(5).slice(0, 30)}`, `${at(5).slice(30)}\n${stop}\n`, "malformed\n"];
    let pulls = 0;
    const cancel = vi.fn();
    const body = new ReadableStream({
      pull(controller) {
        controller.enqueue(encoder.encode(chunks[pulls++]));
        if (pulls === chunks.length) controller.close();
      },
      cancel,
    }, { highWaterMark: 0 });
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(new Response(body, { status: 206 }))
      .mockImplementation(async (url: string) => {
        const id = new URL(url).pathname.split("/")[2]!.replace(/\.json$/, "");
        return Response.json({ id, modified: `2026-11-20T09:${id.slice(5).padStart(2, "0")}:00Z` });
      }));
    expect(await fetchOsvChanges(now, null, new Map())).toMatchObject({
      records: [{ id: "GHSA-5" }, { id: "GHSA-10" }],
      cursor: "2026-11-20T09:10:00.000000000Z",
      gap: false,
    });
    expect(pulls).toBe(3);
    expect(cancel).toHaveBeenCalled();
  });

  it("ignores the cut-off final line and reports the gap before it", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(`${at(1)}\n2026-11-20T09:00:00Z,PyPI/GHSA-cut`, { status: 206 }))
      .mockResolvedValueOnce(Response.json({ id: "GHSA-1", modified: "2026-11-20T09:01:00Z" }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await fetchOsvChanges(now, null, new Map())).toMatchObject({
      records: [{ id: "GHSA-1" }],
      cursor: "2026-11-20T09:01:00.000000000Z",
      gap: true,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects a range without a complete line", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("2026-11-20T09:00:00Z,PyPI/GHSA", { status: 206 })));
    await expect(fetchOsvChanges(now, null, new Map())).rejects.toThrow("no complete lines");
  });

  it.each([
    "",
    "2026-11-20T09:30:00Z PyPI/GHSA-1",
    "2026-11-20 09:30:00Z,PyPI/GHSA-1",
    "2026-11-20T09:30:00+00:00,PyPI/GHSA-1",
    "2026-11-20T09:30:00.1234567890Z,PyPI/GHSA-1",
    "2026-11-20T99:30:00Z,PyPI/GHSA-1",
    "2026-11-20T09:30:00Z,PyPI",
    "2026-11-20T09:30:00Z,PyPI/GHSA-1,extra",
  ])("rejects malformed change-list line %j", async (line) => {
    stubOsv([at(40), line, stop]);
    await expect(fetchOsvChanges(now, null, new Map())).rejects.toThrow("malformed line");
  });

  it("rejects an out-of-order change list", async () => {
    stubOsv([at(10), at(20), stop]);
    await expect(fetchOsvChanges(now, null, new Map())).rejects.toThrow("out of order");
  });

  it("orders timestamps by nanosecond regardless of fraction length", async () => {
    const fetchMock = stubOsv([
      "2026-11-20T09:00:00.5Z,PyPI/GHSA-half",
      "2026-11-20T09:00:00.000000002Z,PyPI/GHSA-two",
      "2026-11-20T09:00:00.000000001Z,PyPI/GHSA-one",
      "2026-11-20T09:00:00Z,PyPI/GHSA-zero",
      stop,
    ]);
    const known = new Map([["GHSA-one", "2026-11-20T09:00:00.000000001Z"], ["GHSA-zero", "2026-11-20T09:00:00.000000000Z"]]);
    expect(await fetchOsvChanges(now, "2026-11-20T09:00:00.000000001Z", known)).toMatchObject({
      cursor: "2026-11-20T09:00:00.500000000Z",
      gap: false,
    });
    expect(fetchedPaths(fetchMock)).toEqual(["PyPI/GHSA-two.json", "PyPI/GHSA-half.json"]);
  });

  it("fetches only package-registry advisories but advances past newer skipped entries", async () => {
    const fetchMock = stubOsv([
      at(50, "Debian/DSA-1"),
      at(40, "GitHub Actions/GHSA-actions"),
      at(30, "Red Hat/RHSA-1"),
      at(20, "GIT/CVE-2026-1"),
      at(15, "npm/MAL-2026-1"),
      at(10, "Ubuntu/USN-1"),
      at(5, "[EMPTY]/X-1"),
      at(1, "PyPI/GHSA-pypi"),
      stop,
    ]);
    expect(await fetchOsvChanges(now, null, new Map())).toMatchObject({ cursor: "2026-11-20T09:50:00.000000000Z", partial: false, gap: false });
    expect(fetchedPaths(fetchMock)).toEqual(["PyPI/GHSA-pypi.json", "GitHub Actions/GHSA-actions.json"]);
    expect(fetchMock.mock.calls[2]![0]).toContain("/GitHub%20Actions/");
  });

  it("refetches changed known records from any directory, including MAL- reports", async () => {
    const fetchMock = stubOsv([at(30, "[EMPTY]/GHSA-moved"), at(20, "npm/MAL-2026-1"), at(10, "npm/MAL-2026-2"), stop]);
    const known = new Map([["GHSA-moved", "2026-11-20T09:01:00.000000000Z"], ["MAL-2026-1", "2026-11-20T09:01:00.000000000Z"]]);
    expect(await fetchOsvChanges(now, null, known)).toMatchObject({ cursor: "2026-11-20T09:30:00.000000000Z", partial: false });
    expect(fetchedPaths(fetchMock)).toEqual(["npm/MAL-2026-1.json", "[EMPTY]/GHSA-moved.json"]);
  });

  it.each([
    [null, ["PyPI/GHSA-late-yesterday.json", "PyPI/GHSA-midnight.json"], "2026-11-20T00:00:00.000000000Z"],
    ["2026-11-19T23:30:00Z", ["PyPI/GHSA-late-yesterday.json", "PyPI/GHSA-midnight.json"], "2026-11-20T00:00:00.000000000Z"],
    ["2026-11-20T00:30:00Z", ["PyPI/GHSA-midnight.json"], "2026-11-20T00:30:00.000000000Z"],
  ])("scans from an hour before UTC midnight or the cursor and excludes entries after now (cursor %s)", async (since, paths, cursor) => {
    const fetchMock = stubOsv([
      "2026-11-20T10:00:00.000000001Z,PyPI/GHSA-future",
      "2026-11-20T00:00:00Z,PyPI/GHSA-midnight",
      "2026-11-19T23:30:00Z,PyPI/GHSA-late-yesterday",
      "2026-11-19T23:00:00Z,PyPI/GHSA-at-bound",
    ]);
    expect(await fetchOsvChanges(now, since, new Map())).toMatchObject({ cursor, partial: false, gap: false });
    expect(fetchedPaths(fetchMock)).toEqual(paths);
  });

  it("re-scans an hour before the cursor for late arrivals and skips known entries", async () => {
    const fetchMock = stubOsv([
      at(40),
      at(20),
      at(15),
      at(10),
      "2026-11-20T08:30:00Z,PyPI/GHSA-at-lookback",
      stop,
    ]);
    const known = new Map([
      ["GHSA-15", "2026-11-20T09:14:00.000000000Z"],
      ["GHSA-10", "2026-11-20T09:10:00.000000000Z"],
      ["GHSA-20", "2026-11-20T09:20:00.000000001Z"],
    ]);
    expect(await fetchOsvChanges(now, "2026-11-20T09:30:00Z", known)).toMatchObject({
      cursor: "2026-11-20T09:40:00.000000000Z",
      partial: false,
      gap: false,
    });
    expect(fetchedPaths(fetchMock)).toEqual(["PyPI/GHSA-15.json", "PyPI/GHSA-40.json"]);
  });

  it("reports a gap when the range ends before the lookback bound", async () => {
    stubOsv([at(40), at(10)]);
    expect(await fetchOsvChanges(now, "2026-11-20T09:30:00Z", new Map())).toMatchObject({ gap: true });
  });

  it("does not validate lines past the scan bound", async () => {
    const fetchMock = stubOsv([at(10), stop, "malformed", at(50)]);
    expect(await fetchOsvChanges(now, null, new Map())).toMatchObject({ cursor: "2026-11-20T09:10:00.000000000Z", gap: false });
    expect(fetchedPaths(fetchMock)).toEqual(["PyPI/GHSA-10.json"]);
  });

  it.each([
    [null, [stop], new Map(), null],
    ["2026-11-20T09:10:00.25Z", [at(10), stop], new Map([["GHSA-10", "2026-11-20T09:10:00.000000000Z"]]), "2026-11-20T09:10:00.250000000Z"],
  ])("keeps the cursor at %s when nothing changed", async (since, lines, known, cursor) => {
    const fetchMock = stubOsv(lines);
    expect(await fetchOsvChanges(now, since, known)).toEqual({ records: [], cursor, partial: false, gap: false });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects an invalid cursor", async () => {
    stubOsv([stop]);
    await expect(fetchOsvChanges(now, "2026-11-20T09:10:00", new Map())).rejects.toThrow("cursor");
  });

  it("processes the oldest entries first up to the cap, four at a time", async () => {
    const serve = stubOsv([...Array.from({ length: 12 }, (_, index) => at(12 - index)), stop]);
    let active = 0;
    let peak = 0;
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve));
      active--;
      return serve(url);
    }));
    const result = await fetchOsvChanges(now, null, new Map());
    expect(result).toMatchObject({ cursor: "2026-11-20T09:09:00.000000000Z", partial: true, gap: false });
    expect(result.records.map((record) => record.id)).toEqual(Array.from({ length: 9 }, (_, index) => `GHSA-${index + 1}`));
    expect(serve).toHaveBeenCalledTimes(1 + MAX_OSV_RECORDS);
    expect(peak).toBe(4);
  });

  it("counts only unknown entries toward the cap", async () => {
    const fetchMock = stubOsv([...Array.from({ length: 12 }, (_, index) => at(12 - index)), stop]);
    const known = new Map(Array.from({ length: 3 }, (_, index) => [`GHSA-${index + 1}`, `2026-11-20T09:0${index + 1}:00.000000000Z`]));
    expect(await fetchOsvChanges(now, null, known)).toMatchObject({ cursor: "2026-11-20T09:12:00.000000000Z", partial: false });
    expect(fetchedPaths(fetchMock)).toHaveLength(MAX_OSV_RECORDS);
  });

  it("processes exactly the cap without marking the run incomplete", async () => {
    stubOsv([at(30, "Debian/DSA-1"), ...Array.from({ length: 9 }, (_, index) => at(9 - index)), stop]);
    expect(await fetchOsvChanges(now, null, new Map())).toMatchObject({ cursor: "2026-11-20T09:30:00.000000000Z", partial: false });
  });

  it("finishes a timestamp group split by the cap on the next run", async () => {
    stubOsv([...Array.from({ length: 10 }, (_, index) => at(9, `PyPI/GHSA-group-${index}`)), stop]);
    const first = await fetchOsvChanges(now, "2026-11-20T08:00:00Z", new Map());
    expect(first).toMatchObject({ cursor: "2026-11-20T09:09:00.000000000Z", partial: true });
    expect(first.records).toHaveLength(9);

    const known = new Map(first.records.map((record) => [record.id, record.modified]));
    expect(await fetchOsvChanges(now, first.cursor, known)).toMatchObject({
      records: [{ id: "GHSA-group-0" }],
      cursor: "2026-11-20T09:09:00.000000000Z",
      partial: false,
    });
  });

  it("keeps records fetched after a failure but stops the cursor before it, then retries it", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const lines = [at(40), at(30), at(20), at(10), stop];
    stubOsv(lines, { "PyPI/GHSA-20.json": new Response("missing", { status: 404 }) });
    const first = await fetchOsvChanges(now, null, new Map());
    expect(first).toMatchObject({ cursor: "2026-11-20T09:10:00.000000000Z", partial: true, gap: false });
    expect(first.records.map((record) => record.id)).toEqual(["GHSA-10", "GHSA-30", "GHSA-40"]);
    expect(warn).toHaveBeenCalledWith("OSV record GHSA-20 failed; retrying next run", expect.any(Error));

    const fetchMock = stubOsv(lines);
    const known = new Map(first.records.map((record) => [record.id, record.modified]));
    expect(await fetchOsvChanges(now, first.cursor, known)).toMatchObject({
      records: [{ id: "GHSA-20" }],
      cursor: "2026-11-20T09:40:00.000000000Z",
      partial: false,
    });
    expect(fetchedPaths(fetchMock)).toEqual(["PyPI/GHSA-20.json"]);
  });

  it("fetches a record listed under several registry ecosystems once", async () => {
    const { modified } = fixture.githubActions;
    const fetchMock = stubOsv([
      `${modified},PyPI/GHSA-6f4g-xm8v-pgv6`,
      `${modified},GitHub Actions/GHSA-6f4g-xm8v-pgv6`,
      "2026-11-10T00:00:00Z,PyPI/GHSA-older",
    ], { "PyPI/GHSA-6f4g-xm8v-pgv6.json": fixture.githubActions });
    const { records } = await fetchOsvChanges(new Date("2026-11-11T03:00:00Z"), null, new Map());
    expect(records).toEqual([{
      id: "GHSA-6f4g-xm8v-pgv6",
      modified,
      cves: ["CVE-2026-123369"],
      packages: [{ ecosystem: "GitHub Actions", name: "tmatens/compose-lint" }, { ecosystem: "PyPI", name: "compose-lint" }],
    }]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("extracts canonical CVE IDs and deduplicates registry packages", async () => {
    stubOsv([at(10, "PyPI/CVE-2026-5555"), at(5, "npm/GHSA-none"), stop], {
      "PyPI/CVE-2026-5555.json": {
        id: "CVE-2026-5555",
        modified: "2026-11-20T09:10:00.000Z",
        aliases: ["cve-2026-1234", "CVE-2026-1234", "GHSA-xxxx-yyyy-zzzz", "CVE-2026-12", "XCVE-2026-12345", "PYSEC-2026-1"],
        affected: [
          { package: { ecosystem: "PyPI", name: "example" } },
          { package: { ecosystem: "PyPI", name: "example" } },
          { package: { ecosystem: "Debian:12", name: "example" } },
          { package: { ecosystem: "npm", name: "example" } },
          { ranges: [] },
        ],
      },
    });
    const { records } = await fetchOsvChanges(now, null, new Map());
    expect(records).toEqual([
      { id: "GHSA-none", modified: "2026-11-20T09:05:00.000000000Z", cves: [], packages: [] },
      {
        id: "CVE-2026-5555",
        modified: "2026-11-20T09:10:00.000000000Z",
        cves: ["CVE-2026-5555", "CVE-2026-1234"],
        packages: [{ ecosystem: "PyPI", name: "example" }, { ecosystem: "npm", name: "example" }],
      },
    ]);
  });

  it("accepts a record modified after it was listed and keeps its newer time", async () => {
    stubOsv([at(10), stop], { "PyPI/GHSA-10.json": { id: "GHSA-10", modified: "2026-11-20T09:10:00.000000001Z" } });
    expect(await fetchOsvChanges(now, null, new Map())).toMatchObject({
      records: [{ id: "GHSA-10", modified: "2026-11-20T09:10:00.000000001Z" }],
      cursor: "2026-11-20T09:10:00.000000000Z",
    });
  });

  it.each([
    ["a non-object", []],
    ["a mismatched id", { id: "GHSA-other", modified: "2026-11-20T09:10:00Z" }],
    ["an older modified time", { id: "GHSA-10", modified: "2026-11-20T09:09:59.999999999Z" }],
    ["an invalid modified time", { id: "GHSA-10", modified: "2026-11-20T09:10:00" }],
    ["an invalid withdrawal time", { id: "GHSA-10", modified: "2026-11-20T09:10:00Z", withdrawn: true }],
    ["non-string aliases", { id: "GHSA-10", modified: "2026-11-20T09:10:00Z", aliases: [1] }],
    ["non-array affected", { id: "GHSA-10", modified: "2026-11-20T09:10:00Z", affected: {} }],
    ["a package without a name", { id: "GHSA-10", modified: "2026-11-20T09:10:00Z", affected: [{ package: { ecosystem: "PyPI" } }] }],
    ["invalid JSON", new Response("{")],
    ["HTTP 301", new Response("moved", { status: 301 })],
    ["HTTP 404", new Response("missing", { status: 404 })],
    ["HTTP 500", new Response("error", { status: 500 })],
  ])("skips a record with %s without advancing the cursor", async (_, record) => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    stubOsv([at(10), stop], { "PyPI/GHSA-10.json": record });
    expect(await fetchOsvChanges(now, null, new Map())).toEqual({ records: [], cursor: null, partial: true, gap: false });
    expect(warn).toHaveBeenCalledOnce();
  });
});

describe("refreshOsv", () => {
  const stored: OsvState = {
    date: "2026-11-20",
    cursor: "2026-11-20T09:05:00.000000000Z",
    gap: false,
    records: [{
      id: "GHSA-5",
      modified: "2026-11-20T09:05:00.000000000Z",
      cves: ["CVE-2026-1000"],
      packages: [{ ecosystem: "PyPI", name: "example" }],
    }],
  };

  function kv(value: string | null | Error) {
    const get = value instanceof Error ? vi.fn().mockRejectedValue(value) : vi.fn().mockResolvedValue(value);
    return { get } as unknown as KVNamespace & { get: typeof get };
  }

  it("adds new records to today's state and skips known ones", async () => {
    const fetchMock = stubOsv([at(10), at(5), stop]);
    const store = kv(JSON.stringify(stored));
    const result = await refreshOsv(store, now);
    expect(store.get).toHaveBeenCalledWith(OSV_STATE_KEY);
    expect(fetchedPaths(fetchMock)).toEqual(["PyPI/GHSA-10.json"]);
    expect(result).toEqual({
      state: { ...stored, cursor: "2026-11-20T09:10:00.000000000Z", records: [...stored.records, {
        id: "GHSA-10", modified: "2026-11-20T09:10:00.000000000Z", cves: [], packages: [],
      }] },
      complete: true,
      updated: true,
    });
  });

  it("replaces a stored record with its withdrawal, even from another directory", async () => {
    stubOsv([at(20, "[EMPTY]/GHSA-5"), stop], {
      "[EMPTY]/GHSA-5.json": { id: "GHSA-5", modified: "2026-11-20T09:20:00Z", withdrawn: "2026-11-20T09:20:00Z", aliases: ["CVE-2026-1000"] },
    });
    const { state } = await refreshOsv(kv(JSON.stringify(stored)), now);
    expect(state.records).toEqual([{ id: "GHSA-5", modified: "2026-11-20T09:20:00.000000000Z", cves: [], packages: [] }]);
  });

  it("resets the state at a new UTC day", async () => {
    const fetchMock = stubOsv([at(10), stop]);
    const yesterday = { ...stored, date: "2026-11-19", cursor: "2026-11-19T23:00:00.000000000Z", gap: true };
    expect(await refreshOsv(kv(JSON.stringify(yesterday)), now)).toMatchObject({
      state: { date: "2026-11-20", cursor: "2026-11-20T09:10:00.000000000Z", gap: false, records: [{ id: "GHSA-10" }] },
      complete: true,
    });
    expect(fetchedPaths(fetchMock)).toEqual(["PyPI/GHSA-10.json"]);
  });

  it.each([
    ["a stored gap", { ...stored, gap: true }, [at(10), stop]],
    ["a new gap", stored, [at(10)]],
  ])("keeps the day incomplete after %s", async (_, state, lines) => {
    stubOsv(lines);
    expect(await refreshOsv(kv(JSON.stringify(state)), now)).toMatchObject({ state: { gap: true }, complete: false, updated: true });
  });

  it("marks a capped run incomplete", async () => {
    stubOsv([...Array.from({ length: 10 }, (_, index) => at(29 - index)), stop]);
    expect(await refreshOsv(kv(null), now)).toMatchObject({ state: { gap: false }, complete: false, updated: true });
  });

  it.each([
    ["invalid JSON", "{"],
    ["an invalid cursor", JSON.stringify({ ...stored, cursor: "2026-11-20T09:05:00Z" })],
    ["an invalid record", JSON.stringify({ ...stored, records: [{ ...stored.records[0], cves: ["cve-2026-1000"] }] })],
    ["a missing gap flag", JSON.stringify({ ...stored, gap: undefined })],
  ])("discards a state with %s and rescans the day", async (_, value) => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    stubOsv([at(10), at(5), stop]);
    expect(await refreshOsv(kv(value), now)).toMatchObject({
      state: { date: "2026-11-20", gap: false, records: [{ id: "GHSA-5" }, { id: "GHSA-10" }] },
      updated: true,
    });
    expect(warn).toHaveBeenCalledWith("Discarding invalid OSV state", expect.any(Error));
  });

  it("keeps the earlier state unchanged when OSV fails", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("error", { status: 500 })));
    expect(await refreshOsv(kv(JSON.stringify(stored)), now)).toEqual({ state: stored, complete: false, updated: false });
    expect(warn).toHaveBeenCalledOnce();
  });

  it("publishes without OSV packages when the state cannot be read", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchMock = stubOsv([at(10), stop]);
    expect(await refreshOsv(kv(new Error("KV unavailable")), now)).toEqual({
      state: { date: "2026-11-20", cursor: null, gap: false, records: [] },
      complete: false,
      updated: false,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
