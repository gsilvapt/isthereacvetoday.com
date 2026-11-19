import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchTodaysCves } from "../src/nvd";
import { nvdCve as cve } from "./helpers";

const now = new Date("2026-11-19T09:00:00.000Z");

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("fetchTodaysCves", () => {
  it("requests today's UTC publication window with the key in a header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(Response.json({ startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: cve() }] }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await fetchTodaysCves(now, "secret-key")).toEqual([cve()]);
    const [url, options] = fetchMock.mock.calls[0]!;
    const query = new URL(url).searchParams;
    expect(query.get("pubStartDate")).toBe("2026-11-19T00:00:00.000Z");
    expect(query.get("pubEndDate")).toBe(now.toISOString());
    expect(query.get("resultsPerPage")).toBe("2000");
    expect(query.has("noRejected")).toBe(true);
    expect(url.toString()).not.toContain("secret-key");
    expect(url.toString()).not.toContain("Severity");
    expect(options.headers).toEqual({ apiKey: "secret-key" });
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(options.redirect).toBe("manual");
  });

  it.each([[undefined, 6500], ["key", 650]])("paginates and spaces requests for key %s", async (key, delay) => {
    vi.useFakeTimers();
    const second = cve({ id: "CVE-2026-1001" });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(Response.json({ startIndex: 0, totalResults: 2, vulnerabilities: [{ cve: cve() }] }))
      .mockResolvedValueOnce(Response.json({ startIndex: 1, totalResults: 2, vulnerabilities: [{ cve: second }] }));
    vi.stubGlobal("fetch", fetchMock);
    const result = fetchTodaysCves(now, key);
    await vi.advanceTimersByTimeAsync(delay - 1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(await result).toEqual([cve(), second]);
    expect(new URL(fetchMock.mock.calls[1]![0]).searchParams.get("startIndex")).toBe("1");
    if (!key) expect(fetchMock.mock.calls[0]![1].headers).toBeUndefined();
  });

  it("deduplicates repeated IDs between pages", async () => {
    vi.useFakeTimers();
    const newer = cve({ descriptions: [] });
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(Response.json({ startIndex: 0, totalResults: 2, vulnerabilities: [{ cve: cve() }] }))
      .mockResolvedValueOnce(Response.json({ startIndex: 1, totalResults: 2, vulnerabilities: [{ cve: newer }] })));
    const result = fetchTodaysCves(now);
    await vi.runAllTimersAsync();
    expect(await result).toEqual([newer]);
  });

  it.each([301, 403, 429, 500])("fails on HTTP %s rather than returning an empty day", async (status) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("error", { status })));
    await expect(fetchTodaysCves(now)).rejects.toThrow(`HTTP ${status}`);
  });

  it.each([
    {},
    { startIndex: 0, totalResults: -1, vulnerabilities: [] },
    { startIndex: 1, totalResults: 0, vulnerabilities: [] },
    { startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: { id: "bad", published: "2026-11-19" } }] },
    { startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: { id: "CVE-2026-1000", published: "invalid" } }] },
  ])("rejects invalid upstream structure %#", async (page) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json(page)));
    await expect(fetchTodaysCves(now)).rejects.toThrow("invalid");
  });

  it("rejects an unexpectedly empty page before totalResults", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ startIndex: 0, totalResults: 1, vulnerabilities: [] })));
    await expect(fetchTodaysCves(now)).rejects.toThrow("incomplete page");
  });

  it("bounds pagination to stay below 50 external subrequests", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockImplementation(async (url: URL) => Response.json({
      startIndex: Number(url.searchParams.get("startIndex")),
      totalResults: 21,
      vulnerabilities: [{ cve: cve() }],
    }));
    vi.stubGlobal("fetch", fetchMock);
    const assertion = expect(fetchTodaysCves(now)).rejects.toThrow("subrequest budget");
    await vi.runAllTimersAsync();
    await assertion;
    expect(fetchMock).toHaveBeenCalledTimes(20);
  });
});
