import { describe, expect, it } from "vitest";
import { CATEGORIES, classify } from "../src/classify";
import { cve } from "./helpers";

describe("classify", () => {
  it.each([
    ["Microsoft", "Windows 11", "operating-systems"],
    ["Google", "Chrome", "browsers"],
    ["Fortinet", "FortiOS", "network-security"],
    ["Cisco", "IOS XE", "network-security"],
    ["VMware", "ESXi", "cloud-virtualization"],
    ["PostgreSQL", "PostgreSQL", "databases"],
    ["Unknown", "WordPress Plugin", "wordpress-cms"],
    ["flavorjones", "loofah", "libraries"],
    ["TP-Link", "Archer C7", "iot-firmware"],
    ["Atlassian", "Confluence", "enterprise-apps"],
    ["Unknown", "Unknown", "other"],
  ])("groups %s %s as %s", (vendor, product, category) => {
    expect(classify(cve({ affected: [{ affectedData: [{ vendor, product }] }] }))).toBe(category);
  });

  it.each([
    ["SECURITY@WORDFENCE.COM", "wordpress-cms"],
    ["audit@patchstack.com", "wordpress-cms"],
    ["contact@wpscan.com", "wordpress-cms"],
    ["416baaa9-dc9f-4396-8d5f-8c081fb06d67", "operating-systems"],
    ["chrome-cve-admin@google.com", "browsers"],
  ])("uses the specialist publisher %s", (sourceIdentifier, category) => {
    expect(classify(cve({ sourceIdentifier }))).toBe(category);
  });

  it("does not assume every GitHub advisory is a library", () => {
    expect(classify(cve({ sourceIdentifier: "security-advisories@github.com" }))).toBe("other");
    expect(classify(cve({
      sourceIdentifier: "security-advisories@github.com",
      affected: [{ affectedData: [{ product: "Jenkins" }] }],
    }))).toBe("enterprise-apps");
  });

  it("prefers affected products over incidental description keywords", () => {
    expect(classify(cve({
      affected: [{ affectedData: [{ product: "Jenkins" }] }],
      descriptions: [{ lang: "en", value: "Jenkins can expose credentials on Windows with PostgreSQL installed." }],
    }))).toBe("enterprise-apps");
  });

  it.each([
    ["A flaw in the Python package example.", "libraries"],
    ["A flaw in an open-source library.", "libraries"],
    ["A flaw in the WordPress plugin example.", "wordpress-cms"],
    ["A flaw in a router's firmware.", "iot-firmware"],
    ["SQL injection in an unknown web application.", "other"],
    ["The driver library WFanManager.sys has a flaw.", "other"],
  ])("classifies description: %s", (value, expected) => {
    expect(classify(cve({ descriptions: [{ lang: "en", value }] }))).toBe(expected);
  });

  it.each([
    ["cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", "databases"],
    ["cpe:/a:redhat:ansible_automation_platform:2", "enterprise-apps"],
    ["cpe:2.3:o:unknown:unknown:*:*:*:*:*:*:*:*", "operating-systems"],
    ["cpe:/h:unknown:unknown:1", "iot-firmware"],
  ])("uses affected CPE %s", (criteria, expected) => {
    expect(classify(cve({
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria }] }] }],
    }))).toBe(expected);
  });

  it("ignores non-vulnerable platform CPEs", () => {
    expect(classify(cve({ configurations: [{ nodes: [{ cpeMatch: [
      { vulnerable: false, criteria: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*" },
    ] }] }] }))).toBe("other");
  });

  it("handles missing metadata and unexpected source identifiers", () => {
    expect(classify(cve({ sourceIdentifier: undefined, descriptions: undefined }))).toBe("other");
    expect(classify(cve({ sourceIdentifier: "constructor" }))).toBe("other");
    expect(new Set(CATEGORIES.map((category) => category.id)).size).toBe(10);
  });
});
