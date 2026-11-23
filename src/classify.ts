import type { Cve } from "./types";

export const CATEGORIES = [
  { id: "operating-systems", name: "Operating Systems" },
  { id: "browsers", name: "Browsers" },
  { id: "network-security", name: "Network & Security Appliances" },
  { id: "cloud-virtualization", name: "Cloud & Virtualization" },
  { id: "databases", name: "Databases" },
  { id: "wordpress-cms", name: "WordPress & CMS" },
  { id: "libraries", name: "Open-Source Libraries" },
  { id: "iot-firmware", name: "IoT, Routers & Firmware" },
  { id: "enterprise-apps", name: "Enterprise Apps" },
  { id: "other", name: "Other" },
] as const;

type CategoryId = typeof CATEGORIES[number]["id"];

const SOURCE_CATEGORIES: Record<string, CategoryId> = {
  "security@wordfence.com": "wordpress-cms",
  "audit@patchstack.com": "wordpress-cms",
  "contact@wpscan.com": "wordpress-cms",
  "security@joomla.org": "wordpress-cms",
  "416baaa9-dc9f-4396-8d5f-8c081fb06d67": "operating-systems",
  "chrome-cve-admin@google.com": "browsers",
  "security@opera.com": "browsers",
  "openssl-security@openssl.org": "libraries",
};

const PRODUCT_RULES: [CategoryId, RegExp][] = [
  ["wordpress-cms", /\b(wordpress|woocommerce|drupal|joomla|typo3|prestashop)\b/i],
  ["browsers", /\b(chrome|chromium|firefox|webkit|safari|microsoft edge|thunderbird)\b/i],
  ["network-security", /\b(fortios|fortiproxy|fortimanager|fortigate|pan-os|globalprotect|netscaler|citrix gateway|cisco (?:ios|asa|nx-os|ise|firepower)|ivanti (?:connect|policy)|junos|big-ip|sonicwall|firewall|vpn appliance)\b/i],
  ["cloud-virtualization", /\b(kubernetes|kubelet|docker|containerd|runc|vmware|vcenter|esxi|hyper-v|openstack|xen|qemu|proxmox|cloudstack)\b/i],
  ["databases", /\b(postgresql|postgres|mysql|mariadb|mongodb|redis|valkey|sqlite|sql server|oracle database|cassandra|elasticsearch|opensearch|clickhouse|cockroachdb|neo4j)\b/i],
  ["operating-systems", /\b(windows|linux|macos|ios|ipados|android|freebsd|openbsd|netbsd|watchos|tvos|visionos)\b/i],
  ["iot-firmware", /\b(firmware|router|ip camera|smart camera|iot|embedded device|tenda|tp-link|d-link|netgear|zyxel|mikrotik)\b/i],
  ["enterprise-apps", /\b(atlassian|confluence|jira|bitbucket|gitlab|jenkins|sharepoint|exchange server|microsoft office|microsoft word|microsoft excel|outlook|libreoffice|sap|salesforce|servicenow|adobe acrobat|ansible|awx|oracle (?:fusion|identity|peoplesoft|e-business|weblogic))\b/i],
  ["libraries", /\b(openssl|libxml2|libxslt|libpng|libjpeg|zlib|curl|loofah|nokogiri|lodash|webpack|vite|django|flask|rails|spring framework|spring boot|netty|log4j|jackson-databind|pillow|numpy|scipy|tensorflow|pytorch|open62541)\b/i],
];

export function classify(cve: Cve): CategoryId {
  const source = cve.sourceIdentifier?.toLowerCase() ?? "";
  if (Object.hasOwn(SOURCE_CATEGORIES, source)) return SOURCE_CATEGORIES[source]!;

  const products: string[] = [];
  const cpes: string[] = [];
  for (const affected of cve.affected ?? []) {
    for (const product of affected.affectedData ?? []) {
      products.push(`${product.vendor ?? ""} ${product.product ?? ""}`);
      cpes.push(...(product.cpes ?? []));
    }
  }
  for (const config of cve.configurations ?? []) {
    for (const node of config.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        // Non-vulnerable CPEs usually describe the platform an affected app runs on.
        if (match.vulnerable) cpes.push(match.criteria);
      }
    }
  }

  for (const cpe of cpes) {
    const fields = cpe.startsWith("cpe:2.3:") ? cpe.split(":").slice(3, 5) : cpe.split(":").slice(2, 4);
    products.push(fields.join(" ").replaceAll("_", " "));
  }

  const productText = products.join(" ");
  for (const [category, pattern] of PRODUCT_RULES) {
    if (pattern.test(productText)) return category;
  }

  // Product names take precedence over incidental platform names in descriptions.
  const description = cve.descriptions?.find((entry) => entry.lang === "en")?.value ?? "";
  const lead = description.slice(0, 500);
  for (const [category, pattern] of PRODUCT_RULES) {
    if (pattern.test(lead)) return category;
  }
  if (/\b(?:npm|python|pypi|ruby|rust|go|golang|composer|nuget) (?:package|crate|module|gem)\b|\b(?:javascript|python|ruby|rust|go|php|java|c\+\+) (?:library|framework)\b|\b(?:open.source|shared) library\b/i.test(lead)) {
    return "libraries";
  }
  // OSV packages come only from package registries.
  if (cve.sources.includes("osv")) return "libraries";

  if (cpes.some((cpe) => /^(?:cpe:2\.3:o:|cpe:\/o:)/.test(cpe))) return "operating-systems";
  if (cpes.some((cpe) => /^(?:cpe:2\.3:h:|cpe:\/h:)/.test(cpe))) return "iot-firmware";
  return "other";
}
