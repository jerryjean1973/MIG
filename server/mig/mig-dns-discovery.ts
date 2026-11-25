import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { discoverMigSitemapUrls } from "./mig-sitemap-discovery";

/** Owner-approved public lookup zones, not network or client access grants. */
export const MIG_APPROVED_PUBLIC_DNS_ZONES = [
  "bcentrisk.com",
  "byolab.ai",
  "smartdev.bcentrisk.com",
  "vendorgate.ca",
  "voituresavendre.com",
  "gestionautomobile.com",
  "smartdev.youkandoit.com",
  "youkandoit.com",
] as const;

/** DNS advertisements are observations only, never proof of identity or access. */
export function normalizeMigDnsZone(value: unknown): string {
  if (typeof value !== "string") throw new Error("Enter a DNS domain or private zone.");
  const zone = value.trim().toLowerCase().replace(/\.$/, "");
  if (zone.length > 253 || !zone || isIP(zone) ||
      !zone.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error("Enter a DNS zone only, without a URL, port, path or wildcard.");
  }
  return zone;
}

export async function discoverMigDnsServices(rawZone: unknown, privateScopes: string[] = []) {
  const zone = normalizeMigDnsZone(rawZone);
  // Sitemap reads are independent of SRV answers (including absent/error answers).
  const sitemapDiscovery = discoverMigSitemapUrls(zone, privateScopes);
  // Use the host's configured resolver, including private DNS where configured.
  // Do not accept caller-supplied DNS servers or attempt a zone transfer.
  const resolver = new Resolver({ timeout: 2500, tries: 1 });
  const queries = await Promise.all(["_mcp._tcp", "_mcps._tcp"].map(async service => {
    const name = `${service}.${zone}`;
    try {
      const records = await resolver.resolveSrv(name);
      return { name, status: "answered" as const, records: records.slice(0, 50) };
    } catch (error) {
      const code = String((error as NodeJS.ErrnoException).code ?? "DNS_ERROR");
      return { name, status: ["ENODATA", "ENOTFOUND"].includes(code) ? "no_records" as const : "error" as const, records: [], error: code };
    }
  }));
  const services = queries.flatMap(query => query.records.flatMap(record => {
    if (!record.name || record.name === "." || record.port < 1 || record.port > 65535) return [];
    try {
      const hostname = normalizeMigDnsZone(record.name);
      return [{
        record: query.name, hostname, port: record.port,
        priority: record.priority, weight: record.weight,
        // SRV specifies host and port, not a protocol path. Do not invent one.
        origin: `https://${hostname}${record.port === 443 ? "" : `:${record.port}`}`,
      }];
    } catch { return []; }
  }));
  return {
    zone, queries, services, sitemaps: await sitemapDiscovery,
    registered: false, authority_granted: false,
    scope: "SRV advertisements and same-origin sitemap URLs; not a complete client inventory.",
  };
}
