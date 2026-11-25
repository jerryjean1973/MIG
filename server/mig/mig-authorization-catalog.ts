/**
 * Versioned, semantic authorization catalog. Adapters translate a downstream
 * surface into this contract; policy code authorizes capability IDs, never raw
 * tool names. Tool bindings remain an adapter concern.
 */
import type { MigAdapterToolEntry, MigRiskZone } from "./mig-types";

export interface MigAuthorizationCatalogEntry {
  capabilityId: string;
  domainIds: string[];
  semanticActions: Array<"read" | "execute" | "administer">;
  classification: "read_only" | "execution" | "admin";
  riskZone: MigRiskZone;
}

export interface MigAuthorizationCatalog {
  version: string;
  entries: ReadonlyMap<string, MigAuthorizationCatalogEntry>;
  domains: ReadonlySet<string>;
  intents: ReadonlySet<string>;
}

export function buildAuthorizationCatalog(
  version: string,
  tools: readonly MigAdapterToolEntry[],
  knownDomainIds: readonly string[],
  knownIntentIds: readonly string[] = [],
): MigAuthorizationCatalog {
  const entries = new Map<string, MigAuthorizationCatalogEntry>();
  const domains = new Set(knownDomainIds);
  const classificationRank = { read_only: 0, execution: 1, admin: 2 } as const;
  const riskRank: Record<MigRiskZone, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  for (const tool of tools) {
    if (!tool.has_governance_contract || !tool.capability_id) continue;
    const existing = entries.get(tool.capability_id);
    const domainIds = [...new Set([...(existing?.domainIds ?? []), ...tool.domain_scope])];
    const semanticAction = tool.classification === "read_only" ? "read" : tool.classification === "execution" ? "execute" : "administer";
    const classification = existing && classificationRank[existing.classification] > classificationRank[tool.classification]
      ? existing.classification
      : tool.classification;
    const riskZone = existing && riskRank[existing.riskZone] > riskRank[tool.risk_zone]
      ? existing.riskZone
      : tool.risk_zone;
    domainIds.forEach(domain => domains.add(domain));
    entries.set(tool.capability_id, {
      capabilityId: tool.capability_id, domainIds,
      semanticActions: [...new Set([...(existing?.semanticActions ?? []), semanticAction])],
      classification,
      riskZone,
    });
  }
  return { version, entries, domains, intents: new Set(knownIntentIds) };
}