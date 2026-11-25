import { ownerCall } from "./owner-client";
import type { MigAdapterToolEntry } from "../mig/mig-types";

export interface OwnerCatalog {
  tools: MigAdapterToolEntry[];
  raw_tools: Array<{
    name: string; description: string; classification: "read_only" | "execution" | "admin";
    canonical_service: string; inputSchema: Record<string, unknown>;
    outputSchema?: Record<string, unknown>;
    protocolOutputSchema?: Record<string, unknown>;
  }>;
  domains: string[];
  capability_contract_ids: string[];
  capability_contracts: any[];
  workloads: any[];
  intents: string[];
  restricted_callers: Array<{ principal_id: string; client_id: string }>;
  groups: Array<{ group: string; tools: string[] }>;
}
let catalog: OwnerCatalog | undefined;
let expiresAt = 0;

export async function refreshOwnerCatalog(): Promise<void> {
  const candidate = await ownerCall<OwnerCatalog>("catalog.read", []);
  if (!candidate || !Array.isArray(candidate.tools) || !Array.isArray(candidate.raw_tools) ||
      !Array.isArray(candidate.domains) || !Array.isArray(candidate.capability_contract_ids) ||
      !Array.isArray(candidate.capability_contracts) || !Array.isArray(candidate.workloads) ||
      !Array.isArray(candidate.intents) || !Array.isArray(candidate.restricted_callers) ||
      !Array.isArray(candidate.groups)) {
    throw new Error("MIG_OWNER_CATALOG_INVALID");
  }
  const names = new Set<string>();
  for (const tool of candidate.tools) {
    if (!tool || typeof tool.tool_name !== "string" || names.has(tool.tool_name) ||
        typeof tool.capability_id !== "string" || !tool.capability_id ||
        !["read_only", "execution", "admin"].includes(tool.classification) ||
        !["low", "medium", "high", "critical"].includes(tool.risk_zone) ||
        !Array.isArray(tool.domain_scope) || typeof tool.has_governance_contract !== "boolean") {
      throw new Error("MIG_OWNER_CATALOG_INVALID");
    }
    names.add(tool.tool_name);
  }
  if (candidate.raw_tools.some(tool => !names.has(tool.name)) ||
      candidate.domains.some(domain => typeof domain !== "string") ||
      candidate.capability_contract_ids.some(id => typeof id !== "string")) {
    throw new Error("MIG_OWNER_CATALOG_INVALID");
  }
  catalog = structuredClone(candidate);
  expiresAt = Date.now() + 5 * 60_000;
}

export function readOwnerCatalog(): OwnerCatalog {
  if (!catalog || expiresAt <= Date.now()) throw new Error("MIG_OWNER_CATALOG_UNAVAILABLE");
  return structuredClone(catalog);
}
