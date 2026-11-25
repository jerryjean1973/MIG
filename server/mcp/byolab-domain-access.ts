import { readOwnerCatalog } from "../standalone/catalog";
export const BYOLAB_DOMAIN_TOOL_NAMES = [
  "create_domain_universe", "update_domain_universe", "get_domain_universe",
] as const;
export const BYOLAB_HISTORICAL_TOOL_NAMES = [
  "get_historical_event_contract", "submit_historical_events", "get_historical_event_receipt",
] as const;
export function isByolabDomainTool(name: string): boolean {
  return ([...BYOLAB_DOMAIN_TOOL_NAMES, ...BYOLAB_HISTORICAL_TOOL_NAMES] as readonly string[]).includes(name);
}
export function isByolabDomainCaller(ctx: { tenantId: string; principalId?: string; clientId?: string }): boolean {
  if (ctx.tenantId !== process.env.MIG_TENANT_ID) return false;
  return readOwnerCatalog().restricted_callers.some(binding =>
    binding.principal_id === ctx.principalId && binding.client_id === ctx.clientId);
}
