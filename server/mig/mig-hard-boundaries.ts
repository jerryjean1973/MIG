/** Server-owned hard boundaries. These precede and cannot be overridden by PDP approvals. */
import type { MigRemoteAgent, MigIntentDefinition } from "@shared/schema";
import type { MigAdapterToolEntry } from "./mig-types";

export function evaluateMigHardBoundaries(input: {
  agent: MigRemoteAgent; intent: MigIntentDefinition; tool?: MigAdapterToolEntry; tenantMatches: boolean;
  operation?: { resources?: string[]; semantic_action?: string };
}): { allowed: true } | { allowed: false; reason: string } {
  if (!input.tenantMatches) return { allowed: false, reason: "tenant_context_mismatch" };
  if (!input.tool) return { allowed: false, reason: "unknown_or_prohibited_resource" };
  const prohibited = (input.agent.metadata as Record<string, unknown> | null)?.prohibited_tool_names;
  if (Array.isArray(prohibited) && prohibited.includes(input.tool.tool_name)) return { allowed: false, reason: "prohibited_resource" };
  if ((input.intent.deniedToolNames as string[]).includes(input.tool.tool_name)) return { allowed: false, reason: "prohibited_resource" };
  const sod = (input.agent.metadata as Record<string, unknown> | null)?.separation_of_duties_denied_tools;
  if (Array.isArray(sod) && sod.includes(input.tool.tool_name)) return { allowed: false, reason: "separation_of_duties" };
  const metadata = input.agent.metadata as Record<string, unknown> | null;
  const prohibitedResources = Array.isArray(metadata?.prohibited_resource_ids) ? metadata!.prohibited_resource_ids as string[] : [];
  if (input.operation?.resources?.some(resource => prohibitedResources.includes(resource))) return { allowed: false, reason: "prohibited_resource" };
  const sodResources = Array.isArray(metadata?.separation_of_duties_resource_ids) ? metadata!.separation_of_duties_resource_ids as string[] : [];
  if (input.operation?.resources?.some(resource => sodResources.includes(resource))) return { allowed: false, reason: "separation_of_duties" };
  const destructiveActions = Array.isArray(metadata?.destructive_semantic_actions) ? metadata!.destructive_semantic_actions as string[] : [];
  if (input.operation?.semantic_action && destructiveActions.includes(input.operation.semantic_action) && !metadata?.destructive_operation_grant) {
    return { allowed: false, reason: "destructive_operation_protection" };
  }
  return { allowed: true };
}