import type { MigAuthorizationCatalog } from "./mig-authorization-catalog";
import type { MigNormalizedAuthorizationContext } from "./mig-authorization-context";
import { canonicalKnowledgeResourceRef } from "@shared/corporate-brain/canonical-knowledge-authority";

export interface MigEffectiveEntitlement {
  capabilityIds: string[];
  domainIds: string[];
  intentIds: string[];
  resourceScopes: string[];
  assignedRoles: string[];
}
/** Resolved from trusted tenant configuration, never from a caller request. */
export interface MigTenantAuthorizationPolicy {
  status: "active" | "suspended";
  capabilityIds: string[];
  domainIds: string[];
  intentIds: string[];
  resourceScopes: string[];
  allowedRiskZones: Array<"low" | "medium" | "high" | "critical">;
  allowedResourceStates?: string[];
  staticSodConflicts: Array<[string, string]>;
}
export interface MigAuthorizationDecision {
  decision: "allow" | "deny";
  reason: string;
  effectivePermissions: string[];
  sodResult: { static: "pass" | "deny"; dynamic: "pass" | "deny"; reason?: string };
}
const GOVERNED_SELF_APPROVAL_KINDS = new Set(["fact", "reality", "decision", "policy", "privilege_change", "key_elevation"]);
const contains = (allowed: string[], value: string) => allowed.includes("*") || allowed.includes(value);

export function evaluateAuthorization(
  context: MigNormalizedAuthorizationContext,
  entitlement: MigEffectiveEntitlement | undefined,
  catalog: MigAuthorizationCatalog,
  tenantPolicy?: MigTenantAuthorizationPolicy,
): MigAuthorizationDecision {
  const denied = (reason: string, sodResult: MigAuthorizationDecision["sodResult"] = { static: "pass", dynamic: "pass" }) =>
    ({ decision: "deny" as const, reason, effectivePermissions: [], sodResult });
  if (!entitlement) return denied("principal_entitlement_missing");
  if (!tenantPolicy) return denied("tenant_policy_missing");
  if (tenantPolicy.status !== "active") return denied("tenant_not_active");
  const entry = catalog.entries.get(context.capabilityId);
  if (!entry) return denied("unknown_capability");
  if (!catalog.intents.has(context.intentId)) return denied("unknown_intent");
  if (!entry.semanticActions.includes(context.semanticAction)) return denied("unknown_or_unmapped_action");
  if (!catalog.domains.has(context.domainId) || !entry.domainIds.includes("*") && !entry.domainIds.includes(context.domainId)) return denied("unknown_or_unmapped_domain");
  if (!contains(tenantPolicy.capabilityIds, context.capabilityId)) return denied("tenant_capability_not_allowed");
  if (!contains(tenantPolicy.domainIds, context.domainId)) return denied("tenant_domain_not_allowed");
  if (!contains(tenantPolicy.intentIds, context.intentId)) return denied("tenant_intent_not_allowed");
  if (!contains(tenantPolicy.resourceScopes, context.resourceRef)) return denied("tenant_resource_not_allowed");
  if (!tenantPolicy.allowedRiskZones.includes(entry.riskZone)) return denied("tenant_risk_zone_not_allowed");
  if (context.resourceState && tenantPolicy.allowedResourceStates && !contains(tenantPolicy.allowedResourceStates, context.resourceState)) return denied("resource_state_not_allowed");
  const credential = context.credential;
  const actionRank = { read: 0, execute: 1, administer: 2 } as const;
  if (credential.credentialActionCeiling &&
      actionRank[context.semanticAction] > actionRank[credential.credentialActionCeiling]) {
    return denied("credential_action_ceiling_exceeded");
  }
  const requiredScope = credential.credentialType === "mig_mcp" ? "mcp:invoke" :
    credential.credentialType === "mig_agent" ? "mig:request" : undefined;
  // Missing fields are legacy/unmigrated authority and therefore empty, never
  // wildcard. Optional typing preserves existing non-MIG authenticator shape.
  if (requiredScope && !contains(credential.credentialScopes ?? [], requiredScope)) return denied("credential_scope_missing");
  if (!contains(credential.credentialCapabilityCeiling, context.capabilityId)) return denied("credential_capability_ceiling_exceeded");
  if (!contains(credential.credentialIntentCeiling ?? [], context.intentId)) return denied("credential_intent_ceiling_exceeded");
  if (!contains(credential.credentialDomainCeiling ?? [], context.domainId)) return denied("credential_domain_ceiling_exceeded");
  if (!contains(credential.credentialResourceCeiling ?? [], context.resourceRef)) return denied("credential_resource_ceiling_exceeded");
  if (context.mcpTargetId && !contains(credential.credentialMcpTargetCeiling ?? [], context.mcpTargetId)) return denied("credential_mcp_target_ceiling_exceeded");
  const riskRank = { low: 0, medium: 1, high: 2, critical: 3 } as const;
  if (!credential.credentialRiskZoneCeiling) return denied("credential_risk_zone_ceiling_missing");
  if (riskRank[entry.riskZone] > riskRank[credential.credentialRiskZoneCeiling]) {
    return denied("credential_risk_zone_ceiling_exceeded");
  }
  if (!contains(entitlement.capabilityIds, context.capabilityId)) return denied("principal_capability_not_entitled");
  if (!contains(entitlement.domainIds, context.domainId)) return denied("principal_domain_not_entitled");
  if (!contains(entitlement.intentIds, context.intentId)) return denied("principal_intent_not_entitled");
  if (!contains(entitlement.resourceScopes, context.resourceRef)) return denied("resource_not_entitled");
  if (context.canonicalKnowledge) {
    if (context.resourceRef !== canonicalKnowledgeResourceRef(context.canonicalKnowledge.resource)) {
      return denied("canonical_knowledge_resource_unresolved");
    }
    if (!context.canonicalKnowledge.authority
      && !(context.canonicalKnowledge.authority_state === "DEFERRED_TO_PROTECTED_DISPATCH"
        && context.canonicalKnowledgeBinding)) {
      return denied("canonical_knowledge_authority_unresolved");
    }
    if (context.canonicalKnowledge.authority_state === "DEFERRED_TO_PROTECTED_DISPATCH"
      && !context.canonicalKnowledgeBinding) return denied("canonical_knowledge_binding_required");
    if (context.canonicalKnowledge.authority_state === "DEFERRED_TO_PROTECTED_DISPATCH") {
      // The protected dispatch bridge performs the final CB ALLOW and receipt.
    } else if (context.canonicalKnowledge.authority?.decision !== "ALLOW") {
      return denied(`canonical_knowledge_${context.canonicalKnowledge.authority?.reason ?? "unresolved"}`);
    }
    if (context.canonicalKnowledge.authority
      && context.canonicalKnowledge.authority.operation !== context.canonicalKnowledge.operation) {
      return denied("canonical_knowledge_operation_mismatch");
    }
  }
  if (context.canonicalKnowledgeBinding) {
    const binding = context.canonicalKnowledgeBinding;
    if (!["CONFIRMED", "OVERRIDDEN"].includes(binding.status)) return denied("canonical_knowledge_binding_unconfirmed");
    if (binding.tenant_id !== context.tenantId
      || binding.capability_id !== context.capabilityId) {
      return denied("canonical_knowledge_binding_mismatch");
    }
    if (context.mcpTargetId && binding.mcp_server_id !== context.mcpTargetId) {
      return denied("canonical_knowledge_binding_server_denied");
    }
    if (binding.intent_constraints.length > 0
      && !binding.intent_constraints.includes(context.intentId)) {
      return denied("canonical_knowledge_binding_intent_denied");
    }
    if (binding.route_constraints.length > 0
      && !binding.route_constraints.includes("*")
      && !binding.route_constraints.includes(context.domainId)) {
      return denied("canonical_knowledge_binding_domain_denied");
    }
    const expectedRef = `cb:${binding.tenant_id}:${binding.partition}:${binding.canonical_object_id}${binding.resource_version ? `@${binding.resource_version}` : ""}`;
    if (context.resourceRef !== expectedRef) return denied("canonical_knowledge_binding_resource_denied");
    if (context.canonicalKnowledge
      && binding.canonical_object_id !== context.canonicalKnowledge.resource.canonical_object_id) {
      return denied("canonical_knowledge_binding_object_mismatch");
    }
  }
  const assigned = new Set(entitlement.assignedRoles);
  if (tenantPolicy.staticSodConflicts.some(([left, right]) => assigned.has(left) && assigned.has(right))) {
    return denied("static_segregation_of_duties_conflict", { static: "deny", dynamic: "pass", reason: "incompatible_assignment" });
  }
  const tx = context.transaction;
  const approvingPrincipals = new Set([context.actorPrincipalId, context.executorPrincipalId].filter(Boolean));
  if (tx?.governedKind && GOVERNED_SELF_APPROVAL_KINDS.has(tx.governedKind) &&
    (approvingPrincipals.has(tx.createdByPrincipalId) || approvingPrincipals.has(tx.subjectPrincipalId))) {
    return denied("dynamic_segregation_of_duties_self_approval", { static: "pass", dynamic: "deny", reason: "self_approval" });
  }
  return {
    decision: "allow", reason: "authorization_allowed",
    effectivePermissions: [context.capabilityId],
    sodResult: { static: "pass", dynamic: "pass" },
  };
}