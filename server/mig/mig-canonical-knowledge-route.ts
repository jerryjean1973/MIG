import { corporateBrainKnowledgeService } from "../standalone/knowledge-owner";
import {
  canonicalKnowledgeAuthorityService,
  databaseKnowledgeAuthorityRepository,
} from "../standalone/knowledge-owner";
import {
  canonicalKnowledgeResourceRef,
  isCanonicalKnowledgeResourceRef,
  type CanonicalKnowledgeAuthorityDecision,
  type CanonicalKnowledgePrincipal,
  type CanonicalKnowledgeResource,
  type CBAuthorityOperation,
} from "@shared/corporate-brain/canonical-knowledge-authority";

const REF = /^cb:([^:]+):(FACT|STRUCTURAL_READING|DECISION):([^@]+)(?:@(.+))?$/;

/**
 * Resolves a canonical MCP target from the persisted Corporate Brain record.
 * The route never accepts a caller-supplied object or knowledge id: the cb
 * reference selects an existing server-side record, while the authority
 * service remains the sole policy/binding evaluator.
 */
export async function resolveCanonicalKnowledgeRouteTarget(input: {
  tenantId: string;
  principalId: string;
  resourceRef: string;
  operation: CBAuthorityOperation;
  intentId?: string;
  serviceId?: string;
  accessPath?: string;
  capabilityIds?: string[];
  evaluatedAt?: string;
}): Promise<{
  resource: CanonicalKnowledgeResource;
  resolver: (args: {
    tenantId: string;
    principalId: string;
    intentId: string;
    resource: CanonicalKnowledgeResource;
    operation: CBAuthorityOperation;
    serviceId: string;
    accessPath: string;
    capabilityIds: string[];
  }) => Promise<CanonicalKnowledgeAuthorityDecision | undefined>;
} | undefined> {
  const match = REF.exec(input.resourceRef);
  if (!match || !isCanonicalKnowledgeResourceRef(input.resourceRef)) return undefined;
  const [, tenantId, partition, objectId, version] = match;
  if (tenantId !== input.tenantId || !objectId) return undefined;
  const bindings = await databaseKnowledgeAuthorityRepository.listBindings(tenantId);
  const matchingBindings = bindings.filter(candidate =>
    candidate.tenant_id === tenantId
    && candidate.resource.partition === partition
    && candidate.resource.canonical_object_id === objectId
    && candidate.resource.version === version,
  );
  // Independent principal-scoped policies can bind the same exact version.
  // Resolve one resource identity, not one policy row. Ambiguous metadata
  // remains unresolvable rather than choosing a caller-favorable target.
  if (!matchingBindings.length || matchingBindings.some(candidate =>
    canonicalKnowledgeResourceRef(candidate.resource) !== canonicalKnowledgeResourceRef(matchingBindings[0].resource)
    || JSON.stringify(candidate.resource) !== JSON.stringify(matchingBindings[0].resource))) return undefined;
  const binding = matchingBindings[0];
  if (!binding || canonicalKnowledgeResourceRef(binding.resource) !== input.resourceRef) return undefined;
  const resource = Object.freeze({ ...binding.resource });
  return {
    resource,
    resolver: async args => {
      // The target returned by this resolver is server-owned.  Do not allow a
      // downstream adapter to substitute a different tenant, resource version,
      // principal, intent, capability set, or operation after the reference
      // has been resolved.
      if (
        args.tenantId !== input.tenantId
        || args.principalId !== input.principalId
        || args.operation !== input.operation
        || canonicalKnowledgeResourceRef(args.resource) !== input.resourceRef
      ) {
        return {
          decision: "DENY",
          reason: "canonical_knowledge_route_target_mismatch",
          resource,
          operation: input.operation,
          principal_authorized: false,
        };
      }
      const receipt = await canonicalKnowledgeAuthorityService.authorizeAndPersist(
        resource,
        {
          tenant_id: input.tenantId,
          principal_id: input.principalId,
          intent_id: input.intentId ?? args.intentId,
          service_id: input.serviceId ?? args.serviceId,
          access_path: input.accessPath ?? args.accessPath,
          capability_ids: input.capabilityIds ?? args.capabilityIds,
        } satisfies CanonicalKnowledgePrincipal,
        args.operation,
        input.evaluatedAt,
      );
      return {
        decision: receipt.decision,
        reason: receipt.reason,
        resource,
        operation: input.operation,
        policy_id: receipt.policy_id ?? undefined,
        policy_version: receipt.policy_version ?? undefined,
        inheritance_path: receipt.inheritance_path,
        principal_authorized: receipt.decision === "ALLOW",
      };
    },
  };
}

/**
 * Called immediately before dispatch.  Existence is itself protected
 * metadata: never probe the tenant store until the exact CB READ/REFERENCE
 * decision has been made for the authenticated principal.
 */
export async function canonicalKnowledgeObjectExists(input: {
  resource: CanonicalKnowledgeResource;
  principal: CanonicalKnowledgePrincipal;
  operation?: Extract<CBAuthorityOperation, "READ" | "REFERENCE">;
  evaluatedAt?: string;
}): Promise<boolean> {
  const receipt = await canonicalKnowledgeAuthorityService.authorizeAndPersist(
    input.resource,
    input.principal,
    input.operation ?? "READ",
    input.evaluatedAt,
  );
  if (receipt.decision !== "ALLOW") return false;
  if (!input.resource.knowledge_id) return false;
  const governed = await corporateBrainKnowledgeService.getGovernedKnowledgeById({
    knowledge_id: input.resource.knowledge_id,
    tenant_id: input.resource.tenant_id,
    principal: input.principal,
    evaluated_at: input.evaluatedAt,
  });
  return governed.decision === "ALLOW"
    && governed.records.some(record =>
      record.content.object_id === input.resource.canonical_object_id);
}