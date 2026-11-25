export const CB_AUTHORITY_PARTITIONS = ["FACT", "STRUCTURAL_READING", "DECISION"] as const;

export type CBAuthorityPartition = (typeof CB_AUTHORITY_PARTITIONS)[number];

export const CB_AUTHORITY_OPERATIONS = ["DECLARE", "READ", "REFERENCE", "SUPERSEDE", "REVOKE", "EXPORT"] as const;

export type CBAuthorityOperation = (typeof CB_AUTHORITY_OPERATIONS)[number];

export type CBAuthorityDecision = "ALLOW" | "DENY";

export interface CanonicalKnowledgeResource {
  tenant_id: string;
  partition: CBAuthorityPartition;
  canonical_object_id: string;
  knowledge_id?: string;
  version?: string;
  knowledge_class?: string;
  domain_id?: string;
  sensitivity_class?: string;
  data_contract_id?: string;
  data_contract_version?: string;
  producer_domain?: string;
}

export interface CanonicalKnowledgePrincipal {
  principal_id: string;
  tenant_id: string;
  /** Calling governed route identity, included in the value-free receipt. */
  service_id?: string;
  access_path?: string;
  role_ids?: string[];
  group_ids?: string[];
  intent_id: string;
  capability_ids?: string[];
}

export type CBMCPBindingEffect = CBAuthorityOperation | "COMPUTATION_ONLY";

export interface CanonicalKnowledgeAuthorityDecision {
  decision: CBAuthorityDecision;
  reason: string;
  policy_id?: string;
  resource: CanonicalKnowledgeResource;
  operation: CBAuthorityOperation;
  policy_version?: string;
  inheritance_path?: string[];
  producer_authorized?: boolean;
  principal_authorized?: boolean;
}

export function canonicalKnowledgeResourceRef(resource: CanonicalKnowledgeResource): string {
  assertCanonicalKnowledgeResource(resource);
  return `cb:${resource.tenant_id}:${resource.partition}:${resource.canonical_object_id}${resource.version ? `@${resource.version}` : ""}`;
}

export function isCanonicalKnowledgeResourceRef(value: string): boolean {
  return /^cb:[^:]+:(FACT|STRUCTURAL_READING|DECISION):[^@]+(?:@.+)?$/.test(value);
}

export function resolveTrustedCanonicalKnowledgeResource(input: {
  authenticated_tenant_id: string;
  requested_tenant_id?: string;
  resource_ref: string;
  resource: CanonicalKnowledgeResource;
}): CanonicalKnowledgeResource {
  assertCanonicalKnowledgeResource(input.resource);
  if (input.authenticated_tenant_id !== input.resource.tenant_id
      || (input.requested_tenant_id !== undefined && input.requested_tenant_id !== input.authenticated_tenant_id)) {
    throw new Error("CB_KNOWLEDGE_TENANT_MISMATCH");
  }
  if (input.resource_ref !== canonicalKnowledgeResourceRef(input.resource)) {
    throw new Error("CB_KNOWLEDGE_RESOURCE_REFERENCE_CONFLICT");
  }
  return Object.freeze({ ...input.resource });
}

export function assertCanonicalKnowledgeJourneyNarrowing(
  parent: CanonicalKnowledgeAuthorityDecision,
  child: CanonicalKnowledgeAuthorityDecision,
): void {
  if (parent.decision !== "ALLOW" && child.decision === "ALLOW") {
    throw new Error("CB_KNOWLEDGE_JOURNEY_AUTHORITY_ESCALATION");
  }
  if (parent.resource.tenant_id !== child.resource.tenant_id
      || parent.resource.partition !== child.resource.partition
      || parent.resource.canonical_object_id !== child.resource.canonical_object_id
      || parent.operation !== child.operation) {
    throw new Error("CB_KNOWLEDGE_JOURNEY_RESOURCE_EXPANSION");
  }
  if (parent.resource.version && child.resource.version !== parent.resource.version) {
    throw new Error("CB_KNOWLEDGE_JOURNEY_VERSION_EXPANSION");
  }
}

export function assertCanonicalKnowledgeResource(resource: CanonicalKnowledgeResource): void {
  if (!resource.tenant_id?.trim() || !resource.canonical_object_id?.trim()) {
    throw new Error("CB_KNOWLEDGE_CANONICAL_RESOURCE_REQUIRED");
  }
  if (!CB_AUTHORITY_PARTITIONS.includes(resource.partition)) {
    throw new Error("CB_KNOWLEDGE_PARTITION_INVALID");
  }
}

export interface CanonicalMCPKnowledgeBinding {
  binding_id: string;
  tenant_id: string;
  mcp_server_id: string;
  mcp_tool_name: string;
  mcp_schema_version: string;
  /** Exact canonical fingerprint of the endpoint tool schema at discovery. */
  schema_fingerprint: string;
  producer_id: string;
  producer_domain: string;
  service_id: string;
  capability_id: string;
  partition: CBAuthorityPartition;
  canonical_object_id: string;
  knowledge_id?: string;
  resource_version?: string;
  knowledge_class?: string;
  domain_id?: string;
  sensitivity_class?: string;
  data_contract_id?: string;
  data_contract_version?: string;
  effect: CBMCPBindingEffect;
  operation?: CBAuthorityOperation;
  route_constraints: string[];
  intent_constraints: string[];
  capability_constraints: string[];
  derivation_evidence: string[];
  status: CBMCPBindingStatus;
  binding_version: string;
  supersedes_binding_id?: string;
  confirmation_lineage: string[];
  effective_from: string;
  effective_to?: string;
}

export type CBMCPBindingStatus = "INFERRED" | "CONFIRMED" | "OVERRIDDEN" | "REVOKED";
