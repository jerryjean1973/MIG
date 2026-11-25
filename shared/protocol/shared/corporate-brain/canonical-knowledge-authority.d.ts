export declare const CB_AUTHORITY_PARTITIONS: readonly ["FACT", "STRUCTURAL_READING", "DECISION"];
export type CBAuthorityPartition = (typeof CB_AUTHORITY_PARTITIONS)[number];
export declare const CB_AUTHORITY_OPERATIONS: readonly ["DECLARE", "READ", "REFERENCE", "SUPERSEDE", "REVOKE", "EXPORT"];
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
export interface CanonicalKnowledgeAuthorityReceipt {
    receipt_id: string;
    tenant_id: string;
    principal_id: string;
    service_id: string;
    intent_id: string;
    access_path: string;
    capability_id: string;
    resource_version: string | null;
    operation: CBAuthorityOperation;
    partition: CBAuthorityPartition;
    canonical_object_id: string;
    knowledge_id?: string;
    policy_id: string | null;
    policy_version: string | null;
    inheritance_path: string[];
    capability_intersection: string[];
    effective_ceilings: string[];
    decision: CBAuthorityDecision;
    reason: string;
    evaluated_at: string;
    /** Value-free intersection evidence; each subsystem is independently evaluated. */
    route_result?: "ALLOW" | "DENY";
    mig_result?: "ALLOW" | "DENY";
    corporate_brain_result?: "ALLOW" | "DENY";
    ownership_result?: "ALLOW" | "DENY";
    sensitivity_result?: "ALLOW" | "DENY";
    data_contract_result?: "ALLOW" | "DENY";
    binding_id?: string | null;
    binding_version?: string | null;
    mcp_server_id?: string | null;
    mcp_tool_name?: string | null;
    mcp_schema_version?: string | null;
    effective_intersection?: string[];
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
