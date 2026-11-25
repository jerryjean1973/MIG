export declare const TERM_NEGOTIABILITY: readonly ["server_mandatory", "client_mandatory", "policy_mandatory", "negotiable", "informational"];
export type TermNegotiability = typeof TERM_NEGOTIABILITY[number];
export declare const CONTRACT_ERROR_CODES: readonly ["CONTRACT_REQUIRED", "CONTRACT_INACTIVE", "CONTRACT_FINGERPRINT_MISMATCH", "CONTRACT_EXPIRED", "CONTRACT_REVOKED", "CONTRACT_NOT_FOUND", "CONTRACT_VERSION_MISMATCH", "CONTRACT_AUTH_RELATIONSHIP_INVALID", "CONTRACT_NONCE_REUSED", "CONTRACT_SIGNATURE_INVALID", "CONTRACT_INTENT_MISMATCH", "CONTRACT_TENANT_MISMATCH", "CONTRACT_CAPABILITY_NOT_COVERED", "CONTRACT_RATE_LIMIT_EXCEEDED", "CONTRACT_SOVEREIGNTY_VIOLATED", "NEGOTIATION_MAX_ROUNDS_EXCEEDED", "NEGOTIATION_GOVERNANCE_WEAKENING", "NEGOTIATION_PRIVILEGE_EXPANSION", "NEGOTIATION_SOVEREIGNTY_VIOLATION", "NEGOTIATION_RESIDENCY_VIOLATION", "NEGOTIATION_CONFIDENTIALITY_VIOLATION", "NEGOTIATION_ELIGIBILITY_DENIED", "MIG_ATTESTATION_FAILED"];
export type ContractErrorCode = typeof CONTRACT_ERROR_CODES[number];
export interface ContractExample {
    example_id: string;
    description: string;
    input_sample: Record<string, unknown>;
    expected_output_shape: Record<string, unknown>;
    scenario: string;
    negotiability?: TermNegotiability;
}
export interface PartialResultRule {
    condition: string;
    min_completeness_pct: number;
    delivery_behavior: "deliver_partial" | "fail_closed" | "buffer_and_retry";
    negotiability: TermNegotiability;
}
export interface RetrySemantics {
    idempotency_key_required: boolean;
    max_retries: number;
    backoff_strategy: "exponential" | "linear" | "fixed" | "none";
    retry_window_seconds: number;
    negotiability: TermNegotiability;
}
export interface ExecutionLimit {
    max_execution_time_ms: number;
    max_payload_bytes: number;
    timeout_behavior: "hard_fail" | "partial_result" | "queue";
    negotiability: TermNegotiability;
}
export interface RateLimit {
    requests_per_minute: number;
    requests_per_day: number;
    burst_allowance: number;
    throttle_behavior: "reject" | "queue" | "delay";
    negotiability: TermNegotiability;
}
export interface SovereigntyRequirement {
    data_residency_regions: string[];
    prohibited_regions: string[];
    cross_border_transfer_allowed: boolean;
    regulatory_frameworks: string[];
    negotiability: TermNegotiability;
}
export interface BreakingChangeRule {
    trigger: string;
    required_action: "immediate_revocation" | "renegotiation" | "notification";
    grace_period_hours: number;
    negotiability: TermNegotiability;
}
export interface NonBreakingChangeRule {
    trigger: string;
    required_action: "notification" | "silent_update" | "renegotiation_optional";
    notification_window_hours: number;
    negotiability: TermNegotiability;
}
export interface FieldMeaningDefinition {
    field_path: string;
    semantic_meaning: string;
    unit?: string;
    value_range?: string;
    negotiability: TermNegotiability;
}
export interface ApprovalRequirement {
    condition: string;
    approver_role: string;
    approval_timeout_hours: number;
    negotiability: TermNegotiability;
}
export interface EvidenceRequirement {
    evidence_type: string;
    required_freshness_hours: number;
    authority_level: "official" | "verified" | "baseline" | "inferred";
    negotiability: TermNegotiability;
}
export interface CapabilitySideEffect {
    side_effect_id: string;
    description: string;
    scope: "tenant" | "global" | "session";
    reversible: boolean;
    negotiability: TermNegotiability;
}
export interface ContractRequestBlock {
    required_fields: Array<{
        field: string;
        type: string;
        negotiability: TermNegotiability;
    }>;
    optional_fields: Array<{
        field: string;
        type: string;
        negotiability: TermNegotiability;
    }>;
    forbidden_fields: string[];
    validation_rules: Array<{
        rule: string;
        negotiability: TermNegotiability;
    }>;
}
export interface ContractResponseBlock {
    /** Additive instructions on new offers; never rewrites active contracts. */
    client_response_protocol?: import("./contracts/mcp-client-response-protocol").McpClientResponseProtocol;
    guaranteed_fields: Array<{
        field: string;
        type: string;
        negotiability: TermNegotiability;
    }>;
    conditional_fields: Array<{
        field: string;
        condition: string;
        negotiability: TermNegotiability;
    }>;
    field_meanings: FieldMeaningDefinition[];
    partial_result_rules: PartialResultRule[];
}
export interface ContractSemanticsBlock {
    idempotency: "full" | "partial" | "none";
    side_effects: CapabilitySideEffect[];
    retry_semantics: RetrySemantics;
    execution_ordering: "sequential" | "parallel_safe" | "unspecified";
    negotiability: TermNegotiability;
}
export interface ContractConstraintsBlock {
    execution_limits: ExecutionLimit;
    rate_limits: RateLimit;
    sovereignty: SovereigntyRequirement;
    approval_requirements: ApprovalRequirement[];
    negotiability: TermNegotiability;
}
export interface ContractDataQualityBlock {
    minimum_signal_count: number;
    evidence_requirements: EvidenceRequirement[];
    confidence_threshold: number;
    stale_data_policy: "reject" | "warn" | "accept";
    negotiability: TermNegotiability;
}
export interface ContractAuthorizationBlock {
    required_classification: "read_only" | "execution" | "admin";
    scope_restrictions: string[];
    tenant_isolation: "strict" | "tenant_aware" | "none";
    mig_attestation_required: boolean;
    negotiability: TermNegotiability;
}
export interface ContractErrorsBlock {
    defined_error_codes: ContractErrorCode[];
    partial_result_rules: PartialResultRule[];
    breaking_change_rules: BreakingChangeRule[];
    non_breaking_change_rules: NonBreakingChangeRule[];
    negotiability: TermNegotiability;
}
export interface MCPCapabilityContract {
    contractId: string;
    contractVersion: number;
    capabilityId: string;
    clientId: string;
    tenantId: string;
    serverIdentity: string;
    negotiationId: string;
    supersedesContractId?: string;
    status: "draft" | "active" | "expired" | "revoked" | "superseded";
    requestContract: ContractRequestBlock;
    responseContract: ContractResponseBlock;
    semantics: ContractSemanticsBlock;
    constraints: ContractConstraintsBlock;
    dataQuality: ContractDataQualityBlock;
    authorization: ContractAuthorizationBlock;
    /**
     * Credential participation boundary supplied by the canonical MIG
     * credential registry. This is descriptive contract material, never
     * caller-provided authority and never a replacement evaluator.
     */
    participationAuthority?: MigCredentialAuthorityProjection;
    errorsAndPartialResults: ContractErrorsBlock;
    examples: ContractExample[];
    fingerprints: ContractFingerprints;
    validFrom: string;
    validUntil: string;
    createdAt: string;
    acceptedByClient?: string;
    acceptedByServer?: string;
}
export interface ContractFingerprints {
    compatibilityFingerprint: string;
    schemaFingerprint: string;
    semanticFingerprint: string;
    constraintFingerprint: string;
    governanceFingerprint: string;
    dataQualityFingerprint: string;
    behaviorFingerprint: string;
}
export interface ContractAuthorizationRelationship {
    relationshipId: string;
    contractId: string;
    contractVersion: number;
    tenantId: string;
    clientId: string;
    capabilityId: string;
    issuedAt: string;
    validUntil: string;
    migAttestation: string;
    status: "active" | "revoked" | "expired";
    attestationFingerprint: string;
}
export interface ContractInvocationEnvelope {
    contractId: string;
    contractVersion: number;
    authorizationRelationshipId: string;
    runtimeAuthorizationId: string;
    intent: string;
    nonce: string;
    signature: string;
    capabilityId?: string;
    tenantId?: string;
    clientId?: string;
}
export interface McpRegistrationHandshakeDeclaration {
    protocolVersion: string;
    capabilities: string[];
    supportsMigLineage: boolean;
    supportsTerminalOutcomes: boolean;
    name?: string;
}
export interface MigCredentialAuthorityProjection {
    credential_class: "AGENT" | "MCP";
    scopes: string[];
    allowed_intents: string[];
    allowed_domains: string[];
    allowed_mcp_targets: string[];
    allowed_capabilities: string[];
    allowed_resources: string[];
    risk_zone_ceiling: "low" | "medium" | "high" | "critical";
    resource_authority_behavior: "persisted_scope_only";
    lineage_required: boolean;
    escalation: "mig_policy_approval_required";
}
export interface MigCredentialAuthorityComparison {
    requested: MigCredentialAuthorityProjection;
    assigned: MigCredentialAuthorityProjection;
}
export interface MigContractPolicyFinding {
    code: string;
    message: string;
    severity: "error" | "warning" | "info";
    field?: string;
}
export interface MigContractPolicyResult {
    allowed: boolean;
    findings: MigContractPolicyFinding[];
    attestationEligible: boolean;
}
