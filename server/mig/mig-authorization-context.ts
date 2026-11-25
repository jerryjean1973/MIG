/**
 * Canonical trusted authorization context. Boundary adapters populate only
 * verified identity references; client claims such as roles, scopes, tenant,
 * and principal IDs are deliberately not accepted.
 */
import type { MigCredentialType, MigPrincipalStatus, MigPrincipalType } from "@shared/schema";
import type { CanonicalKnowledgeAuthorityDecision, CanonicalKnowledgeResource, CBAuthorityOperation } from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";
import type { CanonicalMCPKnowledgeBinding } from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";

export interface VerifiedCredentialIdentity {
  credentialRef: string;
  credentialType: MigCredentialType;
  principalId: string;
  tenantId: string;
  principalType: MigPrincipalType;
  principalStatus: MigPrincipalStatus;
  credentialStatus: MigPrincipalStatus;
  credentialCapabilityCeiling: string[];
  credentialScopes?: string[];
  credentialIntentCeiling?: string[];
  credentialDomainCeiling?: string[];
  credentialMcpTargetCeiling?: string[];
  credentialResourceCeiling?: string[];
  credentialRiskZoneCeiling?: "low" | "medium" | "high" | "critical";
  /** External verifier ceiling; omitted for legacy/native credentials. */
  credentialActionCeiling?: "read" | "execute" | "administer";
  /** Trusted authentication/delegation provenance, never copied from request body. */
  actorPrincipalId?: string;
  clientPrincipalId?: string;
  executorPrincipalId?: string;
  authorityProvider?: "mig_native" | "microsoft_entra";
  authorityRef?: string;
  authoritySnapshotId?: string;
  authoritySourceEvidence?: string[];
  authorityObservedAt?: Date;
  authorityExpiresAt?: Date;
  /** External-provider role projection after governed claim mapping. */
  authorityAssignedRoles?: string[];
  agentId?: string;
}

export interface MigAuthorizationRequest {
  actorPrincipalId?: string;
  clientPrincipalId?: string;
  executorPrincipalId?: string;
  intentId: string;
  capabilityId: string;
  semanticAction: "read" | "execute" | "administer";
  domainId: string;
  resourceRef: string;
  resourceVersion?: string;
  resourceState?: string;
  /** Requested target only; it is never copied into credential authority. */
  mcpTargetId?: string;
  requestCorrelationId?: string;
  delegationRef?: string;
  beforeHash?: string;
  afterHash?: string;
  transaction?: { createdByPrincipalId?: string; subjectPrincipalId?: string; governedKind?: string };
  /** Populated only by a trusted canonical-resource resolver, never by route aliases. */
  canonicalKnowledge?: {
    resource: CanonicalKnowledgeResource;
    operation: CBAuthorityOperation;
    authority?: CanonicalKnowledgeAuthorityDecision;
    authority_state?: "DEFERRED_TO_PROTECTED_DISPATCH";
  };
  /** Exact server-resolved MCP binding; never populated from a caller alias. */
  canonicalKnowledgeBinding?: CanonicalMCPKnowledgeBinding;
}

export interface MigNormalizedAuthorizationContext extends MigAuthorizationRequest {
  tenantId: string;
  credential: VerifiedCredentialIdentity;
}

/** No arbitrary request claims are copied into the normalized context. */
export function normalizeAuthorizationContext(
  credential: VerifiedCredentialIdentity | undefined,
  request: MigAuthorizationRequest,
): { context?: MigNormalizedAuthorizationContext; reason?: string } {
  if (!credential) return { reason: "unknown_credential" };
  if (!credential.credentialRef || !credential.principalId || !credential.tenantId) return { reason: "incomplete_verified_identity" };
  if (credential.principalStatus !== "active") return { reason: "principal_not_active" };
  if (credential.credentialStatus !== "active") return { reason: "credential_not_active" };
  if (!request.intentId || !request.capabilityId || !request.semanticAction || !request.domainId || !request.resourceRef) return { reason: "incomplete_authorization_request" };
  return {
    context: {
      ...request, tenantId: credential.tenantId, credential,
      // Do not trust identity fields carried in a request. A verifier may
      // provide delegation provenance on the verified credential instead.
      actorPrincipalId: credential.actorPrincipalId ?? credential.principalId,
      clientPrincipalId: credential.clientPrincipalId,
      executorPrincipalId: credential.executorPrincipalId ?? credential.principalId,
    },
  };
}