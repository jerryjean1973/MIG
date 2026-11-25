/**
 * server/mig/mig-types.ts
 *
 * Core MIG (MCP Intent Gateway) types. This file is protocol-agnostic:
 * it must never import BRIPe engines, capability registries, or MCP tool
 * definitions. MIG governs identity, intent, capability exposure, and
 * audit only — see server/mig/mig-bripe-adapter.ts for the ONLY place
 * that binds MIG to the BRIPe MCP surface.
 */

import type {
  MigTrustLevel,
  MigRiskZone,
  MigAgentStatus,
  MigRemoteAgent,
  MigIntentDefinition,
  MigTicket,
  MigCapabilityManifest,
} from "@shared/schema";
import type { CBAuthorityOperation } from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";

export type { MigTrustLevel, MigRiskZone, MigAgentStatus };

/** Decoded, unsigned ticket payload (mirrors the signed JWT-like claim set). */
export interface MigTicketPayload {
  jti: string;
  agent_id: string;
  tenant_id: string;
  intent_library_id: string;
  intent_id: string;
  risk_zone: MigRiskZone;
  session_id: string;
  iat: number;
  exp: number;
}

/** A single tool/capability entry exposed by a downstream MCP adapter. */
export interface MigAdapterToolEntry {
  tool_name: string;
  capability_id: string;
  classification: "read_only" | "execution" | "admin";
  risk_zone: MigRiskZone;
  domain_scope: string[];
  /**
   * True only when capability_id resolves to a real entry in the adapter's
   * governance registry (e.g. shared/capability-registry.ts for BRIPe). A
   * capability with no governance contract is never exposed through a
   * manifest, regardless of what an intent/policy would otherwise allow —
   * see mig-manifest.ts buildAndPersistCapabilityManifest.
   */
  has_governance_contract: boolean;
  intent_classes?: Array<"discovery" | "execution" | "administration">;
  semantic_action?: "read" | "execute" | "administer";
  semantic_scopes?: string[];
  resource_types?: string[];
  mutation_class?: "none" | "append_only" | "governed_transition" | "destructive_legacy_blocked";
  sod_class?: "none" | "standard" | "privileged" | "dual_control";
  tenant_mode?: "tenant_bound";
  canonical_service?: string;
  /** Versioned protocol schema advertised by the MCP server. */
  schema_version?: string;
  input_schema?: Record<string, unknown>;
  output_schema?: Record<string, unknown>;
  /** Server-declared producer authority; never sufficient on its own to grant access. */
  producer_declaration?: {
    producer_id: string;
    producer_domain: string;
    service_id: string;
    ownership_proof_ref?: string;
    origin_proof_ref?: string;
  };
  /** Canonical object/resource metadata resolved by the platform, not the caller. */
  canonical_resource?: {
    tenant_id: string;
    partition: "FACT" | "STRUCTURAL_READING" | "DECISION";
    canonical_object_id: string;
    knowledge_id?: string;
    version?: string;
    knowledge_class?: string;
    domain_id?: string;
    sensitivity_class?: string;
  };
  data_contract_id?: string;
  data_contract_version?: string;
  /** Explicit CB operation declaration; absence permits legacy candidate inference only. */
  canonical_operation?: CBAuthorityOperation;
}

/**
 * The abstract contract every protocol adapter (mig-mcp-adapter, and any
 * future non-MCP adapter) must implement. MIG core code depends only on
 * this interface — never on a concrete downstream server.
 */
export interface MigDownstreamAdapter {
  adapter_id: string;
  listTools(): MigAdapterToolEntry[];
  /** Optional server-owned validation view for opaque evidence transport.
   * Must never replace the payload used for authorization hashes or dispatch. */
  authorityAssertionInput?(toolName: string, input: Record<string, unknown>):
    Record<string, unknown> | Promise<Record<string, unknown>>;
  executeTool(toolName: string, input: unknown, ctx: {
    tenantId: string;
    /** Authenticated server context only; never copied from tool arguments. */
    principalId?: string;
    intentId?: string;
  }): Promise<unknown>;
}

export interface MigPolicyResolution {
  allowed_tool_names: string[];
  denied_tool_names: string[];
  allowed_capability_ids: string[];
  suppressed_capability_ids: string[];
  risk_zone: MigRiskZone;
  requires_human_approval: boolean;
  denial_reasons: Record<string, string>;
}

export interface MigManifestResult {
  manifest: MigCapabilityManifest;
  policy: MigPolicyResolution;
}

export interface MigAuthorizationContext {
  agent: MigRemoteAgent;
  ticketPayload: MigTicketPayload;
  ticketRow: MigTicket;
  intent: MigIntentDefinition;
}

export type {
  VerifiedCredentialIdentity,
  MigAuthorizationRequest,
  MigNormalizedAuthorizationContext,
} from "./mig-authorization-context";
export type {
  MigEffectiveEntitlement,
  MigAuthorizationDecision,
  MigTenantAuthorizationPolicy,
} from "./mig-authorization-policy";
export type { AuthorityProvider, AuthorityProviderInput } from "./mig-authority-provider";
export type {
  MigObservationSourceV1, MigEvidenceRegime, MigEvidenceQuality, MigExternalExecutionEventV1,
  MigCorrelationEvidenceV1, MigCorrelationStatus, MigNormalizedCapabilityV1, MigFactualEdgeV1,
  MigObservedJourneyVersionV1, MigObservationFindingV1, MigOperatingMode, MigCustomerOutcomeV1,
  MigObservationStructuralDecisionV1, MigObservationProofReferenceV1,
} from "./mig-observation-types";

export type MigDecision = "allow" | "deny" | "drift_blocked";

export type MigDeploymentMode = "full_control_plane" | "enterprise_intelligence_plane";
export type MigExecutionStrategy = "native_execute" | "external_decision_only";
export type MigExternalDecision = "ALLOW" | "CONSTRAIN" | "ESCALATE" | "STOP";

export interface MigJourneyEvaluationResult {
  decision: MigExternalDecision;
  reason: string;
  deployment_mode: MigDeploymentMode;
  journey_state: "COOL" | "WARM" | "HOT" | "CRITICAL";
  journey_id: string;
  call_id: string;
  authority: {
    provider: "mig_native" | "microsoft_entra";
    reference: string;
    snapshot_id?: string;
  };
  decision_proof_ref: string;
  structural_decision_ref?: string;
  control_ref?: string;
  payload_hash: string;
}

export interface MigGateResult<T = unknown> {
  decision: MigDecision;
  reason: string;
  transition_proof_id?: string;
  authorization_manifest_id?: string;
  data?: T;
}
