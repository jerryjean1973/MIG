/**
 * Vendor-neutral observation contracts.  These are evidence contracts, not
 * authority contracts: no field supplied by an observer establishes identity,
 * entitlement, intent, parentage, or a factual relationship.
 */
import type { CanonicalSignalV1 } from "../../shared/contracts/bripe-execution-v1";
export const MIG_OBSERVATION_SCHEMA_VERSION = "mig.observation.v1" as const;
export type MigUnknown = "UNKNOWN" | "INSUFFICIENT";
export type MigEvidenceRegime = "NATIVE_GOVERNED" | "ENTERPRISE_ATTESTED" | "EXTERNAL_OBSERVED" | "UNKNOWN";
export type MigEvidenceQuality = "VERIFIED" | "ATTESTED" | "PARTIAL" | "UNVERIFIED" | "INSUFFICIENT" | "UNKNOWN";
export type MigCorrelationStatus = "CORRELATED" | "UNCORRELATED_AMBIGUOUS" | "UNCORRELATED_INSUFFICIENT";
export type MigOperatingMode = "observe";

export interface MigObservationSourceV1 {
  source_id: string;
  source_kind: string;
  regime: MigEvidenceRegime;
  quality: MigEvidenceQuality;
}
export interface MigCorrelationEvidenceV1 {
  kind: "trace_id" | "journey_id" | "session_id" | "call_correlation_id";
  value: string;
  exact: boolean;
}
export interface MigNormalizedCapabilityV1 {
  tool_name: string;
  capability_id: string;
  canonical_service: string;
  semantic_action: "read" | "execute" | "administer";
}
export interface MigFactualEdgeV1 {
  from_ref: string;
  to_ref: string;
  relation: string;
  evidence_refs: string[];
  status: "FACTUAL" | "UNKNOWN" | "INSUFFICIENT";
}
export interface MigExternalExecutionEventV1 {
  schema_version: typeof MIG_OBSERVATION_SCHEMA_VERSION;
  event_id: string;
  idempotency_key: string;
  occurred_at: string;
  source: MigObservationSourceV1;
  /** Listener-stamped observation lineage, not a BAL signal or analytical domain. */
  fusion_feed?: {
    organization_id: string;
    source_family: "CYBER" | "FRAUD" | "PHYSICAL_ACCESS";
    listener_id: "listen_cyber_observation" | "listen_fraud_observation" | "listen_physical_access_observation";
    ingestion_id: string;
    source_event_type: string;
    evidence_class: "UNVERIFIED_OBSERVATION";
    raw_evidence_reference: string;
  };
  tool_name?: string;
  mcp_ref?: string;
  resource_refs?: string[];
  outcome?: string | MigUnknown;
  correlation?: MigCorrelationEvidenceV1[];
  factual_edges?: MigFactualEdgeV1[];
  /** Canonical structural evidence supplied by the connector, rebound to this event on admission. */
  normalized_evidence?: CanonicalSignalV1[];
  /** Opaque source envelope retained as evidence, never interpreted as authority. */
  envelope?: Record<string, unknown>;
}
export interface MigObservedJourneyVersionV1 {
  journey_version_id: string;
  observed_journey_id: string;
  version: number;
  supersedes_journey_version_id?: string;
  correlation_status: MigCorrelationStatus;
  event_refs: string[];
  mcp_refs: string[];
  capabilities: MigNormalizedCapabilityV1[];
  resource_refs: string[];
  outcome_refs: string[];
  factual_edge_refs: string[];
  evidence_quality: MigEvidenceQuality;
}
export interface MigObservationFindingV1 {
  finding_id: string;
  observed_journey_version_id: string;
  status: "OBSERVED" | "INSUFFICIENT_EVIDENCE";
  would_have_denied: boolean | "UNKNOWN";
  structural_decision_ref?: string;
  proof_ref?: string;
  evidence_refs: string[];
}
export interface MigObservationStructuralDecisionV1 {
  structural_decision_id: string;
  observed_journey_version_id: string;
  enforcement: "ALLOW" | "ALLOW_WITH_CONTROL" | "REQUIRE_APPROVAL" | "BLOCK";
  reason: string;
  canonical_request_ref: string;
  evidence_refs: string[];
}
export interface MigObservationProofReferenceV1 {
  proof_reference_id: string;
  structural_decision_id: string;
  proof_ref: string;
  evidence_refs: string[];
}
export interface MigCustomerOutcomeV1 {
  outcome_id: string;
  observed_journey_version_id?: string;
  outcome: string | MigUnknown;
  evidence_refs: string[];
}