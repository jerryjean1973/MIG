import { type StructuralPriorComposition } from "../protocol/shared/contracts/structural-prior-composition";

import type { CSSLDecisionContext } from "../protocol/shared/contracts/cssl-decision-context";

import type { ProjectionReconstructionBinding } from "../protocol/shared/corporate-brain/projection-request";

import { type PackageExecutionBindingV1 } from "../protocol/shared/corporate-brain/package-execution-binding";

import { type RealitySelectionIdentity } from "../protocol/shared/corporate-brain/morpheus-reality-selection";

import { type ImmutableRealitySelection } from "../protocol/shared/bripe/immutable-reality-selection";

import { type RippleOSINTRealitySelectionV1 } from "../protocol/shared/ripple/osint-reality-selection";

import { type VSOCDemoRealitySelectionV1 } from "../protocol/shared/ripple/vsoc-demo-reality-selection";

import { type CBKnowledgeOrigin } from "../protocol/shared/corporate-brain/cb-knowledge-origin-contract";

export interface CanonicalObservation {
  observation_id:    string;
  observation_type:  string;
  /** Product origin: "vendorgate" | "pra" | "ripple" | ... */
  source_product:    string;
  entity_id:         string;
  entity_name:       string;
  observed_at:       string;
  evidence_ref:      string;
  payload:           Record<string, unknown>;
  confidence:        number;
  limitations:       string[];
}

export interface KAOCoverageRecord {
  domain_id:           string;
  kao_id:              string;
  satisfied:           boolean;
  confidence:          number;
  evidence_source_ids: string[];
  computed_at:         string;
}

export interface KAOCoverage {
  records:              KAOCoverageRecord[];
  overall_satisfied:    boolean;
  unsatisfied_kao_ids:  string[];
  coverage_score:       number;  // 0–1
}

export interface ContradictionRecord {
  contradiction_id:   string;
  signal_id_a:        string;
  signal_id_b:        string;
  contradiction_type: "value_conflict" | "temporal_conflict" | "source_conflict";
  detail:             string;
  resolution:         "a_wins" | "b_wins" | "both_suppressed" | "unresolved";
}

export interface QualifiedEvidence {
  evidence_id:     string;
  source_type:     string;
  source_key:      string;
  collected_at:    string;
  confidence:      number;
  entity_id:       string;
  payload_summary: string;
}

export interface DecisionConstraint {
  constraint_id:   string;
  constraint_type: "output_scope" | "confidence_floor" | "domain_restriction" | "temporal_bound";
  detail:          string;
  blocks_output_ids: string[];
}

export type BRIPeExecutionMode = "real" | "demo" | "replay" | "test";

export interface CanonicalSignalV1 {
  /** Priors and missingness have separate envelopes; neither may masquerade as a signal/fact. */
  epistemic_kind?: "OBSERVED_EVIDENCE" | "DERIVED_STATE";
  signal_id: string;
  type: string;
  entity: string;
  system: string;
  timestamp: string;
  value: {
    severity: number;
    [key: string]: unknown;
  };
  /**
   * Producer-supplied evidence support for this exact normalized proposition,
   * subject and applicable time. Not severity, cause, persistence, extraction/
   * capture quality, path/EQL or result confidence. Historical producer values
   * retain their existing interpretation; new governed qualifications bind the
   * versioned signal-proposition-evidence-support.v1 receipt separately.
   * Unknown is NOT representable here: withhold upstream, never default it.
   */
  confidence: number;
  source: string;
  source_key: string;
  evidence_id: string;
  signal_category: string;
  dependency_group: string;
  region: string | null;
  jurisdiction: string | null;
  limitations: string[];
  completeness: true;
  /** Required for every signal entering a real production execution. */
  knowledge_origin?: CBKnowledgeOrigin;
}

export interface CanonicalBRIPeExecutionInputV1 {
  /** Package-owner composed priors, separate from observed ESSG signals and evidence. */
  structural_prior_composition?: StructuralPriorComposition;
  schema_version: "bripe.execution.v1";
  request_id: string;

  /**
   * CB Phase 3 — Tenant identifier for this execution run.
   *
   * Required for Corporate Brain snapshot hydration: the orchestrator uses
   * this value to look up the snapshot in the correct tenant partition.
   * When absent, the orchestrator falls back to DEFAULT_TENANT_ID, which
   * causes CB snapshots for non-default tenants to be inaccessible.
   *
   * Callers MUST supply this field when using multi-tenant deployments.
   * Single-tenant deployments may omit it (DEFAULT_TENANT_ID applied automatically).
   */
  tenant_id?: string;
  /** MIG projection binding; descriptive evidence, never caller authority. */
  intent_access_projection_id?: string;
  intent_access_path_fingerprint?: string;
  intent_access_payload_hash?: string;

  /**
   * CB §18 — ESSG snapshot reference.
   *
   * Optional in V1 for backward compatibility during the migration window.
   * Required in V2 (CanonicalBRIPeExecutionInputV2).
   *
   * When present: the BRIPe gate validates the snapshot ID format and the
   * execution gate hydrates signals from the snapshot rather than .signals[].
   *
   * When absent: a deprecation warning is emitted; .signals[] is used as-is.
   * Callers MUST migrate to providing an essg_snapshot_id before the
   * "Producer and consumer compliance sweep" task removes the fallback.
   */
  essg_snapshot_id?: string;

  /**
   * Non-scoreable projection reconstruction identity and exact ESSG
   * consumption receipt. This context is validated and hashed with the
   * canonical request; it is never converted into an engine signal.
   */
  non_scoreable_context?: {
    projection_reconstruction_binding?: ProjectionReconstructionBinding;
    /** Exact native package/source context; not an execution or evidence grant. */
    package_execution_binding?: PackageExecutionBindingV1;
    /** Independently sealed observation source joined into this ESSG population, if any. */
    observation_snapshot_id?: string | null;
    /** Persisted BAL/ESC admission proof reloaded for the exact observation source. */
    bal_source_admission_receipt_id?: string | null;
    bal_source_admission_receipt_hash?: string | null;
    consumption_receipt: CanonicalBRIPeConsumptionReceiptV1;
  };

  /**
   * CB Phase 5 — Corporate Brain snapshot reference (CB Law 8). REQUIRED.
   *
   * ID of the CorporateBrainSnapshot assembled by produceCBSnapshot() that
   * BRIPe should reason from. The snapshot is the sole data contract between
   * CB and BRIPe; BRIPe MUST NOT query product DB tables directly.
   *
   * Required as of Phase 5. Every BRIPe execution entry point MUST:
   *   1. Call produceCBSnapshotForExecution() before execution to obtain the ID.
   *   2. Pass the resulting snapshot_id here before calling the BRIPe orchestrator.
   *
   * When absent at runtime, the CB snapshot hydrator throws CBSnapshotRequiredError,
   * which hard-blocks BRIPe execution (Phase 5 enforcement).
   *
   * Obtain via: produceCBSnapshotForExecution() in server/bripe/cb-snapshot-hydrator.ts
   *
   * Note: Callers that construct the envelope before calling produceCBSnapshotForExecution
   * (which mutates the envelope to set this field) may initialize with "" as a sentinel —
   * produceCBSnapshotForExecution will replace it with the real snapshot ID before execution.
   */
  cb_snapshot_id: string;

  /**
   * Morpheus reality-selection identity (Articles 54–64).
   *
   * Optional only for legacy/non-reality executions. When supplied it is
   * validated fail-closed before BRIPe can reason about a claimed reality.
   */
  reality_selection?: RealitySelectionIdentity | null;

  /**
   * Required immutable execution boundary for all new canonical runs. It binds
   * this envelope to one subject, one Morpheus reality, verified snapshots,
   * an evidence boundary, and derivation lineage.
   */
  immutable_reality_selection?: ImmutableRealitySelection | null;
  /** Ripple-owned external observation reality; never an enterprise reality claim. */
  osint_reality_selection?: RippleOSINTRealitySelectionV1 | null;
  /** Only a sealed synthetic exercise; cannot claim Morpheus enterprise authority. */
  demo_reality_selection?: VSOCDemoRealitySelectionV1 | null;

  /**
   * CB v2.1 — CSSL decision context (governed historical structural signal memory).
   *
   * LAYER SEPARATION DOCTRINE (CB v2.1):
   *   ESSG maintains current enterprise structural reality.
   *   CSSL maintains governed historical structural signal memory.
   *   BRIPe reasons across both to produce decision-specific structural intelligence.
   *
   * Optional for backward compatibility.  When absent, BRIPe proceeds in degraded
   * temporal mode — it cannot distinguish transient spikes from structurally durable
   * conditions.  The `cssl_coverage` field records this for pipeline accountability.
   *
   * Obtain via getCSSLContextForDecision() or enrichBRIPeInputWithCSSL()
   * (server/constitution/cssl/CSSLDecisionQuery.ts).
   */
  cssl_context?: CSSLDecisionContext;

  /**
   * CB v2.1 — CSSL coverage status for this execution run.
   *
   * Set by enrichBRIPeInputWithCSSL() or by the BRIPe orchestrator.
   * Recorded in the PipelineRunLedger for accountability.
   *
   *   "present"  — CSSLDecisionContext with ≥5 capabilities was attached.
   *   "degraded" — CSSLDecisionContext attached but <5 capabilities have data.
   *   "absent"   — No CSSL context; BRIPe proceeds without historical memory.
   *
   * When absent or undefined, treated as "absent" downstream.
   */
  cssl_coverage?: "present" | "absent" | "degraded";

  /**
   * External threat intelligence context — observations from free/public threat sources.
   *
   * When present, BRIPe orchestrator step 7.1 calls computeAttackerPressureProfile()
   * with these observations and org_context, then adjusts CALIBRA stage_delay_ratio
   * accordingly (higher attacker pressure → faster expected timeline → more urgent posture).
   *
   * Populated by callers that run the vendor-osint-evidence-fetcher before executing BRIPe.
   * Optional — absent on runs where no OSINT scan precedes execution; step 7.1 is no-op.
   *
   * Threading path:
   *   EnterpriseObservationBundle → _buildCanonicalExecutionInput →
   *   CanonicalBRIPeExecutionInputV1 → canonicalEnvelopeToBRIPeInput → BRIPeInput
   */
  external_threat_context?: {
    observations: import("../protocol/shared/external-threat/external-threat-observation").ExternalThreatObservation[];
    org_context:  import("../protocol/shared/external-threat/org-structural-context").OrgStructuralContext;
  };

  request_source: {
    source_type: "ui" | "api" | "worker" | "replay";
    surface: string;
    route?: string;
    component?: string;
    submitted_at: string;
  };

  execution_mode: BRIPeExecutionMode;

  entity: {
    entity_id: string;
    entity_name: string;
    entity_type:
      | "organization"
      | "asset"
      | "vendor"
      | "product"
      | "market"
      | "person"
      | "location";
    domain_hints: string[];
    region: string | null;
    jurisdiction: string | null;
  };

  trace: {
    origin:
      | "bal"
      | "self_assessment_adapter"
      | "historical_replay"
      | "imported_evidence"
      | "ripple_news_live"
      | "prospect_dsp_adapter"
      | "safemerge_arch_viability_tool";
    collection_path: "canonical_orchestrator";
    bal_entrypoint: string;
    adapter: string;
    provenance_required: true;
  };

  context: {
    requested_outputs: string[];
    requested_contexts: string[];
    constraints?: Record<string, unknown>;
    /** Enterprise objective semantics and evidence; never translated into score signals. */
    enterprise_dsp?: import("../protocol/shared/contracts/enterprise-dsp").EnterpriseDSPRequest;
  };

  domain_profile: {
    domain_id: string;
    archetype: string;
    archetype_source: "bdl" | "deterministic" | "openai_candidate_validated";
    confidence: number;
    limitations: string[];
  };

  evidence_summary: {
    evidence_record_ids: string[];
    source_count: number;
    verified_source_count: number;
    demo_source_count: number;
    proxy_source_count: number;
    limitations: string[];
  };

  /**
   * Production-owned demo package provenance. Forbidden in real execution mode.
   */
  demo_provenance?: {
    package_id: string;
    package_version: string;
    source_label: string;
    evidence_usage: "demo_only";
  };

  signals: CanonicalSignalV1[];

  owner_layer_outputs?: {
    soil?: { status: "present" | "not_required"; ontology_mappings?: unknown[] };
    mesm?: { status: "present" | "not_required"; entity_scope?: unknown };
    bdl?: {
      status: "present" | "not_required";
      business_derivations?: unknown;
      formula_version?: string | null;
    };
    csp?: {
      status: "present" | "not_required";
      positioning?: unknown;
      survivability_context?: unknown;
    };
  };

  replay?: {
    enabled: boolean;
    cutoff_date: string | null;
    forecast_snapshot_id: string | null;
    actual_outcome_hidden: boolean;
    /** Historical request purpose, never evidence or certification authority. */
    projection_mode?: "FORECAST" | "CERTIFY";
    original_execution_ref?: string;
    original_result_hash?: string;
  };

  /**
   * CB §20 — Dual-dimension enterprise memory snapshot.
   *
   * When present, carries BOTH constitutional BRIPe context dimensions:
   *   (a) semanticContext  — canonical entities + relationships from ESSG/CEO
   *   (b) structuralState  — domain definitions + per-scope domain states
   *
   * These two dimensions allow BRIPe structural conditions to trace back to:
   *   - the semantic objects (entities) whose state was breached
   *   - the structural domains whose measured value drove the condition
   *
   * When absent: a deprecation warning is logged (non-blocking). BRIPe
   * proceeds without dual-context traceability.  Callers should migrate to
   * providing this field by calling buildEnterpriseSnapshotForExecution()
   * in server/services/essg-snapshot-service.ts.
   *
   * Obtain via: buildEnterpriseSnapshotForExecution(tenantId) in
   * server/services/essg-snapshot-service.ts.
   */
  enterpriseMemorySnapshot?: import("../protocol/shared/bripe/enterprise-memory-snapshot").EnterpriseMemorySnapshot;

  // ── CB §3011 — Producer-to-BRIPe normalization fields ─────────────────────

  /**
   * Canonical observations submitted by the product adapter before
   * signal extraction.  submitEnterpriseObservations() populates this.
   * When present, the gate validates observation-to-signal traceability.
   */
  observations?: CanonicalObservation[];

  /**
   * Reference to the Domain Constitution that governs this execution.
   * Populated by submitEnterpriseObservations() from KAO_REGISTRY lookup.
   * The domain_id must match a registered DomainConstitutionV1.
   */
  domain_constitution?: {
    domain_id:           string;
    version:             string;
    kao_ids_required:    string[];
    permitted_output_ids:    string[];
    prohibited_output_ids:   string[];
  };

  /**
   * KAO coverage computed from observations before execution.
   * Used by BRIPeReadinessGate to determine permitted outputs.
   */
  kao_coverage?: KAOCoverage;

  /**
   * Server-issued Corporate Brain knowledge-resolution receipt authorizing the
   * exact governed facts reused by this execution. Control-dependent outputs
   * such as DEP remain prohibited unless their satisfied KAO evidence IDs are
   * selected by an exact REUSE scope in this receipt.
   */
  knowledge_resolution_receipt?: import("../protocol/shared/corporate-brain/canonical-object-model").KnowledgeResolutionReceipt;

  /**
   * Signal contradictions detected during observation canonicalization.
   * BRIPe uses these to suppress or flag contradicted structural conditions.
   */
  contradictions?: ContradictionRecord[];

  /**
   * Qualified evidence records assembled from observations.
   * Provides a provenance chain from raw product data to BRIPe signals.
   */
  evidence?: QualifiedEvidence[];

  /**
   * Active decision constraints for this execution.
   * Constraints may restrict which outputs BRIPe is permitted to emit.
   */
  constraints?: DecisionConstraint[];

  /**
   * Deterministic lineage token computed from observations + domain_constitution.
   * Same inputs always produce the same token, enabling reproducibility checks.
   * Format: "lineage_{8-char-hex}_{domain_id}"
   */
  lineage_token?: string;
}

export interface CanonicalBRIPeConsumptionReceiptV1 {
  contract_version: "cb.canonical-consumption.v1";
  essg_snapshot_id: string;
  essg_snapshot_hash: string;
  consumed_signal_ids: string[];
  consumed_entity_ids: string[];
  consumed_relationship_ids: string[];
  /** Exact canonical request payload excluding only its non-scoreable receipt extension. */
  canonical_input_payload: Omit<CanonicalBRIPeExecutionInputV1, "non_scoreable_context">;
  canonical_input_hash: string;
}

export type BRIPeEnvelopeViolationCode =
  | "STRUCTURAL_PRIOR_INVALID"
  | "SCHEMA_VERSION_MISSING"
  | "REQUEST_ID_MISSING"
  | "REQUEST_SOURCE_MISSING"
  | "ENTITY_MISSING"
  | "TRACE_ORIGIN_MISSING"
  | "TRACE_COLLECTION_PATH_INVALID"
  | "PROVENANCE_REQUIRED_NOT_TRUE"
  | "DOMAIN_PROFILE_MISSING"
  | "SIGNALS_NOT_ARRAY"
  | "SIGNAL_MISSING_EVIDENCE_ID"
  | "SIGNAL_MISSING_TIMESTAMP"
  | "SIGNAL_MISSING_SOURCE_KEY"
  | "SIGNAL_COMPLETENESS_NOT_TRUE"
  | "SIGNAL_VALUE_SEVERITY_MISSING"
  | "NON_SCOREABLE_CONSUMPTION_CONTEXT_INVALID"
  | "REAL_MODE_SIGNAL_ORIGIN_UNAUTHORIZED"
  | "REAL_MODE_ZERO_VERIFIED_SOURCES"
  | "REAL_MODE_DEMO_SOURCES_PRESENT"
  | "REAL_MODE_DEMO_PROVENANCE_PRESENT"
  | "DEMO_MODE_PROVENANCE_MISSING"
  | "DEMO_MODE_PROVENANCE_INVALID"
  | "DEMO_MODE_ZERO_DEMO_SOURCES"
  | "DEMO_MODE_NON_DEMO_SOURCES_PRESENT"
  | "REAL_MODE_PROXY_SOURCES_PRESENT"
  | "ARCHETYPE_SOURCE_UNVALIDATED_OPENAI"
  | "REPLAY_MISSING_CUTOFF_DATE"
  | "REPLAY_OUTCOME_NOT_HIDDEN"
  // ── CB §18: ESSG snapshot enforcement ────────────────────────────────────
  // V2-only hard-fail: BRIPeExecutionInputV2 requires essg_snapshot_id.
  // V1 callers should migrate using wrapLegacySignalsWithSnapshotShim().
  | "ESSG_SNAPSHOT_ID_MISSING"
  | "ESSG_SNAPSHOT_ID_FORMAT_INVALID"
  // ── CB Phase 5: CB snapshot enforcement ───────────────────────────────────
  // Hard requirement as of Phase 5. All BRIPe execution entry points must
  // supply a cb_snapshot_id obtained via produceCBSnapshotForExecution().
  | "CB_SNAPSHOT_ID_MISSING"
  | "REALITY_SELECTION_INVALID"
  | "IMMUTABLE_REALITY_SELECTION_INVALID"
  | "ENTERPRISE_DSP_REQUEST_INVALID";

export interface BRIPeEnvelopeViolation {
  code: BRIPeEnvelopeViolationCode;
  detail: string;
}

export type BRIPeEnvelopeGateResult =
  | { ok: true }
  | { ok: false; violations: BRIPeEnvelopeViolation[] };

import { ownerCall } from "../../server/standalone/owner-client";
export const validateBRIPeEnvelopeV1 = (input: unknown): Promise<BRIPeEnvelopeGateResult> => ownerCall("envelope.validate", [input]);
