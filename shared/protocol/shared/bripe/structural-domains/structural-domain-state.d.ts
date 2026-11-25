export type StructuralDomainStateStatus = "ACTIVE" | "SUPERSEDED" | "DEGRADED" | "UNKNOWN" | "HELD";
export type StructuralDomainTrend = "IMPROVING" | "STABLE" | "WORSENING" | "INSUFFICIENT_HISTORY";
export interface StructuralDomainState {
    /**
     * Globally unique state record ID.
     * Format: sds_{domainId}_{entityId_short}_{hex8}
     */
    stateId: string;
    /** The domain this state record belongs to. Must be in ENTERPRISE_STRUCTURAL_DOMAINS. */
    structuralDomainId: string;
    /**
     * The canonical entity identity this state is scoped to.
     * For an enterprise-wide state: the tenant's root entity ID.
     * For a vendor: the CEO-admitted vendor entity ID.
     */
    targetEntityId: string;
    /**
     * Tenant isolation — required on every read and write.
     */
    tenantId: string;
    /**
     * A secondary scope key (e.g. "vendor_approval", "cyber_triage").
     * Allows the same entity to have domain states in different decision contexts.
     * Default: "default"
     */
    scopeId: string;
    /**
     * The computed domain state value at calculatedAt.
     * Null when status is UNKNOWN.
     * Units: defined by StructuralDomainDefinition.scale.
     */
    currentValue: number | null;
    /**
     * The value from the immediately preceding ACTIVE record (before this one
     * was created).  Null when this is the first record for this domain/entity.
     */
    previousValue: number | null;
    /**
     * currentValue normalised to [0, 1] per the domain's scale.
     * Null when currentValue is null.
     * Formula: (currentValue - scale.min) / (scale.max - scale.min)
     *   — or inverted when scale.direction = "lower_is_stronger".
     */
    normalizedValue: number | null;
    /** Current state status (see StructuralDomainStateStatus). */
    status: StructuralDomainStateStatus;
    /** Trend relative to previousValue. */
    trend: StructuralDomainTrend;
    /**
     * Confidence in the currentValue [0–1].
     * Derived by the confidencePolicyId from the domain definition.
     */
    confidence: number;
    /**
     * Maximum confidence this domain can reach given the available signals.
     * Below 1.0 when not all required signal types are present.
     */
    confidenceCeiling: number;
    /**
     * Signal IDs that support (reinforce) the currentValue.
     */
    supportingSignalIds: string[];
    /**
     * Signal IDs that contradict the currentValue.
     */
    contradictingSignalIds: string[];
    /**
     * Evidence record IDs (EQE/ESC evidence) backing this state.
     */
    supportingEvidenceIds: string[];
    /**
     * Source observation IDs from the ESC compilation that produced the
     * signals driving this state update.
     */
    sourceObservationIds: string[];
    /**
     * Derivation run ID — unique to the computation that produced this record.
     * Allows tracing exactly which derivation policy run produced the value.
     */
    derivationId: string;
    /**
     * Formula/derivation version from the domain definition at write time.
     * A version mismatch vs the current definition flags stale state records.
     */
    formulaVersion: string;
    /**
     * ISO-8601 timestamp when this record became active (validFrom).
     * Set to now() at write time.  Never null.
     */
    validFrom: string;
    /**
     * ISO-8601 timestamp when this record was superseded (validTo).
     * null → this is the current ACTIVE record.
     * set → this record has been superseded by a newer one.
     */
    validTo: string | null;
    /**
     * ISO-8601 timestamp when the value was computed.
     * May differ from validFrom if the computation was batched.
     */
    calculatedAt: string;
    /**
     * ESSG snapshot ID in scope when this state was calculated.
     * null when no snapshot was in scope (legacy/direct-signal path).
     */
    snapshotId: string | null;
    /**
     * Opaque lineage token tracing this state back to its admission result.
     * Format: matches ESSGAdmissionResult.lineage_token.
     */
    lineageToken: string;
    /** Exact producer receipt lineage when this is a conserved producer state. */
    producerLineage?: {
        receipt_id: string;
        producer_id: string;
        canonical_subject_id: string;
        evidence_ids: string[];
        effective_at: string;
        transaction_at: string;
        version: string;
    } | null;
}
