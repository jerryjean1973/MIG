export type ScaleDirection = "higher_is_stronger" | "lower_is_stronger";
export type MissingDataPolicy = "hold" | "degrade" | "reset" | "extrapolate";
export interface StructuralDomainScale {
    min: number;
    max: number;
    direction: ScaleDirection;
}
export interface StructuralDomainDefinition {
    /** Stable canonical domain identifier — used as the DB key. */
    domainId: string;
    /** Human-readable domain name for ODA surfaces. */
    displayName: string;
    /** One-line description of what this domain measures. */
    description: string;
    /**
     * Signal types that are REQUIRED to compute a meaningful domain state.
     * If all required types are absent, the missingDataPolicy applies.
     */
    requiredSignalTypes: string[];
    /**
     * Signal types that are OPTIONAL contributors.
     * Signals of these types enrich the domain state but their absence does
     * not trigger the missingDataPolicy.
     */
    optionalSignalTypes: string[];
    /** Numeric scale and direction for currentValue / normalizedValue. */
    scale: StructuralDomainScale;
    /**
     * ID of the canonical confidence policy that governs how per-signal
     * confidence values are aggregated into a domain-level confidence score.
     * Must be registered in the confidence-policy registry (future task).
     */
    confidencePolicyId: string;
    /**
     * ID of the canonical derivation policy that governs how admitted signals
     * are transformed into a numeric domain state value.
     * Must be registered in the derivation-policy registry (future task).
     */
    derivationPolicyId: string;
    /** What to do when required signals are missing. */
    missingDataPolicy: MissingDataPolicy;
    /**
     * BRIPe domain package ID that backs this domain.
     * "PENDING_BINDING" when no package is registered yet.
     */
    domainPackageId: string;
    /**
     * Semver — incremented whenever the definition fields change.
     * Persisted state rows carry the formulaVersion at write time;
     * a version mismatch flags a stale state record.
     */
    definitionVersion: string;
    /**
     * KAO IDs from KAO_REGISTRY that govern knowledge acquisition for this domain.
     * Every domain must have ≥1 KAO bound; "PENDING_BINDING" here is a lint error.
     * Used by BAL-I to execute constitutions and by the completeness service to
     * compute per-domain completeness scores.
     */
    kaoIds: string[];
}
