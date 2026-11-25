export interface CSSLContradictionRecord {
    /** The signal that contradicts a prior observation. */
    contradicting_signal_id: string;
    /** The prior signal being contradicted. */
    prior_signal_id: string;
    /** The structural node where the contradiction was observed. */
    node_id: string;
    /**
     * Type of contradiction:
     *   value     — same signal type, conflicting value/severity
     *   temporal  — observation timing conflicts with prior window
     *   source    — multi-source disagreement on the same node
     *   scope     — contradicting signal applies to a different scope
     */
    contradiction_type: "value" | "temporal" | "source" | "scope";
    /** Confidence difference between the contradicting and prior signals. */
    confidence_delta: number;
    observed_at: number;
    resolved: boolean;
    resolution_note?: string;
}
export interface CSSLConvergenceRecord {
    /**
     * Number of independent sources that observed this structural condition
     * within the convergence window.
     */
    source_count: number;
    /** Number of tools (BRIPe surfaces) that contributed signals. */
    tool_count: number;
    /**
     * The recurrence ratio: (days_active in window) / (observed_days in window).
     * 0.0 = never active; 1.0 = active every observed day.
     */
    recurrence_ratio: number;
    /**
     * Convergence tier:
     *   none     — no convergence evidence (0 sources, 0 recurrence)
     *   weak     — single source, low recurrence (<0.3)
     *   moderate — 2+ sources OR recurrence 0.3–0.6
     *   strong   — 3+ sources AND recurrence ≥0.6
     */
    convergence_tier: "none" | "weak" | "moderate" | "strong";
    /** ISO-8601 start of the convergence analysis window. */
    window_start: string;
    /** ISO-8601 end of the convergence analysis window. */
    window_end: string;
    /** Whether historical convergence data was available for this decision scope. */
    data_available: boolean;
}
export interface CSSLSurvivabilityRecord {
    /**
     * Count of confirmed structural conditions that persisted through at least
     * one mitigation attempt without resolution.
     */
    persistent_condition_count: number;
    /**
     * Count of structural conditions that were contained/resolved and did not
     * recur within the observation window.
     */
    resolved_condition_count: number;
    /**
     * Survivability ratio: persistent / (persistent + resolved).
     * 0.0 = all conditions resolved; 1.0 = no conditions resolved.
     * null = insufficient data.
     */
    survivability_ratio: number | null;
    /** Whether suppressed signals were present (indicating a prior containment event). */
    has_suppressed_signals: boolean;
    /** Count of suppressed (contained) signals. */
    suppressed_count: number;
}
export interface CSSLReplayAnchor {
    /** The cache key or snapshot reference for this replay point. */
    anchor_id: string;
    /** Cutoff timestamp for this replay anchor (unix ms). */
    cutoff_ms: number;
    /** ISO-8601 of when this anchor was captured. */
    captured_at: string;
    /** Domain or entity scope of the anchor. */
    scope: string;
    /** Count of signals in the corpus at this anchor point. */
    signal_count: number;
}
export interface CSSLConfidenceEvolution {
    /**
     * Average confidence of ALL signals in the corpus at this decision time.
     */
    current_avg_confidence: number;
    /**
     * Average confidence of confirmed signals only.
     * null = no confirmed signals.
     */
    confirmed_avg_confidence: number | null;
    /**
     * Time-ordered confidence trend: newest first.
     * Each entry: unix ms timestamp → avg confidence at that point.
     * Used to detect drift (confidence eroding) or reinforcement (rising).
     */
    confidence_history: Array<{
        ts: number;
        avg_confidence: number;
    }>;
    /**
     * Confidence trend direction over the observation window.
     *   rising   — avg confidence increased >10% vs prior window
     *   stable   — avg confidence within ±10% of prior window
     *   eroding  — avg confidence decreased >10% vs prior window
     *   unknown  — insufficient history
     */
    trend: "rising" | "stable" | "eroding" | "unknown";
}
export interface CSSLTemporalLineageEntry {
    /** The signal whose lineage is being described. */
    signal_id: string;
    /** Ordered transformer steps with timestamps. */
    steps: Array<{
        transformer: string;
        timestamp_ms: number;
        tool_source: string;
    }>;
    /** First time this signal was observed (unix ms). */
    first_observed_ms: number;
    /** Most recent observation (unix ms). */
    last_observed_ms: number;
    /** Whether the lineage chain is complete (no gaps detected). */
    lineage_complete: boolean;
}
export interface CSSLDecisionContext {
    /** Tenant isolation. */
    tenant_id: string;
    /** The entity this context is scoped to. */
    entity_id: string;
    /** The domain package ID scoping this context. */
    domain_id: string;
    /**
     * Signals observed AFTER this cutoff are excluded from the historical
     * context.  Must align with the ESSG snapshot's cutoff_time.
     * ISO-8601.
     */
    cutoff_time: string;
    /** All historical canonical signals in scope at cutoff_time. */
    historical_signal_count: number;
    /** Summary statistics of the historical corpus. */
    corpus_stats: {
        confirmed_count: number;
        strong_count: number;
        weak_count: number;
        contextual_count: number;
        oldest_signal_ms: number | null;
        newest_signal_ms: number | null;
    };
    recurrence_strength: number;
    recurrence_window_days: number;
    max_recurrence_count: number;
    /** Derived persistence state of the dominant structural condition. */
    persistence_state: "new" | "increasing" | "stable" | "declining" | "absent";
    /** Current unbroken run of active days. */
    consecutive_active_days: number;
    /** Total active days in the observation window. */
    total_active_days: number;
    contradictions: CSSLContradictionRecord[];
    unresolved_contradiction_count: number;
    convergence: CSSLConvergenceRecord;
    survivability: CSSLSurvivabilityRecord;
    replay_anchors: CSSLReplayAnchor[];
    confidence_evolution: CSSLConfidenceEvolution;
    temporal_lineage: CSSLTemporalLineageEntry[];
    /**
     * Whether this CSSL context has sufficient historical data for BRIPe
     * to distinguish transient from structurally durable conditions.
     *   full      — all 10 capabilities have data
     *   partial   — some capabilities have data; BRIPe runs with reduced temporal confidence
     *   minimal   — only recurrence/persistence available; limited temporal intelligence
     *   absent    — no historical data; BRIPe cannot use temporal memory for this decision
     */
    coverage_status: "full" | "partial" | "minimal" | "absent";
    /** Names of the 10 capabilities that have data. */
    capabilities_present: string[];
    /** Names of the 10 capabilities with no data (degraded mode will apply). */
    capabilities_missing: string[];
    /** ISO-8601 timestamp when this context was assembled. */
    assembled_at: string;
}
