export type ObservationType = "malware_sample_observed" | "malicious_url_active" | "ioc_observed" | "c2_infrastructure_active" | "vulnerability_exploited" | "vulnerability_disclosed" | "exploitation_probability" | "breach_detected" | "credential_exposed" | "ransomware_victim_published" | "threat_actor_campaign_active" | "internet_exposure_discovered" | "attacker_ttp_active" | "government_advisory_issued" | "exploit_public_available" | "exploit_poc_published";
export type SubjectEntityType = "domain" | "ip" | "url" | "hash" | "malware_family" | "threat_actor" | "vendor" | "technology" | "cve";
export interface SubjectEntity {
    entity_type: SubjectEntityType;
    entity_value: string;
    /** 0.0 = speculative match, 1.0 = exact match on queried identifier */
    match_confidence: number;
}
export interface RawReference {
    /** Canonical URL of the source record — used for analyst drill-down */
    canonical_url: string;
    /**
     * SHA-256 of (title + canonical_url) — stable deduplication key.
     * Use contentHash() helper below to produce this.
     */
    content_hash: string;
    /** Source system's own record ID, if available */
    api_record_id?: string;
}
export interface CollectionPolicy {
    /**
     * HARD INVARIANT — must always be false.
     * We never retain stolen credentials, malware payloads, or leaked data.
     * Enforced by TypeScript literal type — any collector that tries to set
     * this to true will fail to compile.
     */
    stolen_data_retained: false;
    /**
     * Whether raw article/page content is retained (false = metadata only).
     * MalwareBazaar: false (no binary content).
     * URLhaus/ThreatFox/Feodo: false (metadata only).
     */
    raw_content_retained: boolean;
    /** True when only metadata fields (hash, family name, date, etc.) are stored */
    metadata_only: boolean;
    /** Days after collection that this observation record may be retained */
    retention_days: number;
}
export interface ObservationLineage {
    /** collector_id from ExternalThreatSourceDefinition */
    collector_id: string;
    /** ISO timestamp of when this observation was produced by the collector */
    collected_at: string;
    /** Version string of the source data feed, if provided */
    source_version?: string;
    /** Pipeline run ID for correlation across observations from the same run */
    pipeline_run_id?: string;
}
export interface ExternalThreatObservation {
    /** Stable observation ID — deterministic from source_id + source_record_id */
    observation_id: string;
    /** source_id from ExternalThreatSourceDefinition */
    source_id: string;
    /** Source system's record identifier (hash, URL ID, IOC ID, etc.) */
    source_record_id: string;
    /** ISO timestamp from the source — when the threat was first observed */
    observed_at: string;
    /** ISO timestamp of when our collector ran */
    collected_at: string;
    /** Canonical observation type */
    observation_type: ObservationType;
    /** Entities identified in this observation, with match confidence */
    subject_entities: SubjectEntity[];
    /** Technology products or platforms affected */
    affected_technologies: string[];
    /** Industry sectors affected */
    affected_sectors: string[];
    /** Geographic regions relevant to this observation */
    affected_regions: string[];
    /** Threat actor name if known (APT name, criminal group, etc.) */
    threat_actor?: string;
    /** Malware family name if identified */
    malware_family?: string;
    /** CVE identifiers directly mentioned in this observation */
    cve_ids: string[];
    /** MITRE ATT&CK technique IDs (e.g. T1059.001) */
    attack_techniques: string[];
    /** Severity of the observed threat */
    severity: "critical" | "high" | "medium" | "low" | "info";
    /** 0.0–1.0 confidence in the observation itself */
    confidence: number;
    /** Source reliability from ExternalThreatSourceDefinition.source_reliability_weight */
    source_reliability: number;
    /** Independence group — correlated sources share a group name */
    source_independence_group: string;
    /** Provenance back to the original source record */
    raw_reference: RawReference;
    /** Data retention policy applied to this observation */
    collection_policy: CollectionPolicy;
    /** Lineage for pipeline traceability */
    lineage: ObservationLineage;
}
