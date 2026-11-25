export interface VSOCDemoRealitySelectionV1 {
    schema_version: "ripple.vsoc_demo_reality.v1";
    authority: "ripple";
    reality_kind: "SYNTHETIC_DEMO";
    tenant_id: string;
    scenario_id: string;
    canonical_subject_id: string;
    essg_snapshot_id: string;
    essg_snapshot_hash: string;
    cb_snapshot_id: string;
    signal_ids: string[];
    evidence_ids: string[];
    evidence_fingerprint: string;
}
