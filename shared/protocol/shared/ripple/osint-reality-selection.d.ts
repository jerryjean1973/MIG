export interface RippleOSINTRealitySelectionV1 {
    schema_version: "ripple.osint_reality.v1";
    authority: "ripple";
    reality_kind: "OSINT";
    region: string;
    canonical_subject_id: string;
    evidence_ids: string[];
    signal_ids: string[];
    evidence_fingerprint: string;
}
