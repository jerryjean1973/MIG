export type RealitySelectionStatus = "selected" | "not_applicable";
export type RealitySelectionAuthority = "morpheus";
export interface MorpheusRealityProof {
    registry: "morpheus";
    registry_entry_id: string;
    registry_version: string;
    immutable_fingerprint: string;
    lineage_fingerprint: string;
    reality_ids: string[];
    captured_at: string;
    /** Optional execution partition for multi-tenant Morpheus deployments. */
    tenant_id?: string | null;
    /** Optional as-of boundary for replayable historical selections. */
    cutoff_at?: string | null;
}
export interface MorpheusStructuralDeltaReference {
    delta_id: string;
    source_reality_id: string;
    target_reality_id: string;
}
export interface RealitySelectionIdentity {
    reality_selection_v1: true;
    selection_status: RealitySelectionStatus;
    enterprise_id: string | null;
    /** Optional tenant partition; omitted for legacy/global selections. */
    tenant_id?: string | null;
    /** Optional historical cutoff; omitted means the registry's current boundary. */
    cutoff_at?: string | null;
    current_reality_id: string | null;
    target_reality_id: string | null;
    scenario_reality_id: string | null;
    branch_id: string | null;
    iteration_id: string | null;
    delta_id: string | null;
    structural_delta: MorpheusStructuralDeltaReference | null;
    reality_selection_reason: string;
    reality_selection_authority: RealitySelectionAuthority;
    immutable_proof: MorpheusRealityProof | null;
}
