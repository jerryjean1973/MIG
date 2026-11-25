export type LineageNodeKind = "evidence" | "observation" | "structural_artifact" | "reconstructed_object" | "reconstructed_relationship" | "reasoning_operation" | "diagnosis_output" | "recommendation" | "decision";
export interface LineageScope {
    tenant_id: string;
    reality_id: string | null;
    reality_version: string | null;
}
export interface LineageNodeRef {
    kind: LineageNodeKind;
    id: string;
}
export interface CanonicalLineageNode extends LineageNodeRef {
    scope?: Partial<LineageScope>;
    producer?: string;
    owner_id?: string;
    assumptions?: string[];
    contradictions?: string[];
    epistemic_state?: string;
    authorization_state?: string;
}
export interface CanonicalDerivationEdge {
    edge_id: string;
    /** Derived output. */
    from: LineageNodeRef;
    /** Input/dependency consumed by the derived output. */
    to: LineageNodeRef;
    relation: "derived_from" | "reasoned_by" | "reconstructed_from" | "observed_by" | "corroborated_by" | "supersedes";
    operation_id?: string;
    scope?: Partial<LineageScope>;
}
export interface LineageEpistemicAuthorization {
    epistemic_state: string;
    authorization_state: string;
    authorized_by?: string | null;
    basis_refs: string[];
}
export interface PersistedDiagnosisLineage {
    schema_version: "bripe.diagnosis_lineage.v1";
    scope: LineageScope;
    nodes: CanonicalLineageNode[];
    edges: CanonicalDerivationEdge[];
    assumptions: string[];
    contradictions: string[];
    epistemic_authorization: LineageEpistemicAuthorization;
    prior_diagnosis_id?: string | null;
    evidence_delta?: EvidenceDelta | null;
}
export interface EvidenceDelta {
    delta_id: string;
    changed_evidence_ids: string[];
    corrected_evidence_ids: string[];
    revoked_evidence_ids: string[];
    supersedes_delta_id?: string | null;
}
