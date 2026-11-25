import { type EnterprisePrimitiveSemanticMapping } from "../bdl-domain-ontology-map";
export interface GovernedStructuralPrior {
    prior_id: string;
    prior_version: string;
    prior_type: "DOMAIN_BASELINE" | "STRUCTURAL_ARCHETYPE" | "HISTORICAL_STRUCTURAL_PRIOR";
    material_kind: "PRODUCTION_BASELINE";
    domain_package_id: string;
    domain_package_version: string;
    applicable_scopes: string[];
    applicable_archetypes: string[];
    valid_from: string;
    valid_to: string | null;
    provenance_refs: string[];
    authority_ref: string;
    semantic_lineage: {
        source_domain: string;
        domain_primitive: string;
        mapping_version: string;
    };
    confidence: number;
    inputs: Array<{
        signal_type: string;
        target_node_id: string;
        severity: number;
    }>;
}
export interface StructuralPriorComposition {
    contract_version: "bripe.structural-prior-composition.v1";
    epistemic_kind: "STRUCTURAL_PRIOR";
    tenant_id: string;
    subject_id: string;
    scope: string;
    archetype: string;
    effective_at: string;
    package_id: string;
    package_version: string;
    package_artifact_hash: string;
    semantic_versions: Record<string, string>;
    /** Exact admitted BDL mapping bytes; later registry evolution cannot reinterpret a saved result. */
    semantic_bindings: EnterprisePrimitiveSemanticMapping[];
    priors: GovernedStructuralPrior[];
    missing: Array<{
        epistemic_kind: "MISSING";
        requirement_id: string;
    }>;
    content_hash: string;
}
