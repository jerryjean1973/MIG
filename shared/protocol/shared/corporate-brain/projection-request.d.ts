import type { CanonicalKnowledgePrincipal } from "./canonical-knowledge-authority";
export declare const PROJECTION_REQUEST_CONTRACT_VERSION: "cb.projection-request.v1";
export interface ProjectionReconstructionBinding {
    contract_version: typeof PROJECTION_REQUEST_CONTRACT_VERSION;
    request_hash: string;
    reconstruction_receipt_id: string;
    reconstruction_hash: string;
    tenant_id: string;
    subject_id: string;
    cutoff: string;
    authority_principal_ceiling: CanonicalKnowledgePrincipal;
}
