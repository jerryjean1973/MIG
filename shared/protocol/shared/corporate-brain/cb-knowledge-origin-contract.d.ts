/**
 * Canonical knowledge origin contract.
 *
 * Origin is deliberately orthogonal to CBPartition: it describes the
 * evidentiary status and route by which a record entered the Brain.  This
 * module is pure and is intended to be usable by admission, replay, and
 * migration code without importing a service or persistence implementation.
 */
import type { CBOrigin, CBPartition } from "./cb-partition-contract";
export declare const CB_PROVENANCES: readonly ["REAL", "SEED", "DEMO", "FIXTURE", "SYNTHETIC", "SYNTHETIC_TEST"];
export type CBProvenance = (typeof CB_PROVENANCES)[number];
export declare const CB_VERIFICATIONS: readonly ["VERIFIED", "UNVERIFIED_LEGACY"];
export type CBVerification = (typeof CB_VERIFICATIONS)[number];
export declare const CB_PRODUCTION_AUTHORITY: "CORPORATE_BRAIN";
export interface CBDeclarantLineage {
    declarant_id: string;
    declarant_type: string;
    declaration_id: string;
    declared_at: string;
}
export interface CBProducerExecutionLineage {
    producer_id: string;
    execution_id: string;
    executed_at: string;
    execution_version: string;
}
export interface CBDerivationLineage {
    input_ids: string[];
    derivation_id: string;
    derivation_method: string;
}
export interface CBKnowledgeOrigin {
    partition: CBPartition;
    origin: CBOrigin;
    provenance: CBProvenance;
    verification: CBVerification;
    production_authority: typeof CB_PRODUCTION_AUTHORITY | null;
    declarant_lineage?: CBDeclarantLineage;
    producer_execution_lineage?: CBProducerExecutionLineage;
    derivation_lineage?: CBDerivationLineage;
    record_id?: string;
    supersedes_record_id?: string;
    revoked_at?: string;
    revocation_reason?: string;
}
