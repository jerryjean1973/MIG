/**
 * shared/bripe/enterprise-memory-snapshot.ts
 *
 * EnterpriseMemorySnapshot — Dual-Dimension BRIPe Context Contract
 * ================================================================
 *
 * Section 20 of the Master CB Prompt describes the two constitutional
 * dimensions BRIPe requires to produce traceable structural intelligence:
 *
 *   (a) semanticContext  — canonical entities and relationships from ESSG/CEO.
 *       Answers: "What enterprise objects and connections are currently known?"
 *
 *   (b) structuralState  — domain definitions and per-scope domain states.
 *       Answers: "What structural condition has been measured for each domain?"
 *
 * The EXISTING StructuralStateSnapshotV1 (signal-oriented) is preserved.
 * This type is ADDITIVE — it wraps or sits alongside it in the BRIPe
 * execution path and provides the two constitutional dimensions required for
 * full condition traceability.
 *
 * INTEGRITY RULE (Section 25):
 *   assertSnapshotHasBothDimensions() is the fail-closed guard.
 *   It throws if BOTH semanticContext.entities AND structuralState.domainStates
 *   are empty — indicating an unhydrated snapshot should not pass to BRIPe.
 *
 * Layer: Shared Contracts — shared/bripe/
 * Schema version: ems.v1
 */
import type { CanonicalEnterpriseObject, CanonicalEnterpriseRelationship } from "../schema";
import type { StructuralDomainDefinition } from "./structural-domains/structural-domain-registry";
import type { StructuralDomainState } from "./structural-domains/structural-domain-state";
export type { StructuralDomainDefinition } from "./structural-domains/structural-domain-registry";
export type { StructuralDomainState } from "./structural-domains/structural-domain-state";
export interface EnterpriseSemanticContext {
    /**
     * All canonical enterprise objects admitted for this tenant at snapshot time.
     * These are the semantic objects whose structural conditions BRIPe may reference.
     */
    entities: CanonicalEnterpriseObject[];
    /**
     * All canonical enterprise relationships admitted for this tenant at snapshot time.
     * Relationships define how pressure propagates between objects.
     */
    relationships: CanonicalEnterpriseRelationship[];
}
export interface EnterpriseStructuralStateContext {
    /**
     * The full set of domain definitions from ENTERPRISE_STRUCTURAL_DOMAINS,
     * frozen at snapshot creation time. Consumers can detect stale domain
     * definitions by comparing definitionVersion against persisted state rows.
     */
    domainDefinitions: StructuralDomainDefinition[];
    /**
     * All current (valid_to IS NULL) structural domain state records for
     * this tenant, across all entities and scopes.
     */
    domainStates: StructuralDomainState[];
}
export interface EnterpriseMemorySnapshot {
    /** Unique snapshot identifier. Format: ems_{8-char-hex}_{timestamp} */
    snapshotId: string;
    /** Tenant isolation — all reads enforced this. */
    tenantId: string;
    /** ISO-8601 creation timestamp. */
    createdAt: string;
    /**
     * (a) Semantic dimension.
     * Canonical entities and relationships from ESSG/CEO, tenant-scoped.
     */
    semanticContext: EnterpriseSemanticContext;
    /**
     * (b) Structural-state dimension.
     * Domain definitions (frozen) + current domain states (valid_to IS NULL).
     */
    structuralState: EnterpriseStructuralStateContext;
    /**
     * Signal IDs that are active (admitted) at snapshot time.
     * Derived from supportingSignalIds across all domainStates.
     */
    activeSignalIds: string[];
    /**
     * Signal IDs involved in contradictions at snapshot time.
     * Derived from contradictingSignalIds across all domainStates.
     */
    contradictionIds: string[];
    /**
     * CEO ontology version active at snapshot creation time.
     */
    ontologyVersion: string;
    /**
     * Graph structural version at snapshot time.
     * Matches the ESSG graph_version if an ESSG snapshot was the source.
     */
    graphVersion: string;
    /**
     * Deterministic SHA-256 content hash over the entity, relationship,
     * domain-state, and domain-definition payloads (not just IDs).
     *
     * A changed score, confidence, supporting-signal set, definition version,
     * or relationship weight WILL produce a different hash, even if IDs are
     * unchanged. Allows BRIPe to detect payload tampering or replay drift.
     *
     * Computed server-side using computeEnterpriseSnapshotHashInput().
     * Schema version embedded in the pre-image: "ems.v1.1".
     */
    snapshotHash: string;
    /**
     * True when the semantic context was truncated because the tenant's
     * canonical object or relationship count exceeded the store's maximum
     * batch size (5,000 objects / 500 relationships per query).
     *
     * When true, structural conditions for objects beyond the batch window
     * may not be traceable back to their semantic entities in this snapshot.
     * Callers should treat dual-context enrichment as PARTIAL and re-assemble
     * after the store is paginated (follow-up task).
     */
    isTruncated: boolean;
    /**
     * Human-readable description of scope limits when isTruncated is true.
     * Undefined when isTruncated is false.
     */
    scopeBoundary?: string;
    /**
     * (c) Business Knowledge dimension.
     * Named wrapper over the subset of `semanticContext.relationships` that carry
     * a `lineageToken` — those relationships are classified as Business Knowledge.
     *
     * Optional: absent for snapshots created before CB §3022 constitutionalization
     * or when no relationships have been BK-classified yet.
     *
     * Downstream consumers that rely on BK content should declare their dependency
     * on this field rather than scanning `semanticContext.relationships` for intent.
     */
    businessKnowledge?: EnterpriseBusinessKnowledge;
    /**
     * (d) Decision Lineage dimension.
     * Chain of BRIPe/governance decision IDs that have consumed this snapshot.
     *
     * Optional: populated by consumers after using the snapshot; absent for
     * freshly created snapshots that have not yet been consumed.
     */
    decisionLineage?: EnterpriseDecisionLineage;
    /**
     * (e) Historical Context dimension.
     * Prior snapshot IDs and timestamps for replay traceability.
     *
     * Optional: absent for the first snapshot of a tenant, or when history
     * tracking was not enabled at snapshot creation time.
     */
    historicalContext?: EnterpriseHistoricalContext;
}
export interface EnterpriseBusinessKnowledge {
    /**
     * IDs of relationships (from `semanticContext.relationships`) classified as
     * Business Knowledge because they carry a non-null `lineageToken`.
     * Populated at snapshot creation time; not re-evaluated at read time.
     */
    bkRelationshipIds: string[];
    /**
     * ISO-8601 timestamp of the most recently classified BK relationship.
     * Undefined when no BK relationships exist.
     */
    latestBkAt?: string;
}
export interface EnterpriseDecisionLineage {
    /**
     * IDs of BRIPe/governance decisions that consumed this snapshot.
     * Ordered chronologically (oldest first).
     */
    decisionIds: string[];
    /**
     * ISO-8601 timestamp of the most recent decision that consumed this snapshot.
     * Undefined when no decisions have consumed it yet.
     */
    latestDecisionAt?: string;
}
export interface EnterpriseHistoricalContext {
    /**
     * IDs of prior `EnterpriseMemorySnapshot` records for the same tenant,
     * ordered chronologically (oldest first). The current snapshot is NOT
     * included in this list.
     */
    priorSnapshotIds: string[];
    /**
     * ISO-8601 creation timestamps of each prior snapshot, parallel to
     * `priorSnapshotIds`. `snapshotCreatedAt[i]` is the `createdAt` value
     * of `priorSnapshotIds[i]`.
     */
    snapshotCreatedAt: string[];
}
