type Signal = {
    signal_id: string;
    entity: string;
    type: string;
    source: string;
    source_key: string;
    evidence_id: string;
    timestamp: string;
    value: unknown;
    confidence: number;
    knowledge_origin?: unknown;
};
export declare function packageExecutionContentHash(value: unknown): string;
declare function sourcePopulation(signals: readonly Signal[]): {
    signal_id: string;
    subject_id: string;
    type: string;
    producer_id: string;
    source_key: string;
    evidence_id: string;
    effective_at: string;
    confidence: number;
    value_hash: string;
    authority_hash: string;
}[];
export interface PackageExecutionBindingV1 {
    contract_version: "cb.package-execution-binding.v1";
    tenant_id: string;
    subject_id: string;
    effective_at: string;
    package: {
        package_id: string;
        package_version: string;
        artifact_hash: string;
    };
    semantic_contract: unknown;
    source_population: ReturnType<typeof sourcePopulation>;
    execution_context: {
        scope: string;
        execution_kind: string;
        graph_hash: string;
        non_scoreable_context_hash: string;
        authority_context: unknown;
        reconstruction_binding: unknown;
    };
    content_hash: string;
}
export {};
