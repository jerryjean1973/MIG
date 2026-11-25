export interface KnowledgeResolutionReceipt {
    cb_knowledge_resolution_receipt_v1: true;
    receipt_id: string;
    tenant_id: string;
    process_id: string;
    object_id: string;
    consuming_domain: string;
    decision_time: string;
    evaluated_at: string;
    selected_knowledge_ids: string[];
    acquisition_requirement_ids: string[];
    revalidation_requirement_ids: string[];
    requirement_scopes: Array<{
        requirement_id: string;
        knowledge_type: string;
        mode: "REUSE" | "ACQUIRE" | "REVALIDATE" | "INAPPLICABLE";
        required_content?: Record<string, string | number | boolean>;
    }>;
    requirement_fingerprint: string;
    /** HMAC-SHA256 over the complete canonical receipt payload; issued only by the server boundary. */
    authenticity_tag: string | null;
}
