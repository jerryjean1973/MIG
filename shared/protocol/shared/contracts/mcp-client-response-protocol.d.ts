export declare const MONTHLY_SALES_DATA_REQUIREMENTS: readonly [{
    readonly requirement_id: "crm_dossier_coverage";
    readonly priority: "decision_relevant";
    readonly request: "Provide complete assessed-period CRM dossiers (e.g. Activix): open, won, lost and cancelled, dated stage/activity history and assigned salesperson source IDs. State cutoff, omissions and whether missing activity is unknown rather than proven omission.";
}, {
    readonly requirement_id: "sales_delivery_coverage";
    readonly priority: "decision_relevant";
    readonly request: "Provide sales/delivery records (e.g. Autopak) through the latest authorized cutoff. Explicitly state partial coverage and the last extraction date; never assume a full month or November coverage from an October 23 cutoff.";
}, {
    readonly requirement_id: "monthly_history";
    readonly priority: "recommended_not_a_gate";
    readonly request: "Provide comparable prior monthly history, ideally 12 months if available, with coverage gaps. Do not block supported partial analysis solely because 12 months are unavailable.";
}, {
    readonly requirement_id: "sales_objective_baseline";
    readonly priority: "required_for_target_attainment_claim";
    readonly request: "Clarify the +10% or other requested objective separately for each assessed month: comparison period, baseline value and unit, signed versus delivered vehicle definition, target, deadline, timezone and management/source reference. Do not infer approval or a baseline from history.";
}, {
    readonly requirement_id: "operational_sales_procedures";
    readonly priority: "required_for_procedure_adherence_claim";
    readonly request: "Provide applicable operational sales procedures, versions/effective dates, required workflow steps and exact dossier/activity links. These are not cybersecurity controls; skipped steps and employee fault require evidence.";
}];
export declare const MCP_CLIENT_RESPONSE_PROTOCOL: {
    readonly dealer_projection: any;
    readonly version: "mcp.client-response-protocol.v1";
    readonly scope: "Client behavior and declared data exchange only; native owners retain all evidence, authority and projection decisions.";
    readonly instruction: "A BRIPe response can request another action instead of being a final answer. Inspect client_workflow and native result fields before responding to the user.";
    readonly continuation: readonly ["If next_call is present, invoke its tool with arguments unchanged, sequentially, under the same authenticated tenant/client. Do not reset cursors, drop request_context or invent canonical identities.", "Checkpoint source_graph_ref, returned receipts and next_call before continuing. Never resend a retained graph to recover conversion. Submit new data only as a separately identified supplement/update preserving original source IDs.", "Check progress after every response. If the same next_call repeats without progress, stop and report the saved reference and blocker; do not loop indefinitely."];
    readonly data_response: {
        readonly catalog: "monthly_sales";
        readonly applies_to: "Automotive COO/monthly sales assessments only; this catalog is not a claim that every item is missing or applicable to every domain.";
        readonly requirements: readonly [{
            readonly requirement_id: "crm_dossier_coverage";
            readonly priority: "decision_relevant";
            readonly request: "Provide complete assessed-period CRM dossiers (e.g. Activix): open, won, lost and cancelled, dated stage/activity history and assigned salesperson source IDs. State cutoff, omissions and whether missing activity is unknown rather than proven omission.";
        }, {
            readonly requirement_id: "sales_delivery_coverage";
            readonly priority: "decision_relevant";
            readonly request: "Provide sales/delivery records (e.g. Autopak) through the latest authorized cutoff. Explicitly state partial coverage and the last extraction date; never assume a full month or November coverage from an October 23 cutoff.";
        }, {
            readonly requirement_id: "monthly_history";
            readonly priority: "recommended_not_a_gate";
            readonly request: "Provide comparable prior monthly history, ideally 12 months if available, with coverage gaps. Do not block supported partial analysis solely because 12 months are unavailable.";
        }, {
            readonly requirement_id: "sales_objective_baseline";
            readonly priority: "required_for_target_attainment_claim";
            readonly request: "Clarify the +10% or other requested objective separately for each assessed month: comparison period, baseline value and unit, signed versus delivered vehicle definition, target, deadline, timezone and management/source reference. Do not infer approval or a baseline from history.";
        }, {
            readonly requirement_id: "operational_sales_procedures";
            readonly priority: "required_for_procedure_adherence_claim";
            readonly request: "Provide applicable operational sales procedures, versions/effective dates, required workflow steps and exact dossier/activity links. These are not cybersecurity controls; skipped steps and employee fault require evidence.";
        }];
        readonly reply_field: "operational_assessment.request_context.data_requirement_responses";
        readonly statuses: readonly ["PROVIDED", "PARTIAL", "UNAVAILABLE", "NEEDS_CLARIFICATION"];
        readonly instruction: "Return one response per requirement_id with status and details. PROVIDED/PARTIAL must cite exact source_refs or a server-issued supplement_graph_ref. Include source coverage, cutoff and limitations where relevant. Acknowledgement is not data delivery or canonical acceptance.";
        readonly submission: "Acquire only authorized source data. Submit supplements through existing source_graph intake; retain its returned reference. Send declared requirement responses on the operational assessment, preserving earlier context. Use request_context.sales_objectives for explicit monthly/quarterly/yearly targets; do not fabricate unavailable targets.";
        readonly clarification: "For UNAVAILABLE or NEEDS_CLARIFICATION, explain the limitation or the exact question to resolve. Do not invent a baseline or repeatedly acquire the same unavailable data. Continue independently supported work and report affected claims separately.";
    };
    readonly recovery: readonly ["For HTTP 502/timeout, outcome is unknown, not failed: preserve the exact request and source reference. Consult any available saved receipt/status before retrying only the same continuation. If no status read is available, stop and report the reference for operator recovery rather than resubmitting the graph.", "For an explicit retry_call follow it only after its blocker is resolved. Use at most 3 transient retries with exponential backoff; stop after the budget or repeated no-progress response.", "On authentication/authorization denial stop; do not change tenant, identity, domain or credentials to bypass it. Request authorized correction."];
    readonly completion: readonly ["next_call: null alone is not business completion. Intake, source retention, conversion, admission, QUALIFYING, PARTIAL, WITHHELD and EXECUTED are not proof that all requested projections exist.", "Read native availability and exact saved outputs per requested deliverable: dossier risk, recovery/interruption points and objective projections separately by month. Report unsupported or withheld items and source cutoff limitations explicitly.", "Never invent risk probabilities, recovered sales, employee fault, target attainment or timing. Distinguish retrospective outcomes from prospective projections at the stated as-of date."];
};
export type McpClientResponseProtocol = typeof MCP_CLIENT_RESPONSE_PROTOCOL;
