import { MCP_CLIENT_RESPONSE_PROTOCOL, MONTHLY_SALES_DATA_REQUIREMENTS } from "@shared/contracts/mcp-client-response-protocol";

import { SOURCE_JSON_STATUS_POLL_MS } from "@shared/contracts/source-json-intake";

const record = (value: unknown): Record<string, any> | undefined =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, any> : undefined;

export function withMcpClientWorkflow(toolName: string, output: unknown, input: unknown): unknown {
  if (toolName !== "run_bripe_decision") return output;
  const owner = record(output), args = record(input);
  if (!owner || !args) return output;
  const result = record(owner.result) ?? owner;
  const next = result.next_call ?? owner.next_call;
  const retry = result.retry_call ?? owner.retry_call;
  const assessment = record(args.operational_assessment);
  const context = record(assessment?.request_context);
  const responses: Array<Record<string, any>> = context?.data_requirement_responses ?? [];
  const answered = new Set(responses.map(row => row.requirement_id));
  const isSourceFlow = !!(assessment || args.source_graph || args.source_graph_ref || args.source_graph_upload
    || args.source_file_upload || args.source_json !== undefined || args.source_upload_ref
    || args.source_json_binding_ref || args.source_json_request_ref);
  if (!isSourceFlow) return output;
  const routingDeferred = result.automatic_retry === false;
  const statusCall = record(result.status_call);
  const statusArgs = record(statusCall?.arguments);
  // Project only the owner's same-request, same-organization reference call.
  // A status check must never become an upload, binding override or execution mode.
  const canCheckStatus = routingDeferred && result.status_poll_allowed === true
    && owner.ok !== false && !owner.error && result.ok !== false && !result.error
    && result.status === "source_json_binding_pending"
    && statusCall?.name === "run_bripe_decision" && !!statusArgs
    && typeof args.canonical_organization_id === "string" && !!args.canonical_organization_id
    && statusArgs.canonical_organization_id === args.canonical_organization_id
    && typeof result.source_json_request_ref === "string"
    && /^sha256:[a-f0-9]{64}$/.test(result.source_json_request_ref)
    && statusArgs.source_json_request_ref === result.source_json_request_ref
    && (!args.source_json_request_ref || args.source_json_request_ref === result.source_json_request_ref)
    && Object.keys(statusArgs).length === 2
    && Object.keys(statusArgs).every(key => ["canonical_organization_id", "source_json_request_ref"].includes(key));
  const individualLead = result.processing_route === "bal.source-json-individual-lead.v2"
    || ["individual_lead_routing_review", "individual_lead_native_owner", "individual_lead_owner_pending"].includes(result.stage);
  const leadCohort = result.processing_route === "bal.source-json-lead-cohort.v1";
  const strategic = assessment?.mode === "STRATEGIC";
  return {
    ...owner,
    client_workflow: {
      protocol_version: MCP_CLIENT_RESPONSE_PROTOCOL.version,
      final_business_response: false,
      completion_authority: "Exact native owner outputs per requested deliverable; this transport never certifies business completion.",
      action: result.status === "awaiting_parts" ? "SEND_ONLY_MISSING_PARTS"
        : result.status === "source_file_retained" ? "FILE_RETAINED_NOT_ANALYZED"
        : canCheckStatus ? "WAIT_AND_CHECK_STATUS"
        : routingDeferred || result.status === "EXECUTION_STATUS_REQUIRED" ? "REPORT_BLOCKER"
        : next ? "FOLLOW_NEXT_CALL" : retry ? "RESOLVE_BLOCKER_THEN_RETRY"
        : owner.ok === false || owner.error ? "REPORT_BLOCKER" : "REVIEW_NATIVE_OUTPUT_AND_REQUIREMENTS",
      ...(next && !routingDeferred ? { next_call: next } : {}),
      ...(canCheckStatus ? { status_call: statusCall, poll_after_ms: SOURCE_JSON_STATUS_POLL_MS,
        assessment_retry_allowed: false, requires_user_relay: false } : {}),
      ...(retry ? { retry_call: retry } : {}),
      source_graph_ref: result.source_graph_ref ?? args.source_graph_ref ?? null,
      ...(result.source_json_ref ? { source_json_ref: result.source_json_ref,
        source_json_binding_ref: result.source_json_binding_ref, source_records: result.source_records } : {}),
      ...(args.source_file_upload ? {
        source_file_ref: result.source_file_ref ?? null,
        upload_ref: result.upload_ref,
        ...(result.missing_parts ? { missing_parts: result.missing_parts } : {}),
        chunk_bytes: 4194304,
        retention_only: true,
      } : {}),
      instructions: canCheckStatus ? {
        version: "source-json-status.v1",
        scope: "The exact retained request, original subject/domain, source cutoff and cohort.",
        continuation: "Wait poll_after_ms, then issue status_call unchanged using the existing authenticated MCP connection. Repeat only the server-issued status call while WAIT_AND_CHECK_STATUS is returned. Do not ask the user to relay status or repair confirmation.",
        recovery: "automatic_retry:false pauses semantic/native assessment retries, not these explicitly allowed status checks. While blocked, the owner reads the retained state without rerunning the model or engine. Do not re-upload, split the cohort, change domains or invent bindings. Network failures require bounded backoff, not a source resubmission.",
        readiness: "A repaired owner binding changes the response to FOLLOW_NEXT_CALL. Follow that exact server-issued next_call through ordinary authorization; no chat confirmation is required. A status check does not perform code repair or claim that queued repair work is running.",
        completion: "Retained source and routing readiness are not native results. Inspect actual requested outputs and their availability. Never repeat an uncertain native execution.",
      } : strategic ? {
        version: "dealer-strategy-request.v1",
        scope: "Complete authorized source manifest for the requested dealership, region and explicit planning interval.",
        continuation: "Follow exact owner-issued source continuations. Never replace this request with an individual lead or monthly mileage/payment-policy contract.",
        recovery: "Stop on EXECUTION_STATUS_REQUIRED and reconcile the prepared native receipt before another dispatch.",
        completion: "Inspect native field availability and actual periods. Native execution or source retention is not full strategic readiness or empirical forecast validation.",
      } : leadCohort ? {
        version: "source-json-cohort.v1",
        scope: "Every lead in the exact original activity cohort, with its own retained child records, cutoff and selected domain.",
        continuation: "Follow only this parent response's exact next_call. Internal per-lead references are lineage, not another client submission. Do not resend, split or replace the cohort.",
        recovery: "The server bounds per-lead dispatch and reuses saved native receipts. An uncertain or withheld individual outcome is never permission to rerun it.",
        completion: "Inspect each lead and requested outcome. Terminal includes explicitly withheld results, not a claim that every native risk or timing value is available. Never substitute dealership-wide averages.",
      } : individualLead ? {
        version: MCP_CLIENT_RESPONSE_PROTOCOL.version,
        scope: "Only the originally submitted individual lead, meeting, question and retained source cutoff.",
        continuation: "Follow only the exact owner-issued next_call. Do not resend JSON, refresh CRM, invent bindings or substitute the dealership COO contract.",
        recovery: "Stop on automatic_retry:false. Monitoring may resume transient owner work within its bounded budget; an uncertain native outcome must be reconciled, never re-executed.",
        completion: "Review the exact native output and per-field availability. A retained source, routing success or processing acknowledgment is not a projection.",
      } : MCP_CLIENT_RESPONSE_PROTOCOL,
      ...(assessment && !strategic ? {
        data_request: {
          catalog: "monthly_sales",
          state: "CLIENT_RESPONSES_REQUESTED_NOT_EVIDENCE_VALIDATED",
          reply_field: MCP_CLIENT_RESPONSE_PROTOCOL.data_response.reply_field,
          requirements: MONTHLY_SALES_DATA_REQUIREMENTS,
          received_responses: responses.map(row => ({ requirement_id: row.requirement_id,
            declared_status: row.status, qualification: "RECEIVED_CLIENT_DECLARATION_NOT_VERIFIED" })),
          unanswered_requirement_ids: MONTHLY_SALES_DATA_REQUIREMENTS
            .filter(row => !answered.has(row.requirement_id)).map(row => row.requirement_id),
        },
      } : {}),
    },
  };
}
