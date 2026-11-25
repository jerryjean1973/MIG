/**
 * MIG structural PDP contract v1.
 *
 * MIG is the PEP: this contract deliberately contains no structural scoring,
 * path selection, propagation, or intervention implementation.  Those facts
 * are supplied by the canonical BRIPe execution boundary.
 */

import type { CanonicalBRIPeExecutionInputV1, CanonicalSignalV1 } from "./bripe-execution-v1";

export const MIG_STRUCTURAL_PDP_SCHEMA_VERSION = "mig.structural-pdp.v1" as const;
export type MigStructuralEnforcement = "ALLOW" | "ALLOW_WITH_CONTROL" | "REQUIRE_APPROVAL" | "BLOCK";

export interface PrincipalActivityRealityV1 {
  schema_version: typeof MIG_STRUCTURAL_PDP_SCHEMA_VERSION;
  activity_id: string;
  reality_id: string;
  reality_version: string;
  previous_reality_version: string | null;
  tenant_id: string;
  principal_id: string;
  credential_ref: string;
  client_or_agent_id: string;
  intent_id: string;
  tool_name: string;
  semantic_action: string;
  resource_refs: string[];
  destination?: string;
  volume_or_range?: string;
  operation_input_hash: string;
  observed_at: string;
  possible_outcomes: MigStructuralEnforcement[];
  prior_activity_context: Array<{ activity_id: string; reality_version: string; semantic_action: string; resource_refs: string[] }>;
  /** Observations are evidence, never an entitlement assertion. */
  observed_as_evidence: true;
  business_context?: { purpose: string; project_or_process: string };
}

export interface GraphDeltaV1 {
  schema_version: typeof MIG_STRUCTURAL_PDP_SCHEMA_VERSION;
  delta_id: string;
  base_reality_version: string;
  affected_node_ids: string[];
  added_edges: Array<{ from: string; to: string; relation: string }>;
  removed_edges: Array<{ from: string; to: string; relation: string }>;
  /** Bounded projection, not an enterprise graph recomputation. */
  affected_subgraph: { node_ids: string[]; edge_count: number };
}

export interface ContextualApprovalScopeV1 {
  schema_version: typeof MIG_STRUCTURAL_PDP_SCHEMA_VERSION;
  approval_id: string;
  tenant_id: string;
  approval_version: string;
  approval_hash: string;
  status: "active" | "revoked";
  approver_id: string;
  approver_role: string;
  approver_authorization_evidence: string;
  principal_id: string;
  client_or_agent_id: string;
  credential_ref?: string;
  intent_id: string;
  purpose: string;
  resource_refs: string[];
  path: string;
  destination?: string;
  volume_or_range?: string;
  valid_from: string;
  expires_at: string;
  project_or_process: string;
  operation_input_hash: string;
}

export interface StructuralDecisionRequestV1 {
  schema_version: typeof MIG_STRUCTURAL_PDP_SCHEMA_VERSION;
  request_id: string;
  tenant_id: string;
  principal_activity: PrincipalActivityRealityV1;
  proposed_delta: GraphDeltaV1;
  normalized_evidence: CanonicalSignalV1[];
  business_context: { purpose: string; project_or_process: string };
  approvals: ContextualApprovalScopeV1[];
  applicable_outcome_classes: MigStructuralEnforcement[];
  canonical_bripe_envelope: CanonicalBRIPeExecutionInputV1;
}

export interface StructuralDecisionResponseV1 {
  schema_version: typeof MIG_STRUCTURAL_PDP_SCHEMA_VERSION;
  request_id: string;
  canonical_execution_id?: string;
  render_allowed: true;
  canonical_authorized: true;
  raw_response_hash: string;
  proof_manifest_id: string;
  structural_facts: {
    propagation_score?: number;
    ttb_days?: number;
    intervention?: string;
    trust_label?: string;
    viable_path_count?: number;
    dominant_path_id?: string;
    structural_resistance?: number;
  };
}

export interface EnforcementResultV1 {
  schema_version: typeof MIG_STRUCTURAL_PDP_SCHEMA_VERSION;
  decision_id: string;
  decision_version: string;
  enforcement: MigStructuralEnforcement;
  reason: string;
  approval_id?: string;
  execution_result?: "not_executed" | "succeeded" | "failed";
}

export function assertBoundedConservedDelta(delta: GraphDeltaV1): void {
  const nodeIds = new Set(delta.affected_node_ids);
  if (!delta.delta_id || !delta.base_reality_version || nodeIds.size !== delta.affected_node_ids.length ||
      nodeIds.size > 128 || delta.affected_subgraph.edge_count !== delta.added_edges.length + delta.removed_edges.length ||
      delta.affected_subgraph.node_ids.some(id => !nodeIds.has(id)) ||
      [...delta.added_edges, ...delta.removed_edges].some(edge => !nodeIds.has(edge.from) || !nodeIds.has(edge.to))) {
    throw new Error("MIG_GRAPH_DELTA_INVALID_OR_UNBOUNDED");
  }
}

/** Approval matching is exact and expiry is evaluated at enforcement time. */
export function findExactContextualApproval(
  request: Pick<StructuralDecisionRequestV1, "principal_activity" | "business_context" | "approvals">,
  now = new Date(),
): ContextualApprovalScopeV1 | undefined {
  const a = request.principal_activity;
  return request.approvals.find(approval =>
    approval.principal_id === a.principal_id &&
    approval.tenant_id === a.tenant_id &&
    approval.client_or_agent_id === a.client_or_agent_id &&
    (!approval.credential_ref || approval.credential_ref === a.credential_ref) &&
    approval.status === "active" &&
    approval.intent_id === a.intent_id &&
    approval.purpose === request.business_context.purpose &&
    approval.project_or_process === request.business_context.project_or_process &&
    approval.operation_input_hash === a.operation_input_hash &&
    approval.path === a.tool_name &&
    approval.destination === a.destination &&
    approval.volume_or_range === a.volume_or_range &&
    approval.resource_refs.length === a.resource_refs.length &&
    approval.resource_refs.every(resource => a.resource_refs.includes(resource)) &&
    new Date(approval.valid_from).getTime() <= now.getTime() &&
    now.getTime() < new Date(approval.expires_at).getTime(),
  );
}

/** Pure PEP mapping; canonical facts are never recalculated here. */
export function mapStructuralDecisionToEnforcement(
  response: StructuralDecisionResponseV1,
  request: Pick<StructuralDecisionRequestV1, "principal_activity" | "business_context" | "approvals">,
  policy: { hard_block?: boolean; require_human_approval?: boolean; tolerance?: number; criticality?: "low" | "medium" | "high" | "critical" },
  now = new Date(),
): Pick<EnforcementResultV1, "enforcement" | "reason" | "approval_id"> {
  if (policy.hard_block) return { enforcement: "BLOCK", reason: "hard_policy_boundary" };
  if (!response.render_allowed || !response.canonical_authorized) return { enforcement: "BLOCK", reason: "canonical_structural_gate_blocked" };
  const approval = findExactContextualApproval(request, now);
  if (policy.require_human_approval && !approval) return { enforcement: "REQUIRE_APPROVAL", reason: "policy_requires_human_approval" };
  const pressure = response.structural_facts.propagation_score ?? 0;
  const tolerance = policy.tolerance ?? 1;
  if (pressure > tolerance || policy.criticality === "critical") {
    return approval
      ? { enforcement: "ALLOW_WITH_CONTROL", reason: "contextual_approval_with_intervention", approval_id: approval.approval_id }
      : { enforcement: "REQUIRE_APPROVAL", reason: "structural_pressure_requires_contextual_approval" };
  }
  return response.structural_facts.intervention
    ? { enforcement: "ALLOW_WITH_CONTROL", reason: "canonical_intervention_required" }
    : { enforcement: "ALLOW", reason: "canonical_structural_gate_allowed" };
}