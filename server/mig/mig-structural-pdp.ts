/** MIG adapter to the canonical BRIPe gate/executor; no engine logic lives here. */
import { randomUUID, createHash } from "crypto";
import { appendStructuralHistory } from "../../shared/persistence/structural-history-store";
import {
  assertBoundedConservedDelta, mapStructuralDecisionToEnforcement,
  type EnforcementResultV1, type StructuralDecisionRequestV1, type StructuralDecisionResponseV1,
} from "../../shared/contracts/mig-structural-pdp-v1";
import { validateBRIPeEnvelopeV1 } from "../../shared/contracts/bripe-execution-v1";
import { bripeMcpAdapter } from "./mig-bripe-adapter";

const MIG_STRUCTURAL_HISTORY_SCHEMA_VERSION = "mig-pdp-v1";

export async function evaluateMigStructuralDecision(
  request: StructuralDecisionRequestV1,
  policy: { hard_block?: boolean; require_human_approval?: boolean; tolerance?: number; criticality?: "low" | "medium" | "high" | "critical" } = {},
): Promise<EnforcementResultV1> {
  assertBoundedConservedDelta(request.proposed_delta);
  if (request.canonical_bripe_envelope.tenant_id && request.canonical_bripe_envelope.tenant_id !== request.tenant_id) {
    throw new Error("MIG_STRUCTURAL_TENANT_MISMATCH");
  }
  const envelope = {
    ...request.canonical_bripe_envelope,
    tenant_id: request.tenant_id,
    signals: request.normalized_evidence,
  };
  const gate = await validateBRIPeEnvelopeV1(envelope);
  if (!gate.ok) {
    throw new Error(`MIG_CANONICAL_BRIPE_GATE_REJECTED:${gate.violations.map(v => v.code).join(",")}`);
  }
  // This invokes the existing MCP canonical envelope validation, snapshot
  // hydration and BRIPe executor; MIG never calls or reconstructs an engine.
  const raw = await bripeMcpAdapter.executeTool("run_bripe_decision", {
    canonical_envelope: envelope,
  }, { tenantId: request.tenant_id });
  const response = parseCanonicalMigDecisionResponse(raw, request.request_id);
  const mapped = mapStructuralDecisionToEnforcement(response, request, policy);
  const result: EnforcementResultV1 = {
    schema_version: "mig.structural-pdp.v1", decision_id: `mig_dec_${randomUUID()}`,
    decision_version: request.principal_activity.reality_version,
    ...mapped, execution_result: "not_executed",
  };
  const matchedApproval = request.approvals.find(a => a.approval_id === result.approval_id);
  const intervention = response.structural_facts.intervention;
  const policyIdentity = { version: "mig-structural-policy-v1", hash: createHash("sha256").update(JSON.stringify(policy)).digest("hex"), policy };
  await appendStructuralHistory({
    objectType: "decision", objectId: result.decision_id, ownerId: request.principal_activity.principal_id,
    tenantId: request.tenant_id, payload: {
      request, response, canonical_raw_response: raw, canonical_response_hash: response.raw_response_hash, result,
      operation_input_hash: request.principal_activity.operation_input_hash,
      policy_identity: policyIdentity, approval_identity: matchedApproval,
      intervention_identity: intervention,
      intervention_hash: intervention ? createHash("sha256").update(intervention).digest("hex") : undefined,
      snapshot_ids: { cb: request.canonical_bripe_envelope.cb_snapshot_id, essg: request.canonical_bripe_envelope.essg_snapshot_id },
    }, triggerReason: "mig_structural_pdp",
    schemaVersion: MIG_STRUCTURAL_HISTORY_SCHEMA_VERSION, contextId: request.principal_activity.reality_version,
    idempotencyKey: `${request.tenant_id}:${request.request_id}:decision`,
  });
  return result;
}

export function parseCanonicalMigDecisionResponse(raw: unknown, requestId: string): StructuralDecisionResponseV1 {
  if (!raw || typeof raw !== "object") throw new Error("MIG_CANONICAL_BRIPE_RESPONSE_INVALID");
  const r = raw as Record<string, unknown>;
  const decision = r.decision as Record<string, unknown> | undefined;
  const trust = r.decision_trust as Record<string, unknown> | undefined;
  const sufficiency = r.decision_sufficiency as Record<string, unknown> | undefined;
  const proof = r.proof_package as Record<string, unknown> | undefined;
  const cce = proof?.cce as Record<string, unknown> | undefined;
  const metadata = r.metadata as Record<string, unknown> | undefined;
  const propagation = decision?.propagation_score;
  const ttb = decision?.ttb_days;
  const ttf = decision?.ttf_days;
  const trustLabel = trust?.trust_label;
  if (r.ok !== true || r.render_allowed !== true || proof?.authorized !== true || cce?.authorized !== true ||
      typeof metadata?.run_id !== "string" || !decision ||
      (trustLabel !== "AUTHORIZED" && trustLabel !== "SUPPORTED") ||
      sufficiency?.status !== "Sufficient" || sufficiency.operational_readiness !== "Ready" ||
      typeof propagation !== "number" || !Number.isFinite(propagation) || propagation < 0 || propagation > 1 ||
      (ttb !== undefined && (typeof ttb !== "number" || !Number.isFinite(ttb) || ttb < 0)) ||
      (ttf !== undefined && (typeof ttf !== "number" || !Number.isFinite(ttf) || ttf < 0))) {
    throw new Error("MIG_CANONICAL_BRIPE_RESPONSE_INVALID");
  }
  const proofId = typeof proof.manifest_id === "string" ? proof.manifest_id
    : typeof (r.adam_authorization as Record<string, unknown> | undefined)?.proof_manifest_id === "string"
      ? (r.adam_authorization as Record<string, unknown>).proof_manifest_id as string : undefined;
  if (!proofId) throw new Error("MIG_CANONICAL_BRIPE_RESPONSE_INVALID");
  const hash = createHash("sha256").update(JSON.stringify(raw)).digest("hex");
  return {
    schema_version: "mig.structural-pdp.v1", request_id: requestId, canonical_execution_id: metadata.run_id,
    render_allowed: true, canonical_authorized: true, raw_response_hash: hash, proof_manifest_id: proofId,
    structural_facts: {
      propagation_score: propagation as number | undefined,
      ttb_days: typeof ttb === "number" ? ttb : undefined,
      intervention: typeof decision?.smallest_fix === "string" ? decision.smallest_fix : undefined,
      trust_label: trustLabel,
      viable_path_count: typeof decision?.viable_path_count === "number" ? decision.viable_path_count : undefined,
      dominant_path_id: typeof decision?.dominant_path_id === "string" ? decision.dominant_path_id : undefined,
      structural_resistance: typeof decision?.structural_resistance === "number" ? decision.structural_resistance : undefined,
    },
  };
}

/** Execution is a second immutable record, never an update to the decision. */
export async function appendMigStructuralExecutionResult(
  input: {
    tenantId: string; principalId: string; decisionId: string; requestId: string; realityVersion: string;
    deltaId: string; operationInputHash: string; executedPayloadHash: string; policyIdentity: Record<string, unknown>;
    approvalId?: string; interventionId?: string; outcome: "not_executed" | "succeeded" | "failed";
    downstreamDispatched?: boolean; resultHash?: string; executionError?: string;
    pathFingerprint?: string; projectionId?: string;
  },
): Promise<void> {
  await appendStructuralHistory({
    objectType: "decision", objectId: input.decisionId, ownerId: input.principalId, tenantId: input.tenantId,
    payload: { decision_id: input.decisionId, request_id: input.requestId, reality_version: input.realityVersion,
      delta_id: input.deltaId, policy_identity: input.policyIdentity, approval_id: input.approvalId,
      operation_input_hash: input.operationInputHash, executed_payload_hash: input.executedPayloadHash,
      path_fingerprint: input.pathFingerprint, intent_access_projection_id: input.projectionId,
      intervention_id: input.interventionId, execution_result: input.outcome, result_hash: input.resultHash,
      downstream_dispatched: input.downstreamDispatched ?? input.outcome !== "not_executed",
      execution_error: input.executionError },
    triggerReason: "mig_material_execution_result", schemaVersion: MIG_STRUCTURAL_HISTORY_SCHEMA_VERSION,
    idempotencyKey: `${input.tenantId}:${input.decisionId}:execution:${input.outcome}`,
  });
}
