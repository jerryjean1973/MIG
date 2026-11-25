/**
 * Deterministic, cutoff-bound replay adapter for the MIG Structural PDP.
 * It reconstructs historical requests and reuses the canonical PEP mapping;
 * it is not a second inference or decision engine.
 */
import { createHash } from "crypto";
import {
  mapStructuralDecisionToEnforcement,
  type ContextualApprovalScopeV1,
  type EnforcementResultV1,
  type GraphDeltaV1,
  type MigStructuralEnforcement,
  type PrincipalActivityRealityV1,
  type StructuralDecisionRequestV1,
  type StructuralDecisionResponseV1,
} from "../../shared/contracts/mig-structural-pdp-v1";
import type { CanonicalBRIPeExecutionInputV1, CanonicalSignalV1 } from "../../shared/contracts/bripe-execution-v1";
import { isMigEnforcementDispatchable } from "./mig-consequential-operation";
import { queryStructuralHistory } from "../../shared/persistence/structural-history-store";

export const MIG_REPLAY_ADAPTER_VERSION = "mig-structural-replay-v1";

export interface MigReplayEvent {
  event_id: string;
  occurred_at: string;
  known_outcome?: "adverse" | "legitimate";
  workflow_class: "sensitive_data" | "bulk" | "migration" | "administrator" | "finance" | "security" | "data_science";
  credential_type: "api_key" | "oauth_subject";
  principal_activity: PrincipalActivityRealityV1;
  proposed_delta: GraphDeltaV1;
  evidence: CanonicalSignalV1[];
  canonical_bripe_envelope: CanonicalBRIPeExecutionInputV1;
  canonical_run_ref: string;
  canonical_request_id: string;
  policy: { hard_block?: boolean; require_human_approval?: boolean; tolerance?: number; criticality?: "low" | "medium" | "high" | "critical" };
  approvals: ContextualApprovalScopeV1[];
  execution_receipt_ref: string;
}

export interface MigReplayCanonicalRun {
  canonical_run_ref: string;
  tenant_id: string;
  principal_id: string;
  reality_id: string;
  request_id: string;
  request: StructuralDecisionRequestV1;
  policy: MigReplayEvent["policy"];
  cutoff_at: string;
  evidence_hash: string;
  envelope_hash: string;
  response: StructuralDecisionResponseV1;
  engine_identity: { engine_id: string; engine_version: string; policy_version: string };
}

export interface MigReplayExecutionReceipt {
  execution_receipt_ref: string;
  tenant_id: string;
  principal_id: string;
  request_id: string;
  canonical_execution_id: string;
  receipt: {
    operation_input_hash: string;
    result: "not_executed" | "succeeded" | "failed";
    downstream_dispatched: boolean;
    result_hash?: string;
  };
  receipt_hash: string;
}

export interface MigReplayRepository {
  getCanonicalRun(ref: string, tenantId: string, principalId: string): Promise<MigReplayCanonicalRun | undefined>;
  getExecutionReceipt(ref: string, tenantId: string, principalId: string): Promise<MigReplayExecutionReceipt | undefined>;
}

export interface MigReplayDecisionArtifact {
  event_id: string;
  cutoff_at: string;
  request: StructuralDecisionRequestV1;
  canonical_response: StructuralDecisionResponseV1;
  enforcement: EnforcementResultV1;
  credential_type: MigReplayEvent["credential_type"];
  workflow_class: MigReplayEvent["workflow_class"];
  approval?: ContextualApprovalScopeV1;
  engine_identity: MigReplayCanonicalRun["engine_identity"];
  policy_identity: { version: string; hash: string };
  execution_receipt: MigReplayExecutionReceipt;
  artifact_hash: string;
}

export interface MigReplayReport {
  schema_version: "mig.structural-replay.v1";
  replay_id: string;
  adapter_version: typeof MIG_REPLAY_ADAPTER_VERSION;
  decisions: MigReplayDecisionArtifact[];
  milestones: {
    adverse_outcome_first_viable_at?: string;
    dominant_path_emerged_at?: string;
    resistance_materially_compressed_at?: string;
    first_constrain_at?: string;
    first_require_approval_at?: string;
    first_block_at?: string;
    lead_time_to_known_adverse_outcome_ms?: number;
  };
  quality: {
    legitimate_workflow_count: number;
    false_intervention_count: number;
    false_intervention_rate: number;
    legitimate_workflows: Record<string, { total: number; interrupted: number }>;
  };
  report_hash: string;
}

function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter(key => record[key] !== undefined)
    .sort()
    .map(key => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function hashMigReplayValue(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function createMigReplayRequestId(eventId: string): string {
  return `mig_replay_req_${hashMigReplayValue(eventId).slice(0, 24)}`;
}

/** Production replay reader over the canonical tenant-scoped append-only history store. */
export class StructuralHistoryMigReplayRepository implements MigReplayRepository {
  async getCanonicalRun(ref: string, tenantId: string, principalId: string): Promise<MigReplayCanonicalRun | undefined> {
    const rows = await queryStructuralHistory({ objectType: "decision", objectId: ref, tenantId, ownerId: principalId, limit: 20 });
    const row = rows.find(item => item.triggerReason === "mig_structural_pdp");
    const request = row?.payload.request as StructuralDecisionRequestV1 | undefined;
    const response = row?.payload.response as StructuralDecisionResponseV1 | undefined;
    const policy = row?.payload.policy_identity as { version?: string } | undefined;
    if (!row || !request || !response) return undefined;
    return {
      canonical_run_ref: ref, tenant_id: row.tenantId, principal_id: row.ownerId,
      reality_id: request.principal_activity.reality_id, request_id: request.request_id,
      request,
      policy: ((row.payload.policy_identity as { policy?: MigReplayEvent["policy"] } | undefined)?.policy ?? {}),
      cutoff_at: request.principal_activity.observed_at,
      evidence_hash: hashMigReplayValue(request.normalized_evidence),
      envelope_hash: hashMigReplayValue(request.canonical_bripe_envelope),
      response,
      engine_identity: {
        engine_id: "canonical-bripe",
        engine_version: response.canonical_execution_id,
        policy_version: policy?.version ?? "unknown",
      },
    };
  }

  async getExecutionReceipt(ref: string, tenantId: string, principalId: string): Promise<MigReplayExecutionReceipt | undefined> {
    const rows = await queryStructuralHistory({ objectType: "decision", objectId: ref, tenantId, ownerId: principalId, limit: 20 });
    const decision = rows.find(item => item.triggerReason === "mig_structural_pdp");
    const execution = rows.find(item => item.triggerReason === "mig_material_execution_result");
    const request = decision?.payload.request as StructuralDecisionRequestV1 | undefined;
    const response = decision?.payload.response as StructuralDecisionResponseV1 | undefined;
    const result = decision?.payload.result as EnforcementResultV1 | undefined;
    if (!decision || !request || !response || !result) return undefined;
    if (!execution) return undefined;
    const receipt = {
      operation_input_hash: String(execution.payload.operation_input_hash),
      result: execution.payload.execution_result as "not_executed" | "succeeded" | "failed",
      downstream_dispatched: execution.payload.downstream_dispatched === true,
      result_hash: typeof execution.payload.result_hash === "string" ? execution.payload.result_hash : undefined,
    };
    return {
      execution_receipt_ref: ref, tenant_id: decision.tenantId, principal_id: decision.ownerId,
      request_id: request.request_id, canonical_execution_id: response.canonical_execution_id,
      receipt, receipt_hash: hashMigReplayValue(receipt),
    };
  }
}

export async function replayPersistedMigStructuralTimeline(
  replayId: string,
  sourceEvents: readonly MigReplayEvent[],
): Promise<MigReplayReport> {
  return replayMigStructuralTimeline(replayId, sourceEvents, new StructuralHistoryMigReplayRepository());
}

/**
 * Replays immutable events in chronological order. Every decision sees only
 * evidence at or before its own cutoff; future-dated evidence fails closed.
 */
export async function replayMigStructuralTimeline(
  replayId: string,
  sourceEvents: readonly MigReplayEvent[],
  repository: MigReplayRepository,
): Promise<MigReplayReport> {
  const events = [...sourceEvents].sort((a, b) =>
    Date.parse(a.occurred_at) - Date.parse(b.occurred_at) || a.event_id.localeCompare(b.event_id));
  const decisions: MigReplayDecisionArtifact[] = [];
  const streamState = new Map<string, { activities: PrincipalActivityRealityV1[]; resistance?: number }>();
  const adverse = events.find(event => event.known_outcome === "adverse");
  const adverseStreamKey = adverse
    ? `${adverse.principal_activity.tenant_id}|${adverse.principal_activity.principal_id}|${adverse.principal_activity.reality_id}`
    : undefined;
  const milestones: MigReplayReport["milestones"] = {};

  for (const event of events) {
    const cutoff = Date.parse(event.occurred_at);
    if (!Number.isFinite(cutoff)) throw new Error("MIG_REPLAY_CUTOFF_INVALID");
    if (event.evidence.some(item => !Number.isFinite(Date.parse(item.timestamp)))) throw new Error("MIG_REPLAY_EVIDENCE_TIMESTAMP_INVALID");
    if (event.evidence.some(item => Date.parse(item.timestamp) > cutoff)) throw new Error("MIG_REPLAY_FUTURE_EVIDENCE");
    if (event.principal_activity.observed_at !== event.occurred_at) throw new Error("MIG_REPLAY_ACTIVITY_CUTOFF_MISMATCH");
    const evidence = event.evidence.filter(item => Date.parse(item.timestamp) <= cutoff);
    const streamKey = `${event.principal_activity.tenant_id}|${event.principal_activity.principal_id}|${event.principal_activity.reality_id}`;
    const state = streamState.get(streamKey) ?? { activities: [] };
    const predecessor = state.activities.at(-1);
    if (event.proposed_delta.base_reality_version !== (predecessor?.reality_version ?? "0")) {
      throw new Error("MIG_REPLAY_REALITY_CONTINUITY_BROKEN");
    }
    if (event.principal_activity.previous_reality_version !== (predecessor?.reality_version ?? null)) {
      throw new Error("MIG_REPLAY_ACTIVITY_CONTINUITY_BROKEN");
    }
    const principalActivity = event.principal_activity;
    const request: StructuralDecisionRequestV1 = {
      schema_version: "mig.structural-pdp.v1",
      request_id: event.canonical_request_id,
      tenant_id: event.principal_activity.tenant_id,
      principal_activity: principalActivity,
      proposed_delta: event.proposed_delta,
      normalized_evidence: evidence,
      business_context: event.principal_activity.business_context!,
      approvals: event.approvals,
      applicable_outcome_classes: ["ALLOW", "ALLOW_WITH_CONTROL", "REQUIRE_APPROVAL", "BLOCK"],
      canonical_bripe_envelope: { ...event.canonical_bripe_envelope, signals: evidence },
    };
    const boundEnvelope = request.canonical_bripe_envelope;
    if (boundEnvelope.execution_mode !== "replay" || boundEnvelope.replay?.enabled !== true ||
        boundEnvelope.replay.actual_outcome_hidden !== true || boundEnvelope.replay.cutoff_date !== event.occurred_at) {
      throw new Error("MIG_REPLAY_ENVELOPE_INVALID");
    }
    const canonicalRun = await repository.getCanonicalRun(
      event.canonical_run_ref, event.principal_activity.tenant_id, event.principal_activity.principal_id);
    if (!canonicalRun ||
        canonicalRun.canonical_run_ref !== event.canonical_run_ref ||
        canonicalRun.tenant_id !== event.principal_activity.tenant_id ||
        canonicalRun.principal_id !== event.principal_activity.principal_id ||
        canonicalRun.reality_id !== event.principal_activity.reality_id ||
        canonicalRun.request_id !== request.request_id ||
        hashMigReplayValue(canonicalRun.request) !== hashMigReplayValue(request) ||
        hashMigReplayValue(canonicalRun.policy) !== hashMigReplayValue(event.policy) ||
        canonicalRun.cutoff_at !== event.occurred_at ||
        canonicalRun.evidence_hash !== hashMigReplayValue(evidence) ||
        canonicalRun.envelope_hash !== hashMigReplayValue(boundEnvelope) ||
        canonicalRun.response.request_id !== request.request_id ||
        canonicalRun.response.canonical_execution_id === undefined ||
        canonicalRun.response.proof_manifest_id.length === 0) {
      throw new Error("MIG_REPLAY_CANONICAL_RUN_BINDING_INVALID");
    }
    const mapped = mapStructuralDecisionToEnforcement(canonicalRun.response, request, event.policy, new Date(cutoff));
    const executionReceipt = await repository.getExecutionReceipt(
      event.execution_receipt_ref, event.principal_activity.tenant_id, event.principal_activity.principal_id);
    const dispatchable = isMigEnforcementDispatchable(mapped.enforcement);
    if (!executionReceipt || executionReceipt.execution_receipt_ref !== event.execution_receipt_ref ||
        executionReceipt.tenant_id !== event.principal_activity.tenant_id ||
        executionReceipt.principal_id !== event.principal_activity.principal_id ||
        executionReceipt.request_id !== request.request_id ||
        executionReceipt.canonical_execution_id !== canonicalRun.response.canonical_execution_id ||
        executionReceipt.receipt.operation_input_hash !== principalActivity.operation_input_hash ||
        executionReceipt.receipt_hash !== hashMigReplayValue(executionReceipt.receipt) ||
        executionReceipt.receipt.downstream_dispatched !== dispatchable ||
        (dispatchable && executionReceipt.receipt.result === "not_executed") ||
        (!dispatchable && executionReceipt.receipt.result !== "not_executed")) {
      throw new Error("MIG_REPLAY_EXECUTION_RECEIPT_INVALID");
    }
    const enforcement: EnforcementResultV1 = {
      schema_version: "mig.structural-pdp.v1",
      decision_id: `mig_replay_dec_${hashMigReplayValue({ replayId, event: event.event_id, request, response: canonicalRun.response, policy: event.policy }).slice(0, 24)}`,
      decision_version: event.principal_activity.reality_version,
      ...mapped,
      execution_result: executionReceipt.receipt.result,
    };
    const approval = event.approvals.find(item => item.approval_id === enforcement.approval_id);
    const artifactBasis = {
      event_id: event.event_id, cutoff_at: event.occurred_at, request,
      canonical_response: canonicalRun.response, enforcement,
      credential_type: event.credential_type, workflow_class: event.workflow_class,
      approval, engine_identity: canonicalRun.engine_identity,
      policy_identity: { version: canonicalRun.engine_identity.policy_version, hash: hashMigReplayValue(event.policy) },
      execution_receipt: executionReceipt,
    };
    decisions.push({ ...artifactBasis, artifact_hash: hashMigReplayValue(artifactBasis) });
    state.activities.push(principalActivity);
    streamState.set(streamKey, state);

    const facts = canonicalRun.response.structural_facts;
    if (streamKey === adverseStreamKey && (!adverse || cutoff <= Date.parse(adverse.occurred_at))) {
      if (!milestones.adverse_outcome_first_viable_at && (facts.viable_path_count ?? 0) > 0) milestones.adverse_outcome_first_viable_at = event.occurred_at;
      if (!milestones.dominant_path_emerged_at && facts.dominant_path_id) milestones.dominant_path_emerged_at = event.occurred_at;
      if (!milestones.resistance_materially_compressed_at && state.resistance !== undefined &&
          facts.structural_resistance !== undefined && state.resistance - facts.structural_resistance >= .2) {
        milestones.resistance_materially_compressed_at = event.occurred_at;
      }
      if (facts.structural_resistance !== undefined) state.resistance = facts.structural_resistance;
      if (!milestones.first_constrain_at && enforcement.enforcement === "ALLOW_WITH_CONTROL") milestones.first_constrain_at = event.occurred_at;
      if (!milestones.first_require_approval_at && enforcement.enforcement === "REQUIRE_APPROVAL") milestones.first_require_approval_at = event.occurred_at;
      if (!milestones.first_block_at && enforcement.enforcement === "BLOCK") milestones.first_block_at = event.occurred_at;
    }
  }

  if (adverse && milestones.adverse_outcome_first_viable_at) {
    milestones.lead_time_to_known_adverse_outcome_ms =
      Math.max(0, Date.parse(adverse.occurred_at) - Date.parse(milestones.adverse_outcome_first_viable_at));
  }
  const legitimateWorkflows: MigReplayReport["quality"]["legitimate_workflows"] = {};
  let legitimateCount = 0, falseInterventions = 0;
  events.forEach((event, index) => {
    if (event.known_outcome !== "legitimate") return;
    legitimateCount++;
    const interrupted = decisions[index].enforcement.enforcement === "BLOCK" || decisions[index].enforcement.enforcement === "REQUIRE_APPROVAL";
    if (interrupted) falseInterventions++;
    const bucket = legitimateWorkflows[event.workflow_class] ?? { total: 0, interrupted: 0 };
    bucket.total++;
    if (interrupted) bucket.interrupted++;
    legitimateWorkflows[event.workflow_class] = bucket;
  });
  const basis = {
    schema_version: "mig.structural-replay.v1" as const, replay_id: replayId,
    adapter_version: MIG_REPLAY_ADAPTER_VERSION as typeof MIG_REPLAY_ADAPTER_VERSION, decisions, milestones,
    quality: {
      legitimate_workflow_count: legitimateCount,
      false_intervention_count: falseInterventions,
      false_intervention_rate: legitimateCount ? falseInterventions / legitimateCount : 0,
      legitimate_workflows: legitimateWorkflows,
    },
  };
  return { ...basis, report_hash: hashMigReplayValue(basis) };
}

/** A denied structural result is never eligible for downstream MCP dispatch. */
export async function dispatchReplayApprovedOperation<T>(
  artifact: MigReplayDecisionArtifact,
  dispatch: () => Promise<T>,
): Promise<T> {
  if (!isMigEnforcementDispatchable(artifact.enforcement.enforcement)) {
    throw new Error("MIG_REPLAY_DOWNSTREAM_DISPATCH_DENIED");
  }
  return dispatch();
}