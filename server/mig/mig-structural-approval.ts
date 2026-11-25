/** Server-owned, immutable contextual approvals. Never deserialize approvals from tool input. */
import { randomUUID, createHash } from "crypto";
import { appendStructuralHistory, queryStructuralHistory } from "../../shared/persistence/structural-history-store";
import type { ContextualApprovalScopeV1 } from "../../shared/contracts/mig-structural-pdp-v1";

export async function createMigContextualApproval(
  tenantId: string, approverId: string,
  approval: Omit<ContextualApprovalScopeV1, "schema_version" | "approval_id" | "tenant_id" | "approval_version" | "approval_hash" | "status" | "approver_id" | "approver_role" | "approver_authorization_evidence">,
  authorization: { role: string; evidence: string },
): Promise<ContextualApprovalScopeV1> {
  if (!approverId) throw new Error("MIG_APPROVER_REQUIRED");
  if (approverId === approval.principal_id) throw new Error("MIG_APPROVAL_SOD_VIOLATION");
  if (!approval.resource_refs.length || !approval.purpose.trim() || !approval.path.trim() || !approval.project_or_process.trim()) throw new Error("MIG_APPROVAL_SCOPE_INVALID");
  const from = Date.parse(approval.valid_from), until = Date.parse(approval.expires_at);
  if (!Number.isFinite(from) || !Number.isFinite(until) || until <= from) throw new Error("MIG_APPROVAL_VALIDITY_INVALID");
  const basis = {
    principal_id: approval.principal_id, client_or_agent_id: approval.client_or_agent_id,
    credential_ref: approval.credential_ref, intent_id: approval.intent_id, purpose: approval.purpose,
    resource_refs: [...approval.resource_refs], path: approval.path, destination: approval.destination,
    volume_or_range: approval.volume_or_range, valid_from: approval.valid_from, expires_at: approval.expires_at,
    project_or_process: approval.project_or_process,
    operation_input_hash: approval.operation_input_hash,
    schema_version: "mig.structural-pdp.v1" as const, approval_id: `mig_approval_${randomUUID()}`,
    tenant_id: tenantId, approval_version: "1", status: "active" as const, approver_id: approverId,
    approver_role: authorization.role, approver_authorization_evidence: authorization.evidence };
  const approval_hash = createHash("sha256").update(JSON.stringify(basis)).digest("hex");
  const record: ContextualApprovalScopeV1 = { ...basis, approval_hash };
  await appendStructuralHistory({
    objectType: "control", objectId: record.approval_id, ownerId: record.principal_id, tenantId,
    payload: record,
    triggerReason: "mig_contextual_approval_granted", schemaVersion: record.schema_version,
    idempotencyKey: `${tenantId}:${record.approval_id}`,
  });
  return record;
}

export async function resolveMigContextualApprovals(
  tenantId: string, principalId: string, approvalIds: string[],
): Promise<ContextualApprovalScopeV1[]> {
  const unique = [...new Set(approvalIds)];
  const records = await Promise.all(unique.map(async id => {
    const rows = await queryStructuralHistory({ objectType: "control", objectId: id, ownerId: principalId, tenantId, limit: 1 });
    const record = rows[0]?.payload as ContextualApprovalScopeV1 | undefined;
    if (!record) return undefined;
    const { approval_hash, ...basis } = record;
    const expected = createHash("sha256").update(JSON.stringify(basis)).digest("hex");
    if (approval_hash !== expected || record.status !== "active" || record.tenant_id !== tenantId || record.principal_id !== principalId) return undefined;
    return record;
  }));
  if (records.some(record => !record)) throw new Error("MIG_APPROVAL_NOT_FOUND_OR_NOT_OWNED");
  return records.filter((record): record is ContextualApprovalScopeV1 => !!record);
}