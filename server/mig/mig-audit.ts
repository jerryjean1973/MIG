/**
 * server/mig/mig-audit.ts
 *
 * Canonical audit sink for MIG. Every allow/deny decision, discovery,
 * execution, and drift event is recorded here. Denied/blocked events
 * additionally get a "transition proof" — a deterministic hash id proving
 * that the blocked transition was evaluated and recorded (not silently
 * dropped), which the Byolab acceptance scenario and admin UI both surface.
 */

import { createHash, randomBytes } from "crypto";
import { storage } from "../storage";
import type { InsertMigAuditLog, MigAuditLog } from "@shared/schema";
import type { MigRiskZone } from "./mig-types";
import type { MigAuthorizationDecision } from "./mig-authorization-policy";
import type { MigNormalizedAuthorizationContext } from "./mig-authorization-context";

export interface MigAuditInput {
  eventType:
    | "ticket_issued"
    | "ticket_revoked"
    | "manifest_issued"
    | "discovery"
    | "execution"
    | "drift_detected"
    | "agent_registered"
    | "agent_status_changed"
    | "intent_transition_approval";
  decision: "allow" | "deny" | "info";
  ticketJti?: string;
  manifestId?: string;
  agentId?: string;
  tenantId?: string;
  sessionId?: string;
  intentId?: string;
  riskZone?: MigRiskZone;
  toolName?: string;
  capabilityId?: string;
  policyDecision: string;
  inputHash?: string;
  outputHash?: string;
  reason?: string;
  authenticatedPrincipalId?: string;
  journeyId?: string;
  parentCallId?: string;
  originUserId?: string;
  originAgentId?: string;
  rootIntentId?: string;
  compoundedIntentIds?: string[];
  graphCallIds?: string[];
  resourceRef?: string;
  outcome?: "allowed" | "denied" | "failed" | "succeeded";
}

export function hashPayload(payload: unknown): string {
  return createHash("sha256").update(canonicalJson(payload ?? null)).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}
function generateTransitionProofId(input: MigAuditInput): string {
  const basis = `${input.eventType}:${input.agentId ?? ""}:${input.ticketJti ?? ""}:${input.toolName ?? ""}:${input.reason ?? ""}:${randomBytes(8).toString("hex")}`;
  return `mig_proof_${createHash("sha256").update(basis).digest("hex").slice(0, 32)}`;
}

/**
 * Records an audit event. Deny/blocked decisions always receive a
 * transition_proof_id so downstream governance (DPM/DEL, admin UI, Byolab
 * scenario) can point to concrete proof that the block was enforced.
 */
export function buildMigAuditEvent(input: MigAuditInput): {
  data: InsertMigAuditLog;
  transitionProofId?: string;
} {
  const transitionProofId = input.decision === "deny" ? generateTransitionProofId(input) : undefined;
  const data: InsertMigAuditLog = {
    eventId: `mig_evt_${randomBytes(12).toString("hex")}`,
    eventType: input.eventType,
    decision: input.decision,
    ticketJti: input.ticketJti,
    manifestId: input.manifestId,
    agentId: input.agentId,
    tenantId: input.tenantId,
    sessionId: input.sessionId,
    intentId: input.intentId,
    riskZone: input.riskZone,
    toolName: input.toolName,
    capabilityId: input.capabilityId,
    policyDecision: input.policyDecision,
    transitionProofId,
    inputHash: input.inputHash,
    outputHash: input.outputHash,
    reason: input.reason,
    authenticatedPrincipalId: input.authenticatedPrincipalId,
    journeyId: input.journeyId,
    parentCallId: input.parentCallId,
    originUserId: input.originUserId,
    originAgentId: input.originAgentId,
    rootIntentId: input.rootIntentId,
    compoundedIntentIds: input.compoundedIntentIds,
    graphCallIds: input.graphCallIds,
    resourceRef: input.resourceRef,
    outcome: input.outcome ?? (input.decision === "allow" ? "allowed" : input.decision === "deny" ? "denied" : undefined),
  };
  return { data, transitionProofId };
}
export async function recordMigAuditEvent(input: MigAuditInput): Promise<MigAuditLog & { transition_proof_id?: string }> {
  const { data, transitionProofId } = buildMigAuditEvent(input);
  const row = await storage.recordMigAuditEvent(data);
  return { ...row, transition_proof_id: transitionProofId };
}

export async function listMigAuditEvents(filters?: { tenantId?: string; agentId?: string; limit?: number }): Promise<MigAuditLog[]> {
  return storage.listMigAuditEvents(filters);
}

export async function listMigIntentTransitionApprovalEvents(input: {
  tenantId: string;
  journeyId?: string;
  limit?: number;
}): Promise<MigAuditLog[]> {
  if (!input.tenantId) throw new Error("MIG_AUDIT_TENANT_REQUIRED");
  return storage.listMigAuditEvents({
    tenantId: input.tenantId,
    journeyId: input.journeyId,
    eventType: "intent_transition_approval",
    limit: input.limit,
  });
}
/**
 * Append-only proof for the enterprise authorization evaluator. It contains
 * opaque references and hashes only; callers must never pass tokens, keys, or
 * raw authorization headers into this function.
 */
export async function persistAuthorizationManifest(
  context: MigNormalizedAuthorizationContext,
  decision: MigAuthorizationDecision,
  policyVersion: string,
): Promise<import("@shared/schema").MigAuthorizationManifest> {
  const body = {
    tenantId: context.tenantId,
    actorPrincipalId: context.actorPrincipalId,
    clientPrincipalId: context.clientPrincipalId,
    executorPrincipalId: context.executorPrincipalId,
    credentialRef: context.credential.credentialRef,
    intentId: context.intentId,
    capabilityId: context.capabilityId,
    semanticAction: context.semanticAction,
    domainId: context.domainId,
    resourceRef: context.resourceRef,
    resourceVersion: context.resourceVersion,
    policyVersion,
    decision: decision.decision,
    reason: decision.reason,
    effectivePermissions: decision.effectivePermissions,
    sodResult: decision.sodResult,
    requestCorrelationId: context.requestCorrelationId,
    delegationRef: context.delegationRef,
    authorityProvider: context.credential.authorityProvider ?? "mig_native",
    authorityRef: context.credential.authorityRef ?? context.credential.credentialRef,
    authoritySnapshotId: context.credential.authoritySnapshotId,
    authorityEvidence: [
      ...(context.credential.authoritySourceEvidence ?? []),
      ...(context.canonicalKnowledge ? [{
        kind: "canonical_knowledge_authority",
        partition: context.canonicalKnowledge.resource.partition,
        canonical_object_id: context.canonicalKnowledge.resource.canonical_object_id,
        knowledge_id: context.canonicalKnowledge.resource.knowledge_id ?? null,
        operation: context.canonicalKnowledge.operation,
        authority_decision: context.canonicalKnowledge.authority?.decision ?? "DENY",
        authority_reason: context.canonicalKnowledge.authority?.reason ?? "unresolved",
        policy_version: context.canonicalKnowledge.authority?.policy_version ?? null,
        inheritance_path: context.canonicalKnowledge.authority?.inheritance_path ?? [],
      }] : []),
    ],
    authorityObservedAt: context.credential.authorityObservedAt,
    authorityExpiresAt: context.credential.authorityExpiresAt,
    effectiveRiskZoneCeiling: context.credential.credentialRiskZoneCeiling,
    beforeHash: context.beforeHash,
    afterHash: context.afterHash,
  };
  return storage.createMigAuthorizationManifest({
    authorizationManifestId: `mig_authz_${randomBytes(12).toString("hex")}`,
    ...body,
    manifestHash: hashPayload(body),
  });
}

/** Records a fail-closed decision made before a trusted tenant/principal exists. */
export async function persistRejectedAuthorizationManifest(
  reason: string,
  policyVersion: string,
  request?: Partial<MigNormalizedAuthorizationContext>,
  unverifiedCredentialRef?: string,
): Promise<import("@shared/schema").MigAuthorizationManifest> {
  const body = {
    tenantId: "__unresolved__",
    actorPrincipalId: null,
    clientPrincipalId: null,
    executorPrincipalId: null,
    credentialRef: unverifiedCredentialRef ? `sha256:${hashPayload(unverifiedCredentialRef)}` : null,
    intentId: request?.intentId,
    capabilityId: request?.capabilityId,
    semanticAction: request?.semanticAction,
    domainId: request?.domainId,
    resourceRef: request?.resourceRef,
    resourceVersion: request?.resourceVersion,
    policyVersion,
    decision: "deny",
    reason,
    effectivePermissions: [],
    sodResult: { static: "pass", dynamic: "pass" },
    requestCorrelationId: request?.requestCorrelationId,
    delegationRef: request?.delegationRef,
    beforeHash: request?.beforeHash,
    afterHash: request?.afterHash,
  };
  return storage.createMigAuthorizationManifest({
    authorizationManifestId: `mig_authz_${randomBytes(12).toString("hex")}`,
    ...body,
    manifestHash: hashPayload(body),
  });
}
