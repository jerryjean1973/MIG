/**
 * server/mcp/bripe-mcp-audit.ts
 *
 * Audit logging for every MCP tool invocation. Records provenance (which
 * canonical service was called, tenant, capability/domain, manifest/decision
 * ids), hashes of input/output, and the full GDP output JSON for
 * `run_bripe_decision` calls so every BRIPe output is queryable in full.
 *
 * Decision-outcome fields (ttb_days, ttf_days, propagation_score) are stored
 * as structured scalars. full_output_json stores the complete GDP response.
 * input_payload stores the canonical envelope (signals, entity context).
 */
import { createHash, randomUUID } from "crypto";

import { storage } from "../storage";

import type { McpToolClassification } from "../../shared/protocol/server/mcp/bripe-mcp-schemas";

export function hashPayload(payload: unknown): string {
  const json = JSON.stringify(payload ?? null);
  return createHash("sha256").update(json).digest("hex");
}

export interface McpInvocationContext {
  requestId: string;
  toolName: string;
  toolClassification: McpToolClassification;
  tenantId: string;
  apiKeyId?: number;
  canonicalService: string;
  capabilityId?: string;
  domainId?: string;
  packageId?: string;
  authorizationManifestId?: string;
  delegationJti?: string;
  authorizationDecisionId?: string;
  authorizationPolicyVersion?: string;
  migClientId?: string;
  migPrincipalId?: string;
  journeyId?: string;
  parentCallId?: string;
  originUserId?: string;
  originAgentId?: string;
  rootIntentId?: string;
  currentIntentId?: string;
  compoundedIntentIds?: string[];
  graphCallIds?: string[];
  resourceRef?: string;
  resourceVersion?: string;
}

export interface McpDecisionMetrics {
  manifestId?: string;
  decisionId?: string;
  ttbDays?: number | null;
  ttfDays?: number | null;
  propagationScore?: number | null;
  /** Full tool response JSON. */
  fullOutputJson?: Record<string, unknown> | null;
  /** Full validated tool request JSON. */
  inputPayload?: Record<string, unknown> | null;
  /** ADAM gate outcome — AUTHORIZED / QUALIFIED / HUMAN_REVIEW_REQUIRED / BLOCKED. */
  adamOutcome?: string | null;
  /** ADAM proof manifest ID for audit trail linkage. */
  adamProofManifestId?: string | null;
  /** Reason for BLOCKED or QUALIFIED outcomes; null when AUTHORIZED. */
  adamDowngradeReason?: string | null;
}

function toAuditRecord(value: unknown, field: "request" | "result"): Record<string, unknown> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return { [field]: value ?? null };
}

export function beginMcpInvocation(params: Omit<McpInvocationContext, "requestId"> & { requestId?: string }): McpInvocationContext {
  return { requestId: params.requestId ?? randomUUID(), ...params };
}

export async function recordMcpInvocationSuccess(
  ctx: McpInvocationContext,
  input: unknown,
  output: unknown,
  startedAtMs: number,
  extra?: McpDecisionMetrics,
): Promise<void> {
  try {
    await storage.recordMcpToolInvocation({
      requestId: ctx.requestId,
      toolName: ctx.toolName,
      toolClassification: ctx.toolClassification,
      tenantId: ctx.tenantId,
      apiKeyId: ctx.apiKeyId ?? null,
      capabilityId: ctx.capabilityId ?? null,
      domainId: ctx.domainId ?? null,
      packageId: ctx.packageId ?? null,
      canonicalService: ctx.canonicalService,
      inputHash: hashPayload(input),
      outputHash: hashPayload(output),
      manifestId: ctx.authorizationManifestId ?? extra?.manifestId ?? null,
      decisionId: ctx.authorizationDecisionId ?? extra?.decisionId ?? null,
      delegationJti: ctx.delegationJti ?? null,
      authorizationPolicyVersion: ctx.authorizationPolicyVersion ?? null,
      migClientId: ctx.migClientId ?? null,
      migPrincipalId: ctx.migPrincipalId ?? null,
      journeyId: ctx.journeyId ?? null,
      parentCallId: ctx.parentCallId ?? null,
      originUserId: ctx.originUserId ?? null,
      originAgentId: ctx.originAgentId ?? null,
      rootIntentId: ctx.rootIntentId ?? null,
      currentIntentId: ctx.currentIntentId ?? null,
      compoundedIntentIds: ctx.compoundedIntentIds ?? [],
      graphCallIds: ctx.graphCallIds ?? [],
      resourceRef: ctx.resourceRef ?? null,
      resourceVersion: ctx.resourceVersion ?? null,
      outcome: "succeeded",
      status: "success",
      errorCode: null,
      durationMs: Date.now() - startedAtMs,
      ttbDays: extra?.ttbDays ?? null,
      ttfDays: extra?.ttfDays ?? null,
      propagationScore: extra?.propagationScore ?? null,
      fullOutputJson: extra?.fullOutputJson ?? toAuditRecord(output, "result"),
      inputPayload: extra?.inputPayload ?? toAuditRecord(input, "request"),
      adamOutcome: extra?.adamOutcome ?? null,
      adamProofManifestId: extra?.adamProofManifestId ?? null,
      adamDowngradeReason: extra?.adamDowngradeReason ?? null,
    });
  } catch (err) {
    console.error("[BRIPeMcpAudit] Failed to record success invocation:", err);
    throw err;
  }
}

export async function recordMcpInvocationFailure(
  ctx: McpInvocationContext,
  input: unknown,
  errorCode: string,
  startedAtMs: number,
  output?: unknown,
): Promise<void> {
  try {
    await storage.recordMcpToolInvocation({
      requestId: ctx.requestId,
      toolName: ctx.toolName,
      toolClassification: ctx.toolClassification,
      tenantId: ctx.tenantId,
      apiKeyId: ctx.apiKeyId ?? null,
      capabilityId: ctx.capabilityId ?? null,
      domainId: ctx.domainId ?? null,
      packageId: ctx.packageId ?? null,
      canonicalService: ctx.canonicalService,
      inputHash: hashPayload(input),
      outputHash: null,
      manifestId: ctx.authorizationManifestId ?? null,
      decisionId: ctx.authorizationDecisionId ?? null,
      delegationJti: ctx.delegationJti ?? null,
      authorizationPolicyVersion: ctx.authorizationPolicyVersion ?? null,
      migClientId: ctx.migClientId ?? null,
      migPrincipalId: ctx.migPrincipalId ?? null,
      journeyId: ctx.journeyId ?? null,
      parentCallId: ctx.parentCallId ?? null,
      originUserId: ctx.originUserId ?? null,
      originAgentId: ctx.originAgentId ?? null,
      rootIntentId: ctx.rootIntentId ?? null,
      currentIntentId: ctx.currentIntentId ?? null,
      compoundedIntentIds: ctx.compoundedIntentIds ?? [],
      graphCallIds: ctx.graphCallIds ?? [],
      resourceRef: ctx.resourceRef ?? null,
      resourceVersion: ctx.resourceVersion ?? null,
      outcome: "failed",
      status: "error",
      errorCode,
      durationMs: Date.now() - startedAtMs,
      ttbDays: null,
      ttfDays: null,
      propagationScore: null,
      inputPayload: toAuditRecord(input, "request"),
      fullOutputJson: toAuditRecord(
        output ?? { isError: true, error: errorCode },
        "result",
      ),
    });
  } catch (err) {
    console.error("[BRIPeMcpAudit] Failed to record failure invocation:", err);
    throw err;
  }
}
