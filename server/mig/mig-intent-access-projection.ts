/**
 * Intent access is a server-derived projection, not an authorization model.
 *
 * This module deliberately contains no path, score, or viability logic.  It
 * binds the facts already admitted by MIG/Corporate Brain to the canonical
 * BRIPe request and keeps the immutable lineage needed to retry that request.
 */
import { createHash, randomUUID } from "crypto";
import { appendStructuralHistory, queryStructuralHistory, getStructuralHistoryDb } from "../../shared/persistence/structural-history-store";
import type { CanonicalSignalV1 } from "../../shared/contracts/bripe-execution-v1";

export const MIG_INTENT_ACCESS_SCHEMA = "mig.intent-access.v1" as const;
const MIG_INTENT_ACCESS_STORAGE_SCHEMA = "mig.ia.v1" as const;
export type IntentAccessHistoryRepository = {
  append(input: Parameters<typeof appendStructuralHistory>[0]): Promise<unknown>;
  query(input: { objectType: "decision"; objectId: string; tenantId: string; ownerId?: string; limit?: number }): Promise<any[]>;
};
let historyRepository: IntentAccessHistoryRepository | undefined;
export function configureIntentAccessHistoryRepository(repository?: IntentAccessHistoryRepository): void {
  historyRepository = repository;
}
export type AccessStep = {
  step_id: string;
  tool: string;
  capability: string;
  operation: string;
  resource_refs: string[];
  authorization_ref: string;
  knowledge_authorization_refs: string[];
  destination?: string;
  /** Policy-derived admitted evidence, never a MIG-computed score. */
  evidence_severity?: number;
};
export type IntentAccessProjection = {
  schema_version: typeof MIG_INTENT_ACCESS_SCHEMA;
  projection_id: string;
  tenant_id: string;
  principal_id: string;
  execution_id: string;
  intent_id: string;
  root_intent_id: string;
  manifest_ref: string;
  credential_ref: string;
  steps: AccessStep[];
  payload_hash: string;
  path_fingerprint: string;
  predecessor_projection_id?: string;
  supersedes_projection_id?: string;
  stream_key: string;
  status?: "proposed" | "admitted" | "succeeded" | "failed" | "blocked";
  created_at: string;
};

export type SealedBaseline = IntentAccessProjection & {
  baseline: true;
  readiness: "ready" | "insufficient";
  evidence_limitations: string[];
  baseline_hash: string;
  baseline_run_ref?: string;
  baseline_proof_ref?: string;
  supersedes_projection_id?: string;
};

const canonical = (value: unknown): string => {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const r = value as Record<string, unknown>;
  return `{${Object.keys(r).sort().filter(k => r[k] !== undefined)
    .map(k => `${JSON.stringify(k)}:${canonical(r[k])}`).join(",")}}`;
};
export const fingerprint = (value: unknown): string =>
  createHash("sha256").update(canonical(value)).digest("hex");

/** Caller supplied structural facts are never part of this projection. */
export function assertNoCallerStructuralFacts(input: Record<string, unknown>, allowControlShell = false): void {
  const forbidden = [ ...(allowControlShell ? [] : ["structural_pdp", "canonical_envelope"]),
    "path", "score", "viable_path_count",
    "dominant_path_id", "propagation_score", "approval", "structural_facts"];
  if (forbidden.some(key => key in input)) throw new Error("MIG_CALLER_STRUCTURAL_FACTS_FORBIDDEN");
  if (allowControlShell && input.structural_pdp && typeof input.structural_pdp === "object") {
    const shell = input.structural_pdp as Record<string, unknown>;
    if (Object.keys(shell).some(key => !["approval_ids", "purpose", "project_or_process", "canonical_envelope"].includes(key))) {
      throw new Error("MIG_CALLER_STRUCTURAL_FACTS_FORBIDDEN");
    }
  }
  const control = input.structural_pdp && typeof input.structural_pdp === "object"
    ? input.structural_pdp as Record<string, unknown> : undefined;
  // Identical anti-forgery rules apply to both context locations. A control
  // envelope never grants permission to submit caller-authored structural facts.
  const envelopes = [input.canonical_envelope, control?.canonical_envelope];
  for (const value of allowControlShell ? envelopes : []) {
    if (!value || typeof value !== "object") continue;
    const envelope = value as Record<string, unknown>;
    if (["path", "score", "viable_path_count", "dominant_path_id", "propagation_score",
      "structural_facts"].some(key => key in envelope)) {
      throw new Error("MIG_CALLER_STRUCTURAL_FACTS_FORBIDDEN");
    }
    if (["signals", "observations", "kao", "coverage", "snapshots", "cb_snapshot", "essg_snapshot"].some(key =>
      key in envelope && envelope[key] !== undefined &&
      (!Array.isArray(envelope[key]) || envelope[key].length > 0))) {
      throw new Error("MIG_CALLER_STRUCTURAL_FACTS_FORBIDDEN");
    }
  }
  const scan = (value: unknown): boolean => {
    if (!value || typeof value !== "object") return false;
    if (Array.isArray(value)) return value.some(scan);
    const record = value as Record<string, unknown>;
    if (Object.entries(record).some(([key, nested]) =>
      ["signals", "observations", "kao", "coverage", "snapshots", "cb_snapshot", "essg_snapshot",
        "path", "score", "structural_facts"].includes(key) &&
      (nested !== undefined && (!Array.isArray(nested) || nested.length > 0)))) return true;
    return Object.values(record).some(scan);
  };
  if (scan(input)) throw new Error("MIG_CALLER_STRUCTURAL_FACTS_FORBIDDEN");
}

export function createIntentAccessProjection(input: {
  tenant_id: string; principal_id: string; execution_id: string; intent_id: string;
  root_intent_id?: string; manifest_ref: string; credential_ref: string;
  steps: readonly AccessStep[]; payload: unknown; predecessor_projection_id?: string;
  projection_id?: string; stream_key?: string;
  now?: string;
}): IntentAccessProjection {
  if (!input.tenant_id || !input.principal_id || !input.intent_id || !input.manifest_ref ||
      !input.credential_ref || !input.steps.length) throw new Error("MIG_INTENT_ACCESS_EVIDENCE_INSUFFICIENT");
  const steps = input.steps.map(step => ({
    ...step, resource_refs: [...step.resource_refs].sort(),
    knowledge_authorization_refs: [...step.knowledge_authorization_refs].sort(),
  }));
  const path_fingerprint = fingerprint(steps);
  return {
    schema_version: MIG_INTENT_ACCESS_SCHEMA, projection_id: input.projection_id ?? `mig_iap_${randomUUID()}`,
    tenant_id: input.tenant_id, principal_id: input.principal_id, execution_id: input.execution_id,
    intent_id: input.intent_id, root_intent_id: input.root_intent_id ?? input.intent_id,
    manifest_ref: input.manifest_ref, credential_ref: input.credential_ref, steps,
    payload_hash: fingerprint(input.payload), path_fingerprint,
    predecessor_projection_id: input.predecessor_projection_id,
    stream_key: input.stream_key ?? `${input.tenant_id}:${input.principal_id}:${input.execution_id}`,
    created_at: input.now ?? new Date().toISOString(),
  };
}

export function sealOnboardingBaseline(
  projection: IntentAccessProjection,
  limitations: string[] = [],
  canonicalRun?: { run_ref: string; proof_ref: string },
): SealedBaseline {
  const readiness = limitations.length === 0 && projection.steps.length > 0 &&
    Boolean(canonicalRun?.run_ref && canonicalRun.proof_ref) ? "ready" : "insufficient";
  const basisProjection = canonicalRun ? {
    ...projection, baseline_run_ref: canonicalRun.run_ref, baseline_proof_ref: canonicalRun.proof_ref,
  } : projection;
  const basis = { projection: basisProjection, readiness, evidence_limitations: [...limitations] };
  return { ...projection, ...(canonicalRun ? {
    baseline_run_ref: canonicalRun.run_ref, baseline_proof_ref: canonicalRun.proof_ref,
  } : {}), baseline: true, readiness, evidence_limitations: [...limitations],
    baseline_hash: fingerprint(basis) } as SealedBaseline;
}

/** Add one already-authorized step without allowing a caller to replace the
 * accumulated journey.  A new immutable projection supersedes the predecessor. */
export function accumulateIntentAccessStep(
  previous: IntentAccessProjection, step: AccessStep, payload: unknown, now?: string,
): IntentAccessProjection {
  if (step.authorization_ref.length === 0) throw new Error("MIG_INTENT_ACCESS_AUTHORIZATION_REFERENCE_REQUIRED");
  return createIntentAccessProjection({
    tenant_id: previous.tenant_id, principal_id: previous.principal_id,
    execution_id: previous.execution_id, intent_id: previous.intent_id,
    root_intent_id: previous.root_intent_id, manifest_ref: previous.manifest_ref,
    credential_ref: previous.credential_ref, steps: [...previous.steps, step],
    payload, predecessor_projection_id: previous.projection_id, now,
  });
}

export async function persistIntentAccessLineage(
  record: SealedBaseline | IntentAccessProjection,
  predecessor?: string,
  status?: "proposed" | "admitted" | "succeeded" | "failed" | "blocked",
): Promise<void> {
  if (!historyRepository && !getStructuralHistoryDb()) throw new Error("MIG_INTENT_ACCESS_HISTORY_UNAVAILABLE");
  const isBaseline = "baseline" in record && record.baseline === true;
  const persistedStatus = status ?? (isBaseline ? "admitted" : "proposed");
  const append = {
    tenantId: record.tenant_id, objectType: "decision" as const, objectId: record.stream_key,
    ownerId: record.principal_id,
    payload: {
      intent_access: { ...record, status: persistedStatus },
      supersedes: predecessor,
      status: persistedStatus,
    },
    triggerReason: isBaseline ? "mig_intent_access_baseline" : "mig_intent_access_projection",
    schemaVersion: MIG_INTENT_ACCESS_STORAGE_SCHEMA,
    contextId: record.execution_id,
    idempotencyKey: `mig-intent-access:${record.tenant_id}:${record.stream_key}:${record.projection_id}:${persistedStatus}`,
  };
  await (historyRepository ? historyRepository.append(append) : appendStructuralHistory(append));
}

export async function readIntentAccessLineage(tenantId: string, principalId: string, projectionId?: string) {
  const rows = await (historyRepository ? historyRepository.query({
    objectType: "decision", tenantId, ownerId: principalId,
    objectId: projectionId ?? `${tenantId}:${principalId}`, limit: 500,
  }) : queryStructuralHistory({
    objectType: "decision", tenantId, ownerId: principalId,
    objectId: projectionId ?? `${tenantId}:${principalId}`,
    limit: 500,
  }));
  return rows.filter(row => row.triggerReason === "mig_intent_access_baseline" ||
    row.triggerReason === "mig_intent_access_projection");
}

export async function readCurrentSealedBaseline(
  tenantId: string, principalId: string, clientStreamKey?: string,
): Promise<SealedBaseline | undefined> {
  if (!clientStreamKey) throw new Error("MIG_INTENT_ACCESS_TARGET_STREAM_REQUIRED");
  const rows = await (historyRepository ? historyRepository.query({
    objectType: "decision", tenantId, ownerId: principalId, objectId: clientStreamKey, limit: 500,
  }) : queryStructuralHistory({
    objectType: "decision", tenantId, ownerId: principalId, objectId: clientStreamKey, limit: 500,
  }));
  const candidates = rows
    .filter(row => row.triggerReason === "mig_intent_access_baseline")
    .map(row => (row.payload.intent_access ?? row.payload) as SealedBaseline)
    .filter(value => value && value.baseline === true);
  return candidates.at(-1);
}

export async function readCurrentRuntimeProjection(
  tenantId: string, principalId: string, streamKey: string, includePending = false,
): Promise<IntentAccessProjection | undefined> {
  const rows = await (historyRepository ? historyRepository.query({
    objectType: "decision", tenantId, ownerId: principalId, objectId: streamKey, limit: 500,
  }) : queryStructuralHistory({
    objectType: "decision", tenantId, ownerId: principalId, objectId: streamKey, limit: 500,
  }));
  const records = rows.filter(row => row.triggerReason === "mig_intent_access_projection" ||
      row.triggerReason === "mig_intent_access_baseline")
    .map(row => (row.payload.intent_access ?? row.payload) as IntentAccessProjection)
    .filter(value => value && ((value as SealedBaseline).baseline === true ||
      value.status === "admitted" || value.status === "succeeded" ||
      value.status === "failed" || value.status === "blocked"));
  const latest = new Map<string, IntentAccessProjection>();
  for (const value of records) latest.set(value.projection_id, value);
  const terminal = [...latest.values()].filter(value => value.status === "succeeded" ||
    (includePending && value.status === "admitted") || (value as SealedBaseline).baseline === true);
  const byId = new Map(terminal.map(value => [value.projection_id, value]));
  const leaves = terminal.filter(value => !terminal.some(other => other.predecessor_projection_id === value.projection_id));
  const leaf = leaves.filter(value => (value as SealedBaseline).baseline !== true).at(-1)
    ?? [...latest.values()].filter(value => value.status === "succeeded").at(-1);
  if (!leaf) return undefined;
  let cursor: IntentAccessProjection | undefined = leaf;
  while (cursor?.predecessor_projection_id) {
    const parent = byId.get(cursor.predecessor_projection_id);
    if (!parent) throw new Error("MIG_INTENT_ACCESS_PREDECESSOR_CHAIN_INVALID");
    cursor = parent;
  }
  return leaf;
}

/** Convert admitted accesses into evidence. MIG does not infer paths here. */
export function accessProjectionSignals(projection: IntentAccessProjection): CanonicalSignalV1[] {
  return projection.steps.map(step => ({
    signal_id: `mig-access:${projection.projection_id}:${step.step_id}`,
    type: "mig.authorized_access", entity: step.resource_refs[0] ?? step.tool,
    system: step.tool, timestamp: projection.created_at,
    value: { severity: step.evidence_severity ?? (() => { throw new Error("MIG_ACCESS_EVIDENCE_SEVERITY_MISSING"); })(),
      capability: step.capability,
      operation: step.operation, destination: step.destination },
    confidence: 1, source: "MIG", source_key: step.authorization_ref,
    evidence_id: step.knowledge_authorization_refs[0] ?? step.authorization_ref,
    signal_category: "security", dependency_group: projection.root_intent_id,
    region: null, jurisdiction: null, limitations: [], completeness: true,
  }));
}

/** Exact payload + accumulated path binding required by consequential dispatch. */
export function assertIntentAccessBinding(
  projection: IntentAccessProjection, payload: unknown, steps: readonly AccessStep[],
): void {
  if (projection.payload_hash !== fingerprint(payload)) throw new Error("MIG_INTENT_ACCESS_PAYLOAD_BINDING_INVALID");
  if (projection.path_fingerprint !== fingerprint(steps.map(step => ({
    ...step, resource_refs: [...step.resource_refs].sort(),
    knowledge_authorization_refs: [...step.knowledge_authorization_refs].sort(),
  })))) throw new Error("MIG_INTENT_ACCESS_PATH_BINDING_INVALID");
}

export function requireConsequentialBaseline(baseline: SealedBaseline | undefined): SealedBaseline {
  if (!baseline || baseline.baseline !== true || baseline.readiness !== "ready" || !baseline.baseline_hash) {
    throw new Error("MIG_INTENT_ACCESS_BASELINE_INSUFFICIENT");
  }
  return baseline;
}

export function assertBaselineCurrent(baseline: SealedBaseline, now = new Date()): void {
  const age = now.getTime() - Date.parse(baseline.created_at);
  if (!Number.isFinite(age) || age < 0 || age > 30 * 60 * 1000) {
    throw new Error("MIG_INTENT_ACCESS_BASELINE_STALE");
  }
  const { baseline_hash: _hash, baseline: _sealed, status: _status,
    evidence_limitations, readiness, ...projection } = baseline;
  if (baseline.baseline_hash !== fingerprint({
    projection, readiness, evidence_limitations,
  })) throw new Error("MIG_INTENT_ACCESS_BASELINE_INTEGRITY_INVALID");
}