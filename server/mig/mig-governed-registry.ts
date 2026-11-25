import { createHash, randomUUID } from "crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { pool } from "../db";
import { storage } from "../storage";
import { registerMigClient, revokeMigClient } from "./mig-client-lineage";
import { fetchRegistryEntries, probeMcpEndpoint, validateRegistryTarget } from "./mig-registry-network";
import type { MigClientClass, MigRegistryCandidate, MigRegistryEntryAdapter, MigRegistryState } from "@shared/schema";

const transitions: Record<MigRegistryState, MigRegistryState[]> = {
  discovered: ["identified", "revoked"], identified: ["classified", "failed_validation", "revoked"],
  classified: ["validated", "failed_validation", "revoked"], validated: ["registered", "suspended", "revoked"],
  registered: ["trusted", "suspended", "revoked"], trusted: ["suspended", "revoked"],
  failed_validation: ["validated", "identified", "revoked"], suspended: ["revoked"], revoked: [],
};
const adapters = new Set<MigRegistryEntryAdapter>(["manual", "proximity", "approved_network", "api"]);
const validText = (value: unknown, max = 128): value is string => typeof value === "string" && value.length > 0 && value.length <= max && /^[A-Za-z0-9._:-]+$/.test(value);
const stableKey = (prefix: string, value: string) => `${prefix}:${createHash("sha256").update(value).digest("hex")}`;

const hostOperatorLocks = new AsyncLocalStorage<ReadonlySet<string>>();
/** All operator activation and lifecycle paths share one cross-process lock. */
export async function withMigHostOperatorRegistryLock<T>(tenantId: string, work: () => Promise<T>): Promise<T> {
  if (hostOperatorLocks.getStore()?.has(tenantId)) return work();
  const connection = await pool.connect();
  const key = `mig-host-operator:${tenantId}`;
  let acquired = false;
  try {
    const result = await connection.query("SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS acquired", [key]);
    acquired = result.rows[0]?.acquired === true;
    if (!acquired) throw new Error("MIG_HOST_OPERATOR_REGISTRATION_BUSY");
    return await hostOperatorLocks.run(new Set([...(hostOperatorLocks.getStore() ?? []), tenantId]), work);
  } finally {
    try {
      if (acquired) await connection.query("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [key]);
    } finally { connection.release(); }
  }
}
async function withHostOperatorMutation<T>(tenantId: string, candidateId: string, work: () => Promise<T>) {
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!(candidate?.target as any)?.host_operator) return work();
  // The callback re-reads the candidate after acquiring the lock.
  return withMigHostOperatorRegistryLock(tenantId, work);
}

/** Host-operator approvals cannot be bypassed via the generic registry endpoints. */
function assertHostOperatorReview(candidate: MigRegistryCandidate, actorId: string) {
  const enrollment = (candidate.target as any)?.host_operator;
  if (!enrollment) return;
  if (enrollment.contract !== "mig.host-operator.enrollment.v1" ||
      enrollment.approval_state !== "approved" || enrollment.approver_actor_id !== actorId ||
      enrollment.requesting_actor_id === actorId || enrollment.key_ownership_verified !== true ||
      candidate.componentId !== enrollment.spec?.client_id) throw new Error("MIG_HOST_OPERATOR_INDEPENDENT_APPROVAL_REQUIRED");
}

async function event(candidate: MigRegistryCandidate, fromState: MigRegistryState | null, toState: MigRegistryState, eventType: string, actorId: string, evidence: object) {
  await storage.createMigRegistryHistory({ eventId: `mig_registry_event_${randomUUID()}`, candidateId: candidate.candidateId, tenantId: candidate.tenantId, fromState, toState, eventType, actorId, evidence });
  await storage.recordMigAuditEvent({ eventId: `mig_registry_audit_${randomUUID()}`, eventType: "registry_" + eventType, decision: toState === "revoked" ? "deny" : "allow", tenantId: candidate.tenantId, policyDecision: toState, reason: candidate.candidateId });
}

export async function createMigRegistryCandidate(input: {
  tenantId: string; actorId: string; componentId: string; principalId?: string; clientClass?: MigClientClass;
  entryAdapter: MigRegistryEntryAdapter; approvedScopes?: string[]; target?: string;
  metadata?: Record<string, unknown>; idempotencyKey?: string; hostOperatorEnrollment?: true;
}) {
  if (input.metadata?.host_operator && !input.hostOperatorEnrollment) throw new Error("MIG_HOST_OPERATOR_RESERVED_METADATA");
  if (!validText(input.componentId) || (input.clientClass && !["AGENT", "MCP"].includes(input.clientClass)) || !adapters.has(input.entryAdapter)) throw new Error("MIG_REGISTRY_CANDIDATE_INVALID");
  if ((!Array.isArray(input.approvedScopes) || !input.approvedScopes.length || input.approvedScopes.length > 20) && !["manual", "proximity"].includes(input.entryAdapter)) throw new Error("MIG_REGISTRY_SCOPES_REQUIRED");
  for (const scope of input.approvedScopes ?? []) if (typeof scope !== "string" || !scope.trim() || scope.length > 2048) throw new Error("MIG_REGISTRY_SCOPE_INVALID");
  if (input.idempotencyKey && !validText(input.idempotencyKey, 128)) throw new Error("MIG_REGISTRY_IDEMPOTENCY_KEY_INVALID");
  if (input.idempotencyKey) {
    const existing = await storage.getMigRegistryCandidateByIdempotencyKey(input.tenantId, input.idempotencyKey);
    if (existing) return { candidate: existing, idempotent: true };
  }
  if (input.principalId) {
    const principal = await storage.getMigPrincipal(input.tenantId, input.principalId);
    if (!principal || principal.status !== "active") throw new Error("MIG_REGISTRY_ACTIVE_PRINCIPAL_REQUIRED");
  }
  const target = {
    identity: input.componentId, display_name: input.componentId,
    ...(input.target ? { url: input.target } : {}), ...(input.metadata ?? {}),
  };
  const candidate = await storage.createMigRegistryCandidate({ candidateId: `mig_candidate_${randomUUID()}`, tenantId: input.tenantId, componentId: input.componentId, principalId: input.principalId, clientClass: input.clientClass, entryAdapter: input.entryAdapter, approvedScopes: input.approvedScopes ?? [], target, idempotencyKey: input.idempotencyKey, state: "discovered", createdBy: input.actorId });
  await event(candidate, null, "discovered", "discovered", input.actorId, { entryAdapter: input.entryAdapter });
  return { candidate, idempotent: false };
}

export async function identifyMigRegistryCandidate(tenantId: string, candidateId: string, principalId: string, actorId: string) {
  return withHostOperatorMutation(tenantId, candidateId, async () => {
  if (!validText(principalId)) throw new Error("MIG_REGISTRY_PRINCIPAL_REQUIRED");
  const principal = await storage.getMigPrincipal(tenantId, principalId);
  if (!principal || principal.status !== "active") throw new Error("MIG_REGISTRY_ACTIVE_PRINCIPAL_REQUIRED");
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!candidate || candidate.state !== "discovered") throw new Error("MIG_REGISTRY_TRANSITION_INVALID");
  if (principal.subjectRef?.startsWith("host-operator:") && principal.subjectRef !== `host-operator:${candidateId}`) {
    throw new Error("MIG_HOST_OPERATOR_PRINCIPAL_REQUEST_MISMATCH");
  }
  assertHostOperatorReview(candidate, actorId);
  if ((candidate.target as any)?.host_operator?.spec.principal_id &&
      (candidate.target as any).host_operator.spec.principal_id !== principalId) throw new Error("MIG_HOST_OPERATOR_PRINCIPAL_MISMATCH");
  await storage.updateMigRegistryCandidate(tenantId, candidateId, { principalId });
  return transitionMigRegistryCandidate(tenantId, candidateId, "identified", actorId);
  });
}

export async function classifyMigRegistryCandidate(tenantId: string, candidateId: string, clientClass: MigClientClass, actorId: string) {
  return withHostOperatorMutation(tenantId, candidateId, async () => {
  if (!["AGENT", "MCP"].includes(clientClass)) throw new Error("MIG_CLIENT_CLASS_INVALID");
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!candidate || candidate.state !== "identified" || !candidate.principalId) throw new Error("MIG_REGISTRY_TRANSITION_INVALID");
  assertHostOperatorReview(candidate, actorId);
  if ((candidate.target as any)?.host_operator && clientClass !== "AGENT") throw new Error("MIG_HOST_OPERATOR_AGENT_CLASS_REQUIRED");
  await storage.updateMigRegistryCandidate(tenantId, candidateId, { clientClass });
  return transitionMigRegistryCandidate(tenantId, candidateId, "classified", actorId);
  });
}

export async function setMigRegistryValidationEvidence(
  tenantId: string, candidateId: string, validation: Record<string, unknown>, actorId: string,
) {
  return withHostOperatorMutation(tenantId, candidateId, async () => {
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!candidate || !["classified", "failed_validation"].includes(candidate.state)) throw new Error("MIG_REGISTRY_VALIDATION_UPDATE_INVALID");
  assertHostOperatorReview(candidate, actorId);
  const allowed = candidate.clientClass === "MCP"
    ? ["identity_auth", "outcome_return", "provenance_preservation", "mig_continuation"]
    : ["identity_auth", "current_intent", "governed_invocation", "mig_root_lineage"];
  const normalized = Object.fromEntries(allowed.map(key => [key, validation?.[key] === true]));
  await storage.updateMigRegistryCandidate(tenantId, candidateId, {
    target: { ...(candidate.target as Record<string, unknown>), validation: normalized },
  });
  await storage.recordMigAuditEvent({
    tenantId, eventType: "registry.validation_evidence_recorded", actorId,
    decision: "allow", reason: "Administrator recorded class-specific validation evidence", payload: { candidateId, fields: allowed },
  });
  });
}

export async function discoverProximityCandidates(input: {
  tenantId: string; actorId: string; observations: Array<Record<string, unknown>>;
}) {
  if (!Array.isArray(input.observations) || input.observations.length === 0 || input.observations.length > 50) throw new Error("MIG_PROXIMITY_OBSERVATIONS_INVALID");
  return Promise.all(input.observations.map((observation, index) => {
    const componentId = String(observation.component_id ?? observation.identity ?? `nearby-${index + 1}`);
    return createMigRegistryCandidate({
      tenantId: input.tenantId, actorId: input.actorId, componentId, entryAdapter: "proximity",
      target: typeof observation.endpoint === "string" ? observation.endpoint : undefined,
      metadata: {
        display_name: String(observation.display_name ?? componentId),
        capabilities: Array.isArray(observation.capabilities) ? observation.capabilities.slice(0, 100) : [],
        auth_hints: Array.isArray(observation.auth_hints) ? observation.auth_hints.slice(0, 20) : [],
        evidence: ["proximity_observation", ...(observation.reachable === true ? ["reachable_association"] : [])],
        configured: observation.configured === true, reachable: observation.reachable === true,
      },
      idempotencyKey: typeof observation.idempotency_key === "string" ? observation.idempotency_key : undefined,
    });
  }));
}

export async function scanApprovedNetworkCandidates(input: {
  tenantId: string; actorId: string; approvedScopes: string[]; targets: string[];
}) {
  if (!Array.isArray(input.targets) || input.targets.length === 0 || input.targets.length > 64) throw new Error("MIG_NETWORK_TARGET_LIMIT");
  const results: Awaited<ReturnType<typeof createMigRegistryCandidate>>[] = [];
  for (let offset = 0; offset < input.targets.length; offset += 4) {
    const batch = input.targets.slice(offset, offset + 4);
    const settled = await Promise.allSettled(batch.map(async target => {
      const proof = await probeMcpEndpoint(target, input.approvedScopes);
      const host = new URL(target).hostname.replace(/[^A-Za-z0-9._:-]/g, "-");
      return createMigRegistryCandidate({
        tenantId: input.tenantId, actorId: input.actorId, componentId: `mcp-${host}`,
        clientClass: "MCP", entryAdapter: "approved_network", approvedScopes: input.approvedScopes, target,
        metadata: {
          evidence: ["bounded_network_probe"], validation_evidence: proof, auth_hints: [], capabilities: [],
          validation: { identity_auth: true, outcome_return: true, provenance_preservation: true, mig_continuation: true },
        },
        idempotencyKey: stableKey("network", target),
      });
    }));
    for (const item of settled) if (item.status === "fulfilled") results.push(item.value);
  }
  return results;
}

export async function importRegistryCandidates(input: {
  tenantId: string; actorId: string; registryUrl: string; approvedScopes: string[]; authorization?: string;
}) {
  const entries = await fetchRegistryEntries(input.registryUrl, input.approvedScopes, input.authorization);
  return Promise.all(entries.map((entry, index) => {
    const componentId = String(entry.component_id ?? entry.id ?? `registry-${index + 1}`);
    const candidateClass = entry.client_class === "AGENT" || entry.client_class === "MCP" ? entry.client_class : undefined;
    return createMigRegistryCandidate({
      tenantId: input.tenantId, actorId: input.actorId, componentId, clientClass: candidateClass,
      entryAdapter: "api", approvedScopes: input.approvedScopes,
      target: typeof entry.endpoint === "string" ? entry.endpoint : undefined,
      metadata: {
        display_name: String(entry.display_name ?? entry.name ?? componentId),
        capabilities: Array.isArray(entry.capabilities) ? entry.capabilities.slice(0, 100) : [],
        auth_hints: Array.isArray(entry.auth_hints) ? entry.auth_hints.slice(0, 20) : [],
        evidence: ["external_registry_record"], source_registry: new URL(input.registryUrl).origin,
      },
      idempotencyKey: stableKey("api", `${new URL(input.registryUrl).origin}:${componentId}`),
    });
  }));
}

export async function transitionMigRegistryCandidate(tenantId: string, candidateId: string, next: MigRegistryState, actorId: string) {
  return withHostOperatorMutation(tenantId, candidateId, async () => {
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!candidate) throw new Error("MIG_REGISTRY_CANDIDATE_NOT_FOUND");
  if (next !== "revoked" && next !== "suspended") assertHostOperatorReview(candidate, actorId);
  const current = candidate.state as MigRegistryState;
  if (!transitions[current]?.includes(next)) throw new Error("MIG_REGISTRY_TRANSITION_INVALID");
  let evidence: object = {};
  if (next === "validated") {
    try {
      if (!candidate.clientClass || !candidate.principalId) throw new Error("MIG_REGISTRY_IDENTIFY_AND_CLASSIFY_REQUIRED");
      const target = candidate.target as Record<string, unknown>;
      const validation = target.validation as Record<string, unknown> | undefined;
      const required = candidate.clientClass === "MCP"
        ? ["identity_auth", "outcome_return", "provenance_preservation", "mig_continuation"]
        : ["identity_auth", "current_intent", "governed_invocation", "mig_root_lineage"];
      if (!validation || required.some(key => validation[key] !== true)) throw new Error("MIG_REGISTRY_VALIDATION_EVIDENCE_REQUIRED");
      const endpoint = target.url;
      if (candidate.clientClass === "MCP") {
        if (typeof endpoint !== "string") throw new Error("MIG_REGISTRY_VALIDATION_EVIDENCE_REQUIRED");
        const networkApproved = candidate.entryAdapter === "approved_network";
        const scopes = networkApproved ? candidate.approvedScopes as string[] : [new URL(endpoint).origin];
        evidence = { ...validation, ...(await probeMcpEndpoint(endpoint, scopes, networkApproved ? "approved_network" : "api")) };
      } else {
        evidence = { ...validation, verified: true };
      }
      await storage.updateMigRegistryCandidate(tenantId, candidateId, {
        target: { ...target, validation_evidence: evidence },
      });
    } catch (error: any) {
      const failed = await storage.setMigRegistryCandidateState(tenantId, candidateId, "failed_validation");
      await event(failed!, current, "failed_validation", "validation_failed", actorId, { error: error.message });
      throw error;
    }
  }
  const updated = await storage.setMigRegistryCandidateState(tenantId, candidateId, next);
  if (!updated) throw new Error("MIG_REGISTRY_CANDIDATE_NOT_FOUND");
  await event(updated, current, next, next === "trusted" ? "trust_approved" : "transition", actorId, evidence);
  return updated;
  });
}

export async function registerTrustedMigRegistryCandidate(tenantId: string, candidateId: string, actorId: string, originUserId?: string, capabilityCeiling?: string[], authority?: {
  scopes?: string[]; allowedIntents?: string[]; allowedDomains?: string[];
  allowedMcpTargets?: string[]; allowedCapabilities?: string[];
  resourceScopes?: string[]; riskZoneCeiling?: "low" | "medium" | "high" | "critical";
}) {
  return withHostOperatorMutation(tenantId, candidateId, async () => {
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!candidate) throw new Error("MIG_REGISTRY_CANDIDATE_NOT_FOUND");
  assertHostOperatorReview(candidate, actorId);
  const hostOperator = (candidate.target as any)?.host_operator;
  if (hostOperator) {
    const spec = hostOperator.spec;
    const same = (left: unknown, right: unknown) => JSON.stringify(left) === JSON.stringify(right);
    if (candidate.principalId !== spec.principal_id || candidate.clientClass !== "AGENT" ||
        !same(capabilityCeiling, spec.capability_ids) || !same(authority?.allowedCapabilities, spec.capability_ids) ||
        !same(authority?.allowedIntents, [spec.intent_id]) || !same(authority?.allowedDomains, [spec.domain_id]) ||
        !same(authority?.resourceScopes, [`project:${spec.project}:environment:${spec.environment}`]) ||
        !same(authority?.allowedMcpTargets, [spec.client_id]) ||
        !same(authority?.scopes, ["intents:create", "intents:continue", "mig:request"]) ||
        authority?.riskZoneCeiling !== "low") throw new Error("MIG_HOST_OPERATOR_IMMUTABLE_SCOPE_REQUIRED");
  }
  if (candidate.state === "registered" || candidate.state === "trusted") return { candidate, client: await storage.getActiveMigClientByComponent(tenantId, candidate.componentId), apiKey: undefined, idempotent: true };
  if (candidate.state !== "validated") throw new Error("MIG_REGISTRY_VALIDATION_REQUIRED");
  if (!candidate.principalId || !candidate.clientClass) throw new Error("MIG_REGISTRY_IDENTIFY_AND_CLASSIFY_REQUIRED");
  const principal = await storage.getMigPrincipal(tenantId, candidate.principalId);
  if (principal?.subjectRef?.startsWith("host-operator:") &&
      (!hostOperator || principal.subjectRef !== `host-operator:${candidateId}`)) {
    throw new Error("MIG_HOST_OPERATOR_PRINCIPAL_REQUEST_MISMATCH");
  }
  if (candidate.clientClass === "AGENT" && !validText(originUserId)) throw new Error("MIG_AGENT_ORIGIN_USER_REQUIRED");
  const existing = await storage.getActiveMigClientByComponent(tenantId, candidate.componentId);
  if (hostOperator && existing && (existing.principalId !== candidate.principalId || existing.clientClass !== "AGENT")) {
    throw new Error("MIG_HOST_OPERATOR_EXISTING_CLIENT_CONFLICT");
  }
  const registered = existing ? { client: existing, apiKey: undefined } : await registerMigClient({
    tenantId, componentId: candidate.componentId, principalId: candidate.principalId,
    clientClass: candidate.clientClass as MigClientClass, originUserId, capabilityCeiling, ...authority,
  });
  const updated = await storage.setMigRegistryCandidateState(tenantId, candidateId, "registered");
  await event(updated!, "validated", "registered", "registered", actorId, { clientId: registered.client.id });
  return { candidate: updated!, ...registered, idempotent: !!existing };
  });
}

export async function revokeMigRegistryCandidate(tenantId: string, candidateId: string, actorId: string) {
  return withHostOperatorMutation(tenantId, candidateId, async () => {
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!candidate) throw new Error("MIG_REGISTRY_CANDIDATE_NOT_FOUND");
  if (candidate.state === "revoked") return candidate;
  const current = candidate.state as MigRegistryState;
  if (!transitions[current].includes("revoked")) throw new Error("MIG_REGISTRY_TRANSITION_INVALID");
  if (current === "registered" || current === "trusted" || current === "suspended") {
    await revokeMigClient(tenantId, candidate.componentId,
      (candidate.target as any)?.host_operator ? candidate.principalId ?? undefined : undefined);
  }
  const updated = await storage.setMigRegistryCandidateState(tenantId, candidateId, "revoked");
  await event(updated!, current, "revoked", "revoked", actorId, {});
  return updated!;
  });
}

export async function suspendMigRegistryCandidate(tenantId: string, candidateId: string, actorId: string) {
  return withHostOperatorMutation(tenantId, candidateId, async () => {
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!candidate || !["registered", "trusted"].includes(candidate.state)) throw new Error("MIG_REGISTRY_SUSPEND_INVALID");
  await storage.suspendMigClient(tenantId, candidate.componentId,
    (candidate.target as any)?.host_operator ? candidate.principalId ?? undefined : undefined);
  return transitionMigRegistryCandidate(tenantId, candidateId, "suspended", actorId);
  });
}