/**
 * API enrollment adapter over MIG's existing principal, registry, entitlement and
 * credential owners. A signature proves key possession, never execution authority.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { storage } from "../storage";
import {
  createMigRegistryCandidate, identifyMigRegistryCandidate, classifyMigRegistryCandidate,
  setMigRegistryValidationEvidence, transitionMigRegistryCandidate,
  registerTrustedMigRegistryCandidate,
  revokeMigRegistryCandidate,
  withMigHostOperatorRegistryLock as locked,
} from "./mig-governed-registry";
import { revokeMigClient } from "./mig-client-lineage";
import { hasBripeCapabilityContract, bripeToolCatalog } from "./mig-bripe-adapter";
import { MIG_HOST_OPERATOR_VALIDATION_FIELDS, type MigHostOperatorSpec, type MigHostOperatorRequestView } from "@shared/mig-host-operator";
import type { MigRegistryCandidate } from "@shared/schema";

const CONTRACT = "mig.host-operator.enrollment.v1";
const identifier = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const allows = (values: unknown, value: string) =>
  Array.isArray(values) && (values.includes(value) || values.includes("*"));

export function normalizeHostOperatorSpec(value: unknown): MigHostOperatorSpec {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("MIG_HOST_OPERATOR_SPEC_REQUIRED");
  const row = value as Record<string, unknown>;
  const fields = ["principal_id", "client_id", "display_name", "project", "environment",
    "capability_ids", "intent_id", "domain_id", "public_key_pem"];
  if (Object.keys(row).some(key => !fields.includes(key))) throw new Error("MIG_HOST_OPERATOR_UNEXPECTED_FIELD");
  for (const field of ["principal_id", "client_id", "project", "intent_id", "domain_id"]) {
    if (!identifier(row[field])) throw new Error(`MIG_HOST_OPERATOR_INVALID_${field.toUpperCase()}`);
  }
  if (row.environment !== "DEV") throw new Error("MIG_HOST_OPERATOR_DEV_ONLY");
  if (typeof row.display_name !== "string" || !row.display_name.trim() ||
      row.display_name.length > 120 || /[\x00-\x1f\x7f]/.test(row.display_name)) {
    throw new Error("MIG_HOST_OPERATOR_DISPLAY_NAME_INVALID");
  }
  if (!Array.isArray(row.capability_ids) || row.capability_ids.length !== 1 || !identifier(row.capability_ids[0])) {
    throw new Error("MIG_HOST_OPERATOR_ONE_INITIAL_CAPABILITY_REQUIRED");
  }
  if (typeof row.public_key_pem !== "string" || row.public_key_pem.length > 4096 ||
      !row.public_key_pem.startsWith("-----BEGIN PUBLIC KEY-----")) {
    throw new Error("MIG_HOST_OPERATOR_PUBLIC_KEY_REQUIRED");
  }
  if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*$/.test(row.public_key_pem)) {
    throw new Error("MIG_HOST_OPERATOR_PUBLIC_KEY_INVALID");
  }
  let publicKey;
  try { publicKey = createPublicKey(row.public_key_pem); }
  catch { throw new Error("MIG_HOST_OPERATOR_PUBLIC_KEY_INVALID"); }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("MIG_HOST_OPERATOR_ED25519_REQUIRED");
  return {
    principal_id: row.principal_id as string, client_id: row.client_id as string,
    display_name: row.display_name.trim(), project: row.project as string, environment: "DEV",
    capability_ids: [row.capability_ids[0]], intent_id: row.intent_id as string, domain_id: row.domain_id as string,
    public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function hostOperatorSigningPayload(tenantId: string, actorId: string, spec: MigHostOperatorSpec, expiresAt: string) {
  return JSON.stringify({ contract: CONTRACT, tenant_id: tenantId, requesting_actor_id: actorId, spec, expires_at: expiresAt });
}
export function hostOperatorChallenge(tenantId: string, actorId: string, input: unknown) {
  const spec = normalizeHostOperatorSpec(input);
  const expires_at = new Date(Date.now() + 5 * 60_000).toISOString();
  const signing_payload = hostOperatorSigningPayload(tenantId, actorId, spec, expires_at);
  return { contract: CONTRACT, spec, expires_at, signing_payload,
    algorithm: "Ed25519", signature_encoding: "base64",
    public_key_fingerprint: `sha256:${hash(createPublicKey(spec.public_key_pem).export({ type: "spki", format: "der" }))}` };
}

function metadata(candidate: MigRegistryCandidate): any {
  const record = (candidate.target as any)?.host_operator;
  if (record?.contract !== CONTRACT || !record.spec) throw new Error("MIG_HOST_OPERATOR_REQUEST_NOT_FOUND");
  return record;
}
const resourceScope = (spec: MigHostOperatorSpec) => `project:${spec.project}:environment:${spec.environment}`;

export async function requestHostOperator(tenantId: string, actorId: string, body: any) {
  if (!body || Object.keys(body).some(key => !["spec", "expires_at", "signature"].includes(key))) {
    throw new Error("MIG_HOST_OPERATOR_REQUEST_INVALID");
  }
  const spec = normalizeHostOperatorSpec(body.spec);
  const expiry = Date.parse(body.expires_at);
  if (typeof body.expires_at !== "string" || !Number.isFinite(expiry) ||
      expiry <= Date.now() || expiry > Date.now() + 5 * 60_000) throw new Error("MIG_HOST_OPERATOR_PROOF_EXPIRED");
  if (typeof body.signature !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(body.signature)) {
    throw new Error("MIG_HOST_OPERATOR_SIGNATURE_INVALID");
  }
  const payload = hostOperatorSigningPayload(tenantId, actorId, spec, body.expires_at);
  if (!verify(null, Buffer.from(payload), createPublicKey(spec.public_key_pem), Buffer.from(body.signature, "base64"))) {
    throw new Error("MIG_HOST_OPERATOR_SIGNATURE_INVALID");
  }
  return locked(tenantId, async () => {
    const requestHash = hash(payload);
    const idempotencyKey = `host-operator:${requestHash}`;
    const prior = await storage.getMigRegistryCandidateByIdempotencyKey(tenantId, idempotencyKey);
    if (prior) return { candidate: prior, idempotent: true };
    if (await storage.getMigPrincipal(tenantId, spec.principal_id) ||
        await storage.getActiveMigClientByComponent(tenantId, spec.client_id)) {
      throw new Error("MIG_HOST_OPERATOR_IDENTITY_ALREADY_EXISTS");
    }
    const fingerprint = `sha256:${hash(createPublicKey(spec.public_key_pem).export({ type: "spki", format: "der" }))}`;
    return createMigRegistryCandidate({
      tenantId, actorId, componentId: spec.client_id, clientClass: "AGENT", entryAdapter: "api",
      idempotencyKey, approvedScopes: [resourceScope(spec)], hostOperatorEnrollment: true,
      metadata: { display_name: spec.display_name, capabilities: spec.capability_ids,
        host_operator: { contract: CONTRACT, spec, requesting_actor_id: actorId,
          request_hash: requestHash, public_key_fingerprint: fingerprint,
          signing_payload: payload, signature: body.signature, key_ownership_verified: true,
          approval_state: "pending", activation_started: false } },
    });
  });
}

async function readiness(tenantId: string, spec: MigHostOperatorSpec) {
  const [policy, intent, authority] = await Promise.all([
    storage.getMigTenantAuthorizationPolicy(tenantId), storage.getMigIntentDefinition(spec.intent_id),
    storage.getMigTenantAuthorityConfig(tenantId),
  ]);
  const blockers: string[] = [];
  if (authority?.status !== "active" || authority.deploymentMode !== "full_control_plane" ||
      authority.authorityProvider !== "mig_native" || authority.executionFabric !== "mig_managed") {
    blockers.push("ACTIVE_NATIVE_MANAGED_AUTHORITY_REQUIRED");
  }
  if (!hasBripeCapabilityContract(spec.capability_ids[0])) blockers.push("CAPABILITY_EXECUTION_CONTRACT_NOT_REGISTERED");
  const library = intent ? await storage.getMigIntentLibrary(intent.libraryId) : undefined;
  if (!intent || intent.status !== "active" || library?.status !== "published") blockers.push("PUBLISHED_ACTIVE_INTENT_REQUIRED");
  else {
    if (!allows(intent.allowedCapabilityIds, spec.capability_ids[0]) ||
        allows(intent.deniedCapabilityIds, spec.capability_ids[0])) blockers.push("CAPABILITY_OUTSIDE_INTENT");
    if (!allows(intent.domainScope, spec.domain_id)) blockers.push("DOMAIN_OUTSIDE_INTENT");
    const tools = bripeToolCatalog().filter(tool => tool.capability_id === spec.capability_ids[0]);
    if (!tools.some(tool => allows(tool.domain_scope, spec.domain_id) &&
        !allows(intent.deniedToolNames, tool.tool_name) &&
        allows(intent.allowedToolNames, tool.tool_name))) blockers.push("NO_EXECUTABLE_TOOL_FOR_INTENT_AND_DOMAIN");
  }
  if (!policy || policy.status !== "active") blockers.push("ACTIVE_TENANT_POLICY_REQUIRED");
  else {
    if (!allows(policy.capabilityIds, spec.capability_ids[0])) blockers.push("CAPABILITY_OUTSIDE_TENANT_POLICY");
    if (!allows(policy.intentIds, spec.intent_id)) blockers.push("INTENT_OUTSIDE_TENANT_POLICY");
    if (!allows(policy.domainIds, spec.domain_id)) blockers.push("DOMAIN_OUTSIDE_TENANT_POLICY");
    if (!allows(policy.resourceScopes, resourceScope(spec))) blockers.push("BC_DEV_RESOURCE_OUTSIDE_TENANT_POLICY");
    if (!allows(policy.allowedRiskZones, "low")) blockers.push("LOW_RISK_ZONE_OUTSIDE_TENANT_POLICY");
  }
  return blockers;
}
export async function hostOperatorView(candidate: MigRegistryCandidate): Promise<MigHostOperatorRequestView> {
  const record = metadata(candidate);
  const spec: MigHostOperatorSpec = record.spec;
  const blockers = await readiness(candidate.tenantId, spec);
  const client = await storage.getActiveMigClientByComponent(candidate.tenantId, spec.client_id);
  const binding = client?.principalId === spec.principal_id
    ? await storage.getActiveMigCredentialBinding(`mig-key:${client.credentialHash}`) : undefined;
  const registered = ["registered", "trusted"].includes(candidate.state) &&
    client?.principalId === spec.principal_id && client.clientClass === "AGENT";
  if (record.activation_failed) blockers.push("ACTIVATION_INTERRUPTED_ADMINISTRATIVE_RECOVERY_REQUIRED");
  else if (record.activation_started && !registered) blockers.push("ACTIVATION_INCOMPLETE_ADMINISTRATIVE_REVIEW_REQUIRED");
  if (registered && (!binding || binding.tenantId !== candidate.tenantId || binding.principalId !== spec.principal_id ||
      binding.expiresAt && binding.expiresAt <= new Date())) blockers.push("ACTIVE_SCOPED_CREDENTIAL_REQUIRED");
  return {
    request_id: candidate.candidateId, state: candidate.state, principal_id: spec.principal_id,
    client_id: spec.client_id, display_name: spec.display_name, project: spec.project, environment: spec.environment,
    resource_scope: resourceScope(spec), capability_ids: spec.capability_ids, intent_id: spec.intent_id,
    domain_id: spec.domain_id, public_key_fingerprint: record.public_key_fingerprint,
    key_ownership_verified: record.key_ownership_verified === true, approval_state: record.approval_state,
    execution_contract_available: !blockers.includes("CAPABILITY_EXECUTION_CONTRACT_NOT_REGISTERED"),
    blockers, registered,
    smartdev_enrollment: "not_verified_by_mig", authorized_execution: "not_verified",
  };
}
export async function listHostOperatorRequests(tenantId: string, actorId?: string) {
  const candidates = await storage.listMigRegistryCandidates(tenantId);
  return Promise.all(candidates.filter(candidate => {
    const record = (candidate.target as any)?.host_operator;
    return record?.contract === CONTRACT && (!actorId || record.requesting_actor_id === actorId);
  }).map(hostOperatorView));
}
export async function readHostOperatorRequest(tenantId: string, actorId: string, requestId: string) {
  const candidate = await storage.getMigRegistryCandidate(tenantId, requestId);
  if (!candidate || metadata(candidate).requesting_actor_id !== actorId) throw new Error("MIG_HOST_OPERATOR_REQUEST_NOT_FOUND");
  return hostOperatorView(candidate);
}

export async function decideHostOperatorRequest(tenantId: string, actorId: string, requestId: string, body: any) {
  if (!body || Object.keys(body).some(key => !["decision", "validation_evidence"].includes(key)) ||
      !["approve", "reject"].includes(body.decision)) throw new Error("MIG_HOST_OPERATOR_DECISION_INVALID");
  return locked(tenantId, async () => {
    let candidate = await storage.getMigRegistryCandidate(tenantId, requestId);
    if (!candidate) throw new Error("MIG_HOST_OPERATOR_REQUEST_NOT_FOUND");
    const record = metadata(candidate), spec: MigHostOperatorSpec = record.spec;
    const principals = await storage.listMigPrincipals(tenantId);
    const approver = principals.find(row => row.subjectRef === actorId && row.principalType === "human" && row.status === "active");
    if (!approver) throw new Error("MIG_HOST_OPERATOR_CANONICAL_HUMAN_ADMIN_REQUIRED");
    if ([actorId, approver.principalId].includes(record.requesting_actor_id) ||
        [actorId, approver.principalId].includes(spec.principal_id)) throw new Error("MIG_HOST_OPERATOR_INDEPENDENT_ADMIN_REQUIRED");
    if (record.approval_state !== "pending" || record.activation_started) throw new Error("MIG_HOST_OPERATOR_DECISION_ALREADY_RECORDED");
    if (candidate.state !== "discovered") throw new Error("MIG_HOST_OPERATOR_REQUEST_STATE_CONFLICT");
    if (body.decision === "reject") {
      await storage.commitMigRegistryReview({ tenantId, candidateId: requestId, expectedState: "discovered",
        expectedTarget: candidate.target, target: {
          ...(candidate.target as any), host_operator: { ...record, approval_state: "rejected", approver_principal_id: approver.principalId },
        }, history: { eventId: `host-operator-rejection:${record.request_hash}`,
          tenantId, candidateId: requestId, fromState: candidate.state, toState: candidate.state,
          eventType: "host_operator_rejected", actorId,
          evidence: { request_hash: record.request_hash, approver_principal_id: approver.principalId } } });
      await storage.recordMigAuditEvent({ tenantId, actorId, eventType: "host_operator.rejected", decision: "deny",
        reason: "Independent administrator rejected host operator registration", payload: { requestId } });
      return { request_id: requestId, approval_state: "rejected", registered: false };
    }
    // Administrator attestation uses the existing AGENT class validation owner.
    const evidence = body.validation_evidence;
    if (!evidence || Object.keys(evidence).some(key => !MIG_HOST_OPERATOR_VALIDATION_FIELDS.includes(key as any)) ||
        MIG_HOST_OPERATOR_VALIDATION_FIELDS.some(key => typeof evidence[key] !== "string" ||
          !evidence[key].trim() || evidence[key].length > 1000)) throw new Error("MIG_HOST_OPERATOR_VALIDATION_REFERENCES_REQUIRED");
    const blockers = await readiness(tenantId, spec);
    if (blockers.length) throw new Error(`MIG_HOST_OPERATOR_NOT_READY:${blockers.join(",")}`);
    if (await storage.getMigPrincipal(tenantId, spec.principal_id) ||
        await storage.getActiveMigClientByComponent(tenantId, spec.client_id)) throw new Error("MIG_HOST_OPERATOR_IDENTITY_ALREADY_EXISTS");
    // Re-verify immutable source-bound proof at the authority transition.
    const normalized = normalizeHostOperatorSpec(spec);
    if (hash(record.signing_payload) !== record.request_hash ||
        !verify(null, Buffer.from(record.signing_payload), createPublicKey(normalized.public_key_pem), Buffer.from(record.signature, "base64")) ||
        JSON.stringify(JSON.parse(record.signing_payload).spec) !== JSON.stringify(normalized) ||
        JSON.parse(record.signing_payload).tenant_id !== tenantId ||
        JSON.parse(record.signing_payload).contract !== CONTRACT ||
        JSON.parse(record.signing_payload).requesting_actor_id !== record.requesting_actor_id ||
        record.public_key_fingerprint !== `sha256:${hash(createPublicKey(normalized.public_key_pem).export({ type: "spki", format: "der" }))}`) {
      throw new Error("MIG_HOST_OPERATOR_STORED_PROOF_INVALID");
    }
    // Fence partial activation: never silently retry an uncertain credential issue.
    const reviewed = { ...record, activation_started: true, approval_state: "approved", approver_actor_id: actorId,
      approver_principal_id: approver.principalId, validation_evidence_refs: evidence };
    await storage.commitMigRegistryReview({ tenantId, candidateId: requestId, expectedState: "discovered",
      expectedTarget: candidate.target, target: { ...(candidate.target as any), host_operator: reviewed },
      history: { eventId: `host-operator-approval:${record.request_hash}`,
        tenantId, candidateId: requestId, fromState: candidate.state, toState: candidate.state,
        eventType: "host_operator_approved", actorId, evidence: { request_hash: record.request_hash,
          approver_principal_id: approver.principalId, validation_evidence_refs: evidence } } });
    try {
      await storage.createMigPrincipal({ tenantId, principalId: spec.principal_id, principalType: "service",
        subjectRef: `host-operator:${requestId}`, displayName: spec.display_name, status: "active" });
      await storage.createMigPrincipalEntitlement({ tenantId, principalId: spec.principal_id,
        entitlementId: `host-operator:${requestId}`, capabilityIds: spec.capability_ids,
        intentIds: [spec.intent_id], domainIds: [spec.domain_id], resourceScopes: [resourceScope(spec)], assignedRoles: [], status: "active" });
      await identifyMigRegistryCandidate(tenantId, requestId, spec.principal_id, actorId);
      await classifyMigRegistryCandidate(tenantId, requestId, "AGENT", actorId);
      await setMigRegistryValidationEvidence(tenantId, requestId,
        Object.fromEntries(MIG_HOST_OPERATOR_VALIDATION_FIELDS.map(key => [key, true])), actorId);
      await transitionMigRegistryCandidate(tenantId, requestId, "validated", actorId);
      const issued = await registerTrustedMigRegistryCandidate(tenantId, requestId, actorId, actorId, spec.capability_ids, {
        scopes: ["intents:create", "intents:continue", "mig:request"], allowedIntents: [spec.intent_id],
        allowedDomains: [spec.domain_id], allowedCapabilities: spec.capability_ids,
        allowedMcpTargets: [spec.client_id], resourceScopes: [resourceScope(spec)], riskZoneCeiling: "low",
      });
      if (!issued.apiKey) throw new Error("MIG_HOST_OPERATOR_CREDENTIAL_ISSUE_UNCERTAIN");
      candidate = (await storage.getMigRegistryCandidate(tenantId, requestId))!;
      return { ...(await hostOperatorView(candidate)), api_key: issued.apiKey,
        credential_delivery: "one_time_to_approving_administrator",
        signing: { algorithm: "Ed25519", public_key_pem: spec.public_key_pem,
          fingerprint: record.public_key_fingerprint, enrollment_target: "SmartDev",
          enrollment_verified: false, mig_authentication: "existing_MIG_client_credential_required" } };
    } catch (error) {
      // Preserve the review and failed state; any emitted client must be unusable.
      await revokeMigClient(tenantId, spec.client_id, spec.principal_id);
      const failedCandidate = await storage.getMigRegistryCandidate(tenantId, requestId);
      if (failedCandidate) {
        await storage.updateMigRegistryCandidate(tenantId, requestId, { target: {
          ...(failedCandidate.target as any), host_operator: { ...reviewed, activation_failed: true },
        } });
        await revokeMigRegistryCandidate(tenantId, requestId, actorId);
      }
      await storage.recordMigAuditEvent({ tenantId, actorId, eventType: "host_operator.activation_failed",
        decision: "deny", reason: "Activation interrupted; credential revoked; independent recovery required", payload: { requestId } });
      throw error;
    }
  });
}
