import { createHash, randomBytes, randomUUID, timingSafeEqual } from "crypto";
import { storage } from "../storage";
import type { MigClient, MigClientClass } from "@shared/schema";
import { buildMigAuditEvent, hashPayload, recordMigAuditEvent } from "./mig-audit";
import { appendMigStructuralExecutionResult } from "./mig-structural-pdp";
import { projectTrustedMigOperation } from "./mig-structural-reality";
import {
  assertCanonicalKnowledgeJourneyNarrowing,
  type CanonicalKnowledgeAuthorityDecision,
} from "@shared/corporate-brain/canonical-knowledge-authority";
import type { AccessStep } from "./mig-intent-access-projection";

const PREFIX = { AGENT: "mig_agent_", MCP: "mig_mcp_" } as const;
const hashKey = (key: string) => createHash("sha256").update(key, "utf8").digest("hex");

export async function registerMigClient(input: {
  tenantId: string; componentId: string; principalId: string; clientClass: MigClientClass; originUserId?: string;
  capabilityCeiling?: string[];
  scopes?: string[]; allowedIntents?: string[]; allowedDomains?: string[];
  allowedMcpTargets?: string[]; allowedCapabilities?: string[]; resourceScopes?: string[];
  riskZoneCeiling?: "low" | "medium" | "high" | "critical";
}): Promise<{ client: MigClient; apiKey: string }> {
  if (input.clientClass !== "AGENT" && input.clientClass !== "MCP") throw new Error("MIG_CLIENT_CLASS_INVALID");
  if (input.clientClass === "AGENT" && !input.originUserId) throw new Error("MIG_AGENT_ORIGIN_USER_REQUIRED");
  const apiKey = `${PREFIX[input.clientClass]}${randomBytes(32).toString("base64url")}`;
  const credentialHash = hashKey(apiKey);
  const client = await storage.createMigClient({
    ...input, credentialHash, credentialPrefix: PREFIX[input.clientClass], status: "active",
  });
  await storage.createMigCredentialBinding({
    credentialRef: `mig-key:${credentialHash}`, tenantId: input.tenantId, principalId: input.principalId,
    credentialType: input.clientClass === "AGENT" ? "mig_agent" : "mig_mcp",
    providerKind: "mcp",
    status: "active",
    capabilityCeiling: input.capabilityCeiling ?? input.allowedCapabilities ?? [],
    allowedCapabilities: input.allowedCapabilities ?? input.capabilityCeiling ?? [],
    scopes: input.scopes ?? (input.clientClass === "AGENT"
      ? ["intents:create", "intents:continue", "mig:request"]
      : ["mcp:invoke", "mcp:result", "mcp:child-request"]),
    allowedIntents: input.allowedIntents ?? [],
    allowedDomains: input.allowedDomains ?? [],
    allowedMcpTargets: input.allowedMcpTargets ?? (input.clientClass === "MCP" ? [input.componentId] : []),
    resourceScopes: input.resourceScopes ?? [],
    riskZoneCeiling: input.riskZoneCeiling,
  });
  return { client, apiKey };
}

export async function authenticateMigClient(apiKey: string): Promise<MigClient | undefined> {
  const claimed = apiKey.startsWith(PREFIX.AGENT) ? "AGENT" : apiKey.startsWith(PREFIX.MCP) ? "MCP" : undefined;
  if (!claimed || apiKey.length < PREFIX[claimed].length + 32) return undefined;
  const digest = hashKey(apiKey);
  const [client, binding] = await Promise.all([
    storage.getActiveMigClientByCredentialHash(digest),
    storage.getActiveMigCredentialBinding(`mig-key:${digest}`),
  ]);
  if (!client || client.clientClass !== claimed || client.credentialPrefix !== PREFIX[claimed]) return undefined;
  if (!binding || binding.tenantId !== client.tenantId || binding.principalId !== client.principalId ||
      binding.credentialType !== (claimed === "AGENT" ? "mig_agent" : "mig_mcp")) return undefined;
  const a = Buffer.from(client.credentialHash, "hex"), b = Buffer.from(hashKey(apiKey), "hex");
  return a.length === b.length && timingSafeEqual(a, b) ? client : undefined;
}

export async function assertAuthenticatedMcpCapability(client: MigClient, capabilityId: string) {
  if (client.clientClass !== "MCP") return;
  const binding = await storage.getActiveMigCredentialBinding(`mig-key:${client.credentialHash}`);
  if (!binding || !capabilityId || !binding.capabilityCeiling.includes(capabilityId)) {
    throw new Error("MIG_MCP_CAPABILITY_CEILING_DENIED");
  }
}

export async function revokeMigClient(tenantId: string, componentId: string, principalId?: string) {
  return storage.revokeMigClient(tenantId, componentId, principalId);
}

export interface MigCallProposal {
  journeyId?: string; callId?: string; parentCallId?: string; originUserId?: string;
  rootIntentId?: string; rootIntent?: string; currentIntentId: string; currentIntent: string;
  targetComponentId: string; payload: unknown;
}

export interface MigJourneyAuthority {
  toolName: string; capabilityId: string; semanticAction: string; domainId: string;
  resourceRef: string; targetComponentId: string; riskZone: "low" | "medium" | "high" | "critical";
  structuralDecisionRef?: string; structuralAllowed?: boolean;
  canonicalKnowledgeAuthority?: CanonicalKnowledgeAuthorityDecision;
}

export const MIG_INTENT_TRANSITION_GOVERNOR_ROLE = "journey_governor";
export const MIG_INTENT_TRANSITION_APPROVAL_CAPABILITY = "mig.journey.intent_transition.approve";
export const MIG_INTENT_TRANSITION_REVOCATION_CAPABILITY = "mig.journey.intent_transition.revoke";

const riskRank = { low: 0, medium: 1, high: 2, critical: 3 } as const;
const journeyAuthorityFingerprint = (authority: Partial<MigJourneyAuthority>) => hashPayload({
  toolName: authority.toolName ?? null,
  capabilityId: authority.capabilityId ?? null,
  semanticAction: authority.semanticAction ?? null,
  domainId: authority.domainId ?? null,
  resourceRef: authority.resourceRef ?? null,
  targetComponentId: authority.targetComponentId ?? null,
  riskZone: authority.riskZone ?? null,
  structuralDecisionRef: authority.structuralDecisionRef ?? null,
  structuralAllowed: authority.structuralAllowed ?? false,
});

async function approveMigJourneyIntentTransition(input: {
  tenantId: string; journeyId: string; parentCallId: string;
  sourceIntentId: string; targetIntentId: string;
  authorityDelta: MigJourneyAuthority; approverPrincipalId: string; expiresAt: Date;
  successAudit: import("@shared/schema").InsertMigAuditLog;
}) {
  if (!input.sourceIntentId || !input.targetIntentId || input.sourceIntentId === input.targetIntentId) {
    throw new Error("MIG_INTENT_TRANSITION_INVALID");
  }
  if (!(input.expiresAt instanceof Date) || !Number.isFinite(input.expiresAt.getTime()) ||
      input.expiresAt.getTime() <= Date.now()) throw new Error("MIG_INTENT_TRANSITION_EXPIRY_INVALID");
  const [journey, parent, parentOutcome, approver] = await Promise.all([
    storage.getMigJourney(input.tenantId, input.journeyId),
    storage.getMigJourneyCall(input.tenantId, input.parentCallId),
    storage.getMigJourneyOutcome(input.tenantId, input.parentCallId),
    storage.getMigPrincipal(input.tenantId, input.approverPrincipalId),
  ]);
  if (!journey || !parent || parent.journeyId !== journey.journeyId) throw new Error("MIG_INTENT_TRANSITION_LINEAGE_INVALID");
  if (parent.currentIntentId !== input.sourceIntentId) throw new Error("MIG_INTENT_TRANSITION_SOURCE_INVALID");
  if (!parentOutcome || parentOutcome.outcome !== "succeeded") throw new Error("MIG_INTENT_TRANSITION_PARENT_NOT_SUCCESSFUL");
  if (!approver || approver.status !== "active" || approver.principalType !== "human") {
    throw new Error("MIG_INTENT_TRANSITION_APPROVER_INVALID");
  }
  if (parent.sequence > 0 && input.targetIntentId === journey.rootIntentId) {
    throw new Error("MIG_INTENT_TRANSITION_ROOT_RESET_FORBIDDEN");
  }
  return storage.createMigJourneyIntentTransitionWithAudit({
    transitionId: `mig_intent_transition_${randomUUID()}`,
    tenantId: input.tenantId, journeyId: journey.journeyId, parentCallId: parent.callId,
    sourceIntentId: input.sourceIntentId, targetIntentId: input.targetIntentId,
    authorityDelta: input.authorityDelta, approverPrincipalId: input.approverPrincipalId,
    expiresAt: input.expiresAt,
  }, input.successAudit);
}

/**
 * Governed human issuance boundary. The authenticated user subject is supplied
 * by the server session adapter; request identity fields are intentionally not
 * part of this contract.
 */
export async function issueGovernedMigJourneyIntentTransition(input: {
  tenantId: string; authenticatedUserId: string; journeyId: string; parentCallId: string;
  sourceIntentId: string; targetIntentId: string;
  authorityDelta: MigJourneyAuthority; expiresAt: Date;
}) {
  let approverPrincipalId: string | undefined;
  let canonicalJourneyId: string | undefined;
  let canonicalParentCallId: string | undefined;
  const auditInput = (decision: "allow" | "deny", reason: string) => ({
      eventType: "intent_transition_approval",
      decision,
      tenantId: input.tenantId,
      authenticatedPrincipalId: approverPrincipalId,
      journeyId: canonicalJourneyId,
      parentCallId: canonicalParentCallId,
      intentId: input.targetIntentId,
      capabilityId: input.authorityDelta?.capabilityId,
      resourceRef: input.authorityDelta?.resourceRef,
      riskZone: input.authorityDelta?.riskZone,
      policyDecision: reason,
      reason,
      inputHash: hashPayload({
        journeyId: input.journeyId,
        parentCallId: input.parentCallId,
        sourceIntentId: input.sourceIntentId,
        targetIntentId: input.targetIntentId,
        authorityDelta: {
          toolName: input.authorityDelta?.toolName,
          capabilityId: input.authorityDelta?.capabilityId,
          semanticAction: input.authorityDelta?.semanticAction,
          domainId: input.authorityDelta?.domainId,
          resourceRef: input.authorityDelta?.resourceRef,
          targetComponentId: input.authorityDelta?.targetComponentId,
          riskZone: input.authorityDelta?.riskZone,
          structuralDecisionRef: input.authorityDelta?.structuralDecisionRef,
          structuralAllowed: input.authorityDelta?.structuralAllowed,
        },
        expiresAt: input.expiresAt instanceof Date && Number.isFinite(input.expiresAt.getTime())
          ? input.expiresAt.toISOString()
          : "invalid",
      }),
    } as const);

  try {
    const [principals, requestedJourney, requestedParent] = await Promise.all([
      storage.listMigPrincipals(input.tenantId),
      storage.getMigJourney(input.tenantId, input.journeyId),
      storage.getMigJourneyCall(input.tenantId, input.parentCallId),
    ]);
    if (requestedParent) {
      canonicalParentCallId = requestedParent.callId;
      canonicalJourneyId = requestedParent.journeyId;
    } else if (requestedJourney) {
      canonicalJourneyId = requestedJourney.journeyId;
    }
    const approver = principals.find(candidate =>
      candidate.subjectRef === input.authenticatedUserId &&
      candidate.principalType === "human" &&
      candidate.status === "active");
    if (!approver) throw new Error("MIG_INTENT_TRANSITION_AUTHENTICATED_GOVERNOR_REQUIRED");
    approverPrincipalId = approver.principalId;

    const [entitlement, policy, journey, parent] = await Promise.all([
    storage.getActiveMigPrincipalEntitlement(input.tenantId, approver.principalId),
    storage.getMigTenantAuthorizationPolicy(input.tenantId),
    storage.getMigJourney(input.tenantId, input.journeyId),
    storage.getMigJourneyCall(input.tenantId, input.parentCallId),
    ]);
    if (!entitlement || !policy || policy.status !== "active") {
      throw new Error("MIG_INTENT_TRANSITION_GOVERNANCE_AUTHORITY_REQUIRED");
    }
  const roles = new Set(Array.isArray(entitlement.assignedRoles) ? entitlement.assignedRoles : []);
  const capabilities = new Set(Array.isArray(entitlement.capabilityIds) ? entitlement.capabilityIds : []);
  const intents = new Set(Array.isArray(entitlement.intentIds) ? entitlement.intentIds : []);
  const resources = new Set(Array.isArray(entitlement.resourceScopes) ? entitlement.resourceScopes : []);
  const policyCapabilities = new Set(Array.isArray(policy.capabilityIds) ? policy.capabilityIds : []);
  const entitlementDomains = new Set(Array.isArray(entitlement.domainIds) ? entitlement.domainIds : []);
  const policyIntents = new Set(Array.isArray(policy.intentIds) ? policy.intentIds : []);
  const policyDomains = new Set(Array.isArray(policy.domainIds) ? policy.domainIds : []);
  const policyResources = new Set(Array.isArray(policy.resourceScopes) ? policy.resourceScopes : []);
  const policyRiskZones = new Set(Array.isArray(policy.allowedRiskZones) ? policy.allowedRiskZones : []);
  if (!roles.has(MIG_INTENT_TRANSITION_GOVERNOR_ROLE) ||
      !capabilities.has(MIG_INTENT_TRANSITION_APPROVAL_CAPABILITY) ||
      !capabilities.has(input.authorityDelta.capabilityId) ||
      !(intents.has("*") || intents.has(input.targetIntentId)) ||
      !(entitlementDomains.has("*") || entitlementDomains.has(input.authorityDelta.domainId)) ||
      !(resources.has("*") || (resources.has(input.journeyId) && resources.has(input.authorityDelta.resourceRef))) ||
      !(policyCapabilities.has("*") || policyCapabilities.has(MIG_INTENT_TRANSITION_APPROVAL_CAPABILITY)) ||
      !(policyCapabilities.has("*") || policyCapabilities.has(input.authorityDelta.capabilityId)) ||
      !(policyIntents.has("*") || policyIntents.has(input.targetIntentId)) ||
      !(policyDomains.has("*") || policyDomains.has(input.authorityDelta.domainId)) ||
      !(policyResources.has("*") || (policyResources.has(input.journeyId) && policyResources.has(input.authorityDelta.resourceRef))) ||
      !(policyRiskZones.has("*") || policyRiskZones.has(input.authorityDelta.riskZone))) {
    throw new Error("MIG_INTENT_TRANSITION_GOVERNOR_ENTITLEMENT_DENIED");
  }
  if (!journey || !parent || parent.journeyId !== journey.journeyId) {
    throw new Error("MIG_INTENT_TRANSITION_LINEAGE_INVALID");
  }
  const parentClient = await storage.getActiveMigClientByComponent(input.tenantId, parent.callerComponentId);
  if (!parentClient) throw new Error("MIG_INTENT_TRANSITION_REQUESTER_AUTHORITY_UNRESOLVED");
  const requesterEntitlement = await storage.getActiveMigPrincipalEntitlement(
    input.tenantId, parentClient.principalId,
  );
  if (!requesterEntitlement) throw new Error("MIG_INTENT_TRANSITION_REQUESTER_AUTHORITY_UNRESOLVED");
  const requesterRoles = new Set(Array.isArray(requesterEntitlement.assignedRoles)
    ? requesterEntitlement.assignedRoles : []);
  const conflicts = Array.isArray(policy.staticSodConflicts) ? policy.staticSodConflicts : [];
  if (conflicts.some(pair => {
    if (!Array.isArray(pair) || pair.length !== 2) return false;
    const left = String(pair[0]), right = String(pair[1]);
    return (roles.has(left) && (roles.has(right) || requesterRoles.has(right))) ||
      (roles.has(right) && requesterRoles.has(left));
  })) {
    throw new Error("MIG_INTENT_TRANSITION_STATIC_SOD_CONFLICT");
  }
  if (journey.originUserId === input.authenticatedUserId ||
      parentClient?.principalId === approver.principalId) {
    throw new Error("MIG_INTENT_TRANSITION_DYNAMIC_SOD_SELF_APPROVAL");
  }
    const transition = await approveMigJourneyIntentTransition({
      tenantId: input.tenantId,
      journeyId: input.journeyId,
      parentCallId: input.parentCallId,
      sourceIntentId: input.sourceIntentId,
      targetIntentId: input.targetIntentId,
      authorityDelta: input.authorityDelta,
      approverPrincipalId: approver.principalId,
      expiresAt: input.expiresAt,
      successAudit: buildMigAuditEvent(
        auditInput("allow", "MIG_INTENT_TRANSITION_APPROVED"),
      ).data,
    });
    return transition;
  } catch (error) {
    const reason = error instanceof Error ? error.message : "MIG_INTENT_TRANSITION_ISSUANCE_FAILED";
    await recordMigAuditEvent(auditInput("deny", reason));
    throw error;
  }
}

export async function revokeGovernedMigJourneyIntentTransition(input: {
  tenantId: string; authenticatedUserId: string; journeyId: string;
  transitionId: string; reason: string;
}) {
  if (!input.reason?.trim()) throw new Error("MIG_INTENT_TRANSITION_REVOCATION_REASON_REQUIRED");
  const principals = await storage.listMigPrincipals(input.tenantId);
  const revoker = principals.find(candidate =>
    candidate.subjectRef === input.authenticatedUserId &&
    candidate.principalType === "human" &&
    candidate.status === "active");
  if (!revoker) throw new Error("MIG_INTENT_TRANSITION_AUTHENTICATED_GOVERNOR_REQUIRED");

  const [entitlement, policy, journey] = await Promise.all([
    storage.getActiveMigPrincipalEntitlement(input.tenantId, revoker.principalId),
    storage.getMigTenantAuthorizationPolicy(input.tenantId),
    storage.getMigJourney(input.tenantId, input.journeyId),
  ]);
  if (!entitlement || !policy || policy.status !== "active") {
    throw new Error("MIG_INTENT_TRANSITION_GOVERNANCE_AUTHORITY_REQUIRED");
  }
  const transition = journey
    ? await storage.getMigJourneyIntentTransition(input.tenantId, input.journeyId, input.transitionId)
    : undefined;
  if (!journey || !transition || transition.journeyId !== journey.journeyId) {
    throw new Error("MIG_INTENT_TRANSITION_REVOCATION_TARGET_INVALID");
  }
  const roles = new Set(Array.isArray(entitlement.assignedRoles) ? entitlement.assignedRoles : []);
  const capabilities = new Set(Array.isArray(entitlement.capabilityIds) ? entitlement.capabilityIds : []);
  const resources = new Set(Array.isArray(entitlement.resourceScopes) ? entitlement.resourceScopes : []);
  const policyCapabilities = new Set(Array.isArray(policy.capabilityIds) ? policy.capabilityIds : []);
  const policyResources = new Set(Array.isArray(policy.resourceScopes) ? policy.resourceScopes : []);
  if (!roles.has(MIG_INTENT_TRANSITION_GOVERNOR_ROLE) ||
      !capabilities.has(MIG_INTENT_TRANSITION_REVOCATION_CAPABILITY) ||
      !(resources.has("*") || resources.has(input.journeyId)) ||
      !(policyCapabilities.has("*") || policyCapabilities.has(MIG_INTENT_TRANSITION_REVOCATION_CAPABILITY)) ||
      !(policyResources.has("*") || policyResources.has(input.journeyId))) {
    throw new Error("MIG_INTENT_TRANSITION_GOVERNOR_ENTITLEMENT_DENIED");
  }
  const parent = await storage.getMigJourneyCall(input.tenantId, transition.parentCallId);
  if (!parent) throw new Error("MIG_INTENT_TRANSITION_REVOCATION_TARGET_INVALID");
  const parentClient = await storage.getActiveMigClientByComponent(input.tenantId, parent.callerComponentId);
  if (!parentClient) throw new Error("MIG_INTENT_TRANSITION_REQUESTER_AUTHORITY_UNRESOLVED");
  const requesterEntitlement = await storage.getActiveMigPrincipalEntitlement(input.tenantId, parentClient.principalId);
  if (!requesterEntitlement) throw new Error("MIG_INTENT_TRANSITION_REQUESTER_AUTHORITY_UNRESOLVED");
  const requesterRoles = new Set(Array.isArray(requesterEntitlement.assignedRoles) ? requesterEntitlement.assignedRoles : []);
  const conflicts = Array.isArray(policy.staticSodConflicts) ? policy.staticSodConflicts : [];
  if (conflicts.some(pair => {
    if (!Array.isArray(pair) || pair.length !== 2) return false;
    const left = String(pair[0]), right = String(pair[1]);
    return (roles.has(left) && (roles.has(right) || requesterRoles.has(right))) ||
      (roles.has(right) && requesterRoles.has(left));
  })) {
    throw new Error("MIG_INTENT_TRANSITION_STATIC_SOD_CONFLICT");
  }
  if (journey.originUserId === input.authenticatedUserId || parentClient.principalId === revoker.principalId) {
    throw new Error("MIG_INTENT_TRANSITION_DYNAMIC_SOD_SELF_APPROVAL");
  }
  return storage.createMigJourneyIntentTransitionRevocation({
    revocationId: `mig_intent_transition_revocation_${randomUUID()}`,
    transitionId: transition.transitionId,
    tenantId: input.tenantId,
    journeyId: input.journeyId,
    parentCallId: transition.parentCallId,
    revokedByPrincipalId: revoker.principalId,
    reason: input.reason.trim(),
  });
}

/**
 * The single journey-level governor. It compares canonical adapter metadata
 * with immutable lineage and previously successful admissions; request content
 * is intentionally absent from the authority model.
 */
export async function authorizeMigJourneyCall(client: MigClient, journey: import("@shared/schema").MigJourney,
  call: import("@shared/schema").MigJourneyCall, proposed: MigJourneyAuthority,
  phase: "post" | "pre" = "post") {
  const calls = await storage.listMigJourneyCalls(client.tenantId, journey.journeyId);
  const outcomes = await storage.listMigJourneyOutcomes(client.tenantId, journey.journeyId);
  const prior = calls.filter(candidate => candidate.callId !== call.callId).map(candidate => ({
    call: candidate,
    outcome: outcomes.find(outcome => outcome.callId === candidate.callId && outcome.outcome === "succeeded"),
    admission: outcomes.find(outcome => outcome.callId === candidate.callId && outcome.outcome === "allowed"),
  }));
  const successful = prior.filter(item => item.outcome?.outcome === "succeeded");
  const initial = calls.find(candidate => candidate.sequence === 0);
  const baseline = initial
    ? prior.find(item => item.call.callId === initial.callId)?.admission?.effectiveAuthority as Partial<MigJourneyAuthority> | undefined
    : undefined;
  // Temperature is evidence-derived only: a critical-risk admitted hop is
  // CRITICAL; a structurally allowed material hop is HOT; prior successful
  // hops are WARM; an unexecuted root admission is COOL.
  const state = proposed.riskZone === "critical" ? "CRITICAL" :
    proposed.structuralAllowed ? "HOT" : successful.length > 0 ? "WARM" : "COOL";
  const accumulatedState = {
    successful_call_ids: successful.map(item => item.call.callId),
    participant_component_ids: [...new Set(calls.map(item => item.callerComponentId))],
    reached_target_component_ids: [...new Set(calls.map(item => item.targetComponentId))],
    admitted_capability_ids: [...new Set(successful.map(item =>
      (item.admission?.effectiveAuthority as Partial<MigJourneyAuthority> | undefined)?.capabilityId).filter(Boolean))],
    admitted_semantic_actions: [...new Set(successful.map(item =>
      (item.admission?.effectiveAuthority as Partial<MigJourneyAuthority> | undefined)?.semanticAction).filter(Boolean))],
    admitted_resources: [...new Set(successful.map(item =>
      (item.admission?.effectiveAuthority as Partial<MigJourneyAuthority> | undefined)?.resourceRef).filter(Boolean))],
    state,
  };
  const deny = (reason: string) => ({ allowed: false as const, reason, state, accumulatedState, requestedAuthority: proposed });
  if (call.sequence === 0 && call.currentIntentId !== journey.rootIntentId) {
    return deny("MIG_JOURNEY_ROOT_INTENT_RESET_DENIED");
  }
  if (call.parentCallId) {
    const parent = prior.find(item => item.call.callId === call.parentCallId);
    if (!parent || parent.outcome?.outcome !== "succeeded" || parent.call.targetComponentId !== client.componentId) {
      return deny("MIG_JOURNEY_PARENT_NOT_SUCCESSFUL");
    }
    if (calls.some(item => item.callId !== call.callId && item.parentCallId === call.parentCallId)) {
      return deny("MIG_JOURNEY_PARENT_REUSED");
    }
    if (call.currentIntentId !== parent.call.currentIntentId) {
      const transitions = await storage.listMigJourneyIntentTransitions(
        client.tenantId, journey.journeyId, parent.call.callId,
      );
      let transition: import("@shared/schema").MigJourneyIntentTransition | undefined;
      let matchingRevoked = false;
      for (const candidate of transitions) {
        if (candidate.sourceIntentId !== parent.call.currentIntentId ||
            candidate.targetIntentId !== call.currentIntentId ||
            new Date(candidate.expiresAt).getTime() <= Date.now() ||
            journeyAuthorityFingerprint(candidate.authorityDelta as Partial<MigJourneyAuthority>) !==
              journeyAuthorityFingerprint(proposed)) continue;
        const revocation = await storage.getMigJourneyIntentTransitionRevocation(client.tenantId, candidate.transitionId);
        if (!revocation) {
          transition = candidate;
          break;
        }
        matchingRevoked = true;
      }
      if (matchingRevoked && !transition) return deny("MIG_JOURNEY_INTENT_TRANSITION_REVOKED");
      if (!transition) return deny("MIG_JOURNEY_INTENT_TRANSITION_REQUIRED");
    }
  }
  const isMaterial = proposed.semanticAction !== "read";
  const successfulAuthorities = successful.map(item =>
    item.admission?.effectiveAuthority as Partial<MigJourneyAuthority> | undefined).filter(Boolean);
  const priorTargets = new Set(successful.map(item => item.call.targetComponentId));
  const priorReadCapabilities = new Set(successfulAuthorities
    .filter(authority => authority?.semanticAction === "read").map(authority => authority?.capabilityId).filter(Boolean));
  const priorReadTargets = new Set(successful.filter(item =>
    (item.admission?.effectiveAuthority as Partial<MigJourneyAuthority> | undefined)?.semanticAction === "read")
    .map(item => item.call.targetComponentId));
  const priorMaterial = successfulAuthorities.filter(authority => authority?.semanticAction !== "read");
  const materialBaseline = priorMaterial[priorMaterial.length - 1];
  if (phase === "post" && isMaterial && !proposed.structuralAllowed) return deny("MIG_JOURNEY_STRUCTURAL_REAUTHORIZATION_REQUIRED");
  const parentKnowledge = materialBaseline?.canonicalKnowledgeAuthority ?? baseline?.canonicalKnowledgeAuthority;
  if (parentKnowledge && proposed.canonicalKnowledgeAuthority) {
    try {
      assertCanonicalKnowledgeJourneyNarrowing(parentKnowledge, proposed.canonicalKnowledgeAuthority);
    } catch (error) {
      return deny(error instanceof Error ? error.message : "CB_KNOWLEDGE_JOURNEY_AUTHORITY_ESCALATION");
    }
  } else if (parentKnowledge && !proposed.canonicalKnowledgeAuthority) {
    return deny("CB_KNOWLEDGE_JOURNEY_AUTHORITY_MISSING");
  }
  // Canonical BRIPe ALLOW is necessary, but never sufficient for composition.
  // Read evolution is bounded by credential/enterprise checks upstream. Once a
  // side effect is proposed, accumulated reachability and authority may not
  // silently expand without a persisted journey-elevation relation (none
  // exists today).
  if (isMaterial && priorMaterial.length === 0 && (priorReadCapabilities.size > 1 || priorReadTargets.size > 1)) {
    return deny("MIG_JOURNEY_CAPABILITY_COMPOUNDING_DENIED");
  }
  if (isMaterial && successful.length > 0 && !priorTargets.has(proposed.targetComponentId)) {
    return deny("MIG_JOURNEY_NEW_REACHABILITY_DENIED");
  }
  if (materialBaseline?.capabilityId && materialBaseline.capabilityId !== proposed.capabilityId) {
    return deny("MIG_JOURNEY_CAPABILITY_COMPOUNDING_DENIED");
  }
  if (materialBaseline?.resourceRef && materialBaseline.resourceRef !== proposed.resourceRef) {
    return deny("MIG_JOURNEY_RESOURCE_EXPANSION_DENIED");
  }
  if (materialBaseline?.semanticAction && materialBaseline.semanticAction !== proposed.semanticAction) {
    return deny("MIG_JOURNEY_ACTION_ESCALATION_DENIED");
  }
  const priorRisk = materialBaseline?.riskZone ?? baseline?.riskZone;
  if (priorRisk && riskRank[proposed.riskZone] > riskRank[priorRisk]) {
    return deny("MIG_JOURNEY_RISK_ESCALATION_DENIED");
  }
  return { allowed: true as const, reason: "journey_authorized", state, accumulatedState, requestedAuthority: proposed,
    effectiveAuthority: proposed };
}

/** Performs lineage/reachability checks before BRIPe. Structural permission is
 * deliberately deferred; the canonical evaluator remains the sole source of
 * structural authorization. */
export async function preauthorizeMigJourneyCall(client: MigClient,
  journey: import("@shared/schema").MigJourney, call: import("@shared/schema").MigJourneyCall,
  proposed: MigJourneyAuthority) {
  return authorizeMigJourneyCall(client, journey, call, proposed, "pre");
}

export async function beginMigJourneyCall(client: MigClient, proposal: MigCallProposal) {
  if (!proposal.currentIntentId || !proposal.currentIntent || !proposal.targetComponentId) throw new Error("MIG_CALL_LINEAGE_REQUIRED");
  if (!proposal.journeyId) {
    if (client.clientClass !== "AGENT") throw new Error("MIG_ORIGIN_MUST_BE_AGENT");
    const binding = await storage.getActiveMigCredentialBinding(`mig-key:${client.credentialHash}`);
    if (!binding || !binding.scopes.includes("intents:create") || !binding.scopes.includes("mig:request") ||
      !binding.allowedIntents.includes(proposal.currentIntentId) ||
      !binding.allowedMcpTargets.includes(proposal.targetComponentId)) throw new Error("MIG_CREDENTIAL_CEILING_DENIED");
    if (proposal.parentCallId) throw new Error("MIG_ROOT_PARENT_FORBIDDEN");
    if (!client.originUserId || !proposal.rootIntentId || !proposal.rootIntent) throw new Error("MIG_ROOT_LINEAGE_REQUIRED");
  }
  const target = await storage.getActiveMigClientByComponent(client.tenantId, proposal.targetComponentId);
  if (!target) throw new Error("MIG_TARGET_NOT_REGISTERED");
  const targetPrincipal = await storage.getMigPrincipal(client.tenantId, target.principalId);
  if (!targetPrincipal || targetPrincipal.status !== "active") throw new Error("MIG_TARGET_NOT_ACTIVE");
  // Call identity is always minted by MIG. Caller metadata cannot choose or
  // reuse a call ID to splice or orphan immutable lineage.
  const callId = `mig_call_${randomUUID()}`;
  let journey;
  let sequence = 0;
  if (!proposal.journeyId) {
    journey = await storage.createMigJourney({
      journeyId: `mig_journey_${randomUUID()}`, tenantId: client.tenantId,
      originUserId: client.originUserId, originAgentId: client.componentId,
      rootIntentId: proposal.rootIntentId, rootIntent: proposal.rootIntent,
    });
  } else {
    const binding = await storage.getActiveMigCredentialBinding(`mig-key:${client.credentialHash}`);
    const continuationScope = client.clientClass === "MCP" ? "mcp:child-request" : "intents:continue";
    if (!binding || !binding.scopes.includes(continuationScope) || !binding.allowedIntents.includes(proposal.currentIntentId) ||
      !binding.allowedMcpTargets.includes(proposal.targetComponentId)) throw new Error("MIG_CREDENTIAL_CEILING_DENIED");
    journey = await storage.getMigJourney(client.tenantId, proposal.journeyId);
    if (!journey) throw new Error("MIG_JOURNEY_NOT_FOUND");
    if (!proposal.parentCallId) throw new Error("MIG_PARENT_REQUIRED");
    const parent = await storage.getMigJourneyCall(client.tenantId, proposal.parentCallId);
    if (!parent || parent.journeyId !== journey.journeyId) throw new Error("MIG_PARENT_INVALID");
    if (parent.targetComponentId !== client.componentId) throw new Error("MIG_CONTINUATION_NOT_AUTHORIZED");
    const parentOutcome = await storage.getMigJourneyOutcome(client.tenantId, parent.callId);
    if (!parentOutcome || parentOutcome.outcome !== "succeeded") throw new Error("MIG_PARENT_NOT_SUCCESSFUL");
    const calls = await storage.listMigJourneyCalls(client.tenantId, journey.journeyId);
    if (calls.some(call => call.parentCallId === proposal.parentCallId)) throw new Error("MIG_PARENT_REUSED");
    if (proposal.currentIntentId !== parent.currentIntentId) {
      if (parent.sequence > 0 && proposal.currentIntentId === journey.rootIntentId) {
        throw new Error("MIG_JOURNEY_ROOT_INTENT_RESET_DENIED");
      }
      const transitions = await storage.listMigJourneyIntentTransitions(
        client.tenantId, journey.journeyId, parent.callId,
      );
      if (!transitions.some(candidate =>
        candidate.sourceIntentId === parent.currentIntentId &&
        candidate.targetIntentId === proposal.currentIntentId &&
        new Date(candidate.expiresAt).getTime() > Date.now())) {
        throw new Error("MIG_JOURNEY_INTENT_TRANSITION_REQUIRED");
      }
    }
    sequence = calls.length;
  }
  const call = await storage.createMigJourneyCall({
    callId, journeyId: journey.journeyId, tenantId: client.tenantId,
    parentCallId: proposal.parentCallId, sequence,
    currentIntentId: proposal.currentIntentId, currentIntent: proposal.currentIntent,
    callerComponentId: client.componentId, callerClass: client.clientClass,
    targetComponentId: proposal.targetComponentId, inputHash: hashPayload(proposal.payload),
  });
  return { journey, call };
}

/** Runtime adapter for an authenticated MCP continuation.  The MCP never
 * supplies a journey/root/origin identity: MIG derives it from its immutable
 * parent call before invoking the canonical journey writer. */
export async function beginAuthenticatedMcpRuntimeCall(client: MigClient, input: {
  parentCallId: string; currentIntentId: string; currentIntent: string;
  targetComponentId: string; payload: unknown;
}) {
  if (client.clientClass !== "MCP") throw new Error("MIG_MCP_CLIENT_REQUIRED");
  const parent = await storage.getMigJourneyCall(client.tenantId, input.parentCallId);
  if (!parent || parent.targetComponentId !== client.componentId) throw new Error("MIG_CONTINUATION_NOT_AUTHORIZED");
  return beginMigJourneyCall(client, {
    journeyId: parent.journeyId, parentCallId: parent.callId,
    currentIntentId: input.currentIntentId, currentIntent: input.currentIntent,
    targetComponentId: input.targetComponentId, payload: input.payload,
  });
}

/** Server-only journey projection. Caller payloads and structural facts never
 * participate; only persisted successful call outcomes are evidence. */
export async function buildMigJourneyAccessContext(input: {
  tenantId: string; journey: { journeyId: string; rootIntentId: string; tenantId: string };
  currentCall: { callId: string; inputHash: string; targetComponentId: string; journeyId: string };
  requestCorrelationId: string;
}) {
  if (input.journey.tenantId !== input.tenantId || input.currentCall.journeyId !== input.journey.journeyId ||
      input.requestCorrelationId !== input.currentCall.callId) throw new Error("MIG_JOURNEY_CONTEXT_MISMATCH");
  const [calls, outcomes] = await Promise.all([
    storage.listMigJourneyCalls(input.tenantId, input.journey.journeyId),
    storage.listMigJourneyOutcomes(input.tenantId, input.journey.journeyId),
  ]);
  const steps: AccessStep[] = [];
  for (const call of calls.filter(candidate => candidate.sequence < (calls.find(c => c.callId === input.currentCall.callId)?.sequence ?? Infinity))) {
    const callOutcomes = outcomes.filter(outcome => outcome.callId === call.callId);
    if (!callOutcomes.some(outcome => outcome.outcome === "succeeded")) continue;
    const admission = callOutcomes.find(outcome =>
      outcome.outcome === "allowed" && (outcome.effectiveAuthority || outcome.requestedAuthority));
    if (!admission) continue;
    const authority = admission.effectiveAuthority ?? admission.requestedAuthority;
    const a = authority as Record<string, any> | undefined;
    if (!a) continue;
    steps.push({
      step_id: call.callId, tool: String(a.toolName ?? call.targetComponentId),
      capability: String(a.capabilityId ?? "unknown"), operation: String(a.semanticAction ?? "read"),
      resource_refs: [String(a.resourceRef ?? `journey:${call.callId}`)],
      authorization_ref: String(admission.authorizationManifestId ?? call.callId),
      knowledge_authorization_refs: a.canonicalKnowledge?.receiptId ? [String(a.canonicalKnowledge.receiptId)] : [],
      destination: call.targetComponentId,
      evidence_severity: a.riskZone === "critical" ? 1 : a.riskZone === "high" ? .8 :
        a.riskZone === "medium" ? .5 : .2,
    });
  }
  return {
    tenantId: input.tenantId, journeyId: input.journey.journeyId, rootIntentId: input.journey.rootIntentId,
    rootPrincipalId: (input.journey as any).originAgentId,
    currentCallId: input.currentCall.callId, targetComponentId: input.currentCall.targetComponentId,
    steps,
  };
}

export async function sealMigCallOutcome(input: {
  tenantId: string; journeyId: string; callId: string;
  outcome: "allowed" | "denied" | "failed" | "succeeded"; reason: string;
  result?: unknown; resultRef?: string; authorizationManifestId?: string;
  requestedAuthority?: unknown; effectiveAuthority?: unknown; accumulatedState?: unknown;
  structuralDecisionRef?: string; journeyState?: "COOL" | "WARM" | "HOT" | "CRITICAL";
}) {
  if (!["allowed", "denied", "failed", "succeeded"].includes(input.outcome)) throw new Error("MIG_OUTCOME_INVALID");
  if (input.resultRef && input.resultRef.length > 256) throw new Error("MIG_RESULT_REF_TOO_LARGE");
  return storage.createMigJourneyOutcome({
    outcomeId: `mig_outcome_${randomUUID()}`, tenantId: input.tenantId, journeyId: input.journeyId,
    callId: input.callId, outcome: input.outcome, reason: input.reason,
    resultHash: input.result === undefined ? undefined : hashPayload(input.result),
    resultRef: input.resultRef, authorizationManifestId: input.authorizationManifestId,
    requestedAuthority: input.requestedAuthority, effectiveAuthority: input.effectiveAuthority,
    accumulatedState: input.accumulatedState, structuralDecisionRef: input.structuralDecisionRef,
    journeyState: input.journeyState,
  });
}

/**
 * Records an enterprise fabric's result only against the exact previously
 * admitted call and payload. The callback cannot create or redirect lineage.
 */
export async function sealExternalMigCallOutcome(input: {
  tenantId: string; journeyId: string; callId: string; payload: unknown;
  authorityRef: string;
  outcome: "succeeded" | "failed"; reason: string; result?: unknown; resultRef?: string;
}) {
  const [journey, call, currentOutcome] = await Promise.all([
    storage.getMigJourney(input.tenantId, input.journeyId),
    storage.getMigJourneyCall(input.tenantId, input.callId),
    storage.getMigJourneyOutcome(input.tenantId, input.callId),
  ]);
  if (!journey || !call || call.journeyId !== journey.journeyId || !currentOutcome) {
    throw new Error("MIG_EXTERNAL_OUTCOME_ADMISSION_REQUIRED");
  }
  const expectedResultHash = input.result === undefined ? null : hashPayload(input.result);
  const exactRetry = currentOutcome.outcome === input.outcome &&
    currentOutcome.reason === input.reason &&
    (currentOutcome.resultHash ?? null) === expectedResultHash &&
    (currentOutcome.resultRef ?? null) === (input.resultRef ?? null);
  if (currentOutcome.outcome !== "allowed" && !exactRetry) {
    throw new Error("MIG_EXTERNAL_OUTCOME_ADMISSION_REQUIRED");
  }
  const admission = currentOutcome;
  const admittedAuthority = admission.requestedAuthority as { authorityRef?: unknown } | null;
  if (!input.authorityRef || admittedAuthority?.authorityRef !== input.authorityRef) {
    throw new Error("MIG_EXTERNAL_OUTCOME_AUTHORITY_MISMATCH");
  }
  if (call.inputHash !== hashPayload(input.payload)) throw new Error("MIG_EXTERNAL_OUTCOME_PAYLOAD_MISMATCH");
  const execution = admittedAuthority?.structuralExecution as {
    principalId?: string; requestId?: string; realityVersion?: string; deltaId?: string;
    operationInputHash?: string; approvalId?: string; structuralDecisionRef?: string; toolName?: string;
  } | undefined;
  let canonicalExecutionHash: string | undefined;
  if (execution?.structuralDecisionRef) {
    if (!execution.principalId || !execution.requestId || !execution.realityVersion ||
        !execution.deltaId || !execution.operationInputHash || !execution.toolName) {
      throw new Error("MIG_EXTERNAL_OUTCOME_STRUCTURAL_LINEAGE_INVALID");
    }
    canonicalExecutionHash = projectTrustedMigOperation(execution.toolName, "external", input.payload).operation_input_hash;
    if (canonicalExecutionHash !== execution.operationInputHash) {
      throw new Error("MIG_EXTERNAL_OUTCOME_STRUCTURAL_PAYLOAD_MISMATCH");
    }
  }
  const sealed = exactRetry ? currentOutcome : await sealMigCallOutcome({
    tenantId: input.tenantId, journeyId: input.journeyId, callId: input.callId,
    outcome: input.outcome, reason: input.reason, result: input.result, resultRef: input.resultRef,
    requestedAuthority: admission.requestedAuthority ?? undefined,
    effectiveAuthority: admission.effectiveAuthority ?? undefined,
    accumulatedState: admission.accumulatedState ?? undefined,
    authorizationManifestId: admission.authorizationManifestId ?? undefined,
  });
  if (execution?.structuralDecisionRef) {
    await appendMigStructuralExecutionResult({
      tenantId: input.tenantId, principalId: execution.principalId,
      decisionId: execution.structuralDecisionRef, requestId: execution.requestId,
      realityVersion: execution.realityVersion, deltaId: execution.deltaId,
      operationInputHash: execution.operationInputHash,
      executedPayloadHash: canonicalExecutionHash!,
      policyIdentity: { version: "mig-external-fabric-v1", hash: hashPayload({
        authorityRef: input.authorityRef, callId: input.callId,
      }) },
      approvalId: execution.approvalId, outcome: input.outcome,
      downstreamDispatched: true,
      resultHash: input.result === undefined ? undefined : hashPayload(input.result),
      executionError: input.outcome === "failed" ? input.reason : undefined,
    });
  }
  return sealed;
}
export async function reconstructMigJourney(tenantId: string, journeyId: string) {
  const journey = await storage.getMigJourney(tenantId, journeyId);
  if (!journey) return undefined;
  const [calls, outcomes] = await Promise.all([
    storage.listMigJourneyCalls(tenantId, journeyId),
    storage.listMigJourneyOutcomes(tenantId, journeyId),
  ]);
  const byCall = new Map(outcomes.map(outcome => [outcome.callId, outcome]));
  const authorityNodes = await Promise.all(calls.map(async call => {
    const outcome = byCall.get(call.callId);
    const manifest = outcome?.authorizationManifestId
      ? await storage.getMigAuthorizationManifest(tenantId, outcome.authorizationManifestId)
      : undefined;
    const immutableEffective = outcome?.effectiveAuthority as Record<string, any> | null | undefined;
    const immutableAccumulated = outcome?.accumulatedState as Record<string, any> | null | undefined;
    const admittedCapabilities = Array.isArray(immutableAccumulated?.admitted_capability_ids)
      ? immutableAccumulated.admitted_capability_ids
      : immutableEffective?.capabilityId ? [immutableEffective.capabilityId] : [];
    return {
      call_id: call.callId,
      caller: call.callerComponentId,
      requested: { intent_id: call.currentIntentId, intent: call.currentIntent, target_component_id: call.targetComponentId },
      credential: {
        class: call.callerClass,
        // Historical authority is projected only from immutable admission evidence.
        allowed_capabilities: admittedCapabilities,
        risk_zone_ceiling: immutableEffective?.riskZone ?? immutableAccumulated?.risk_zone_ceiling ?? "unavailable",
      },
      authority_source: {
        provider: manifest?.authorityProvider ?? "unavailable",
        reference: manifest?.authorityRef ?? null,
        snapshot_id: manifest?.authoritySnapshotId ?? null,
        observed_at: manifest?.authorityObservedAt ?? null,
        expires_at: manifest?.authorityExpiresAt ?? null,
        evidence_state: manifest ? "verified" : "unavailable",
      },
      journey_authority: {
        root_intent_id: journey.rootIntentId,
        root_intent: journey.rootIntent,
        lineage_valid: call.parentCallId ? true : call.callerClass === "AGENT",
      },
      final_authorization: outcome
        ? { decision: outcome.outcome, reason: outcome.reason, authorization_manifest_id: outcome.authorizationManifestId }
        : { decision: "pending" },
    };
  }));
  return {
    journey,
    calls: calls.map(call => ({ ...call, outcome: byCall.get(call.callId) })),
    outcomeHistory: outcomes,
    // Explainability projection only. The canonical evaluator and immutable
    // journey records remain the authority; this adds no authorization path.
    authorityNodes,
    evidence: {
      intentDrift: new Set(calls.map(call => call.currentIntentId)).size > 1,
      chaining: calls.some(call => call.parentCallId !== null),
      hopping: new Set(calls.map(call => call.callerComponentId)).size > 1,
      compounding: calls.length > 2,
      crossIntentConvergence: new Set(calls.map(call => call.currentIntentId)).size > 1 &&
        new Set(calls.map(call => call.targetComponentId)).size < calls.length,
    },
  };
}
