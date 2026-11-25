/**
 * server/mig/mig-core.ts
 *
 * MIG orchestrator — the single entry point external callers (via
 * server/routes/mig-routes.ts) and internal DPM/DEL wiring use. It composes
 * agent registry, ticket auth, intent library, policy graph, manifest
 * builder, drift detector, and audit into three operations:
 *
 *   issueTicket()          — mints a signed, intent-scoped ticket
 *   authorizeDiscovery()   — resolves a ticket into a filtered tool list
 *   authorizeExecution()   — gates + delegates a single tool call
 *
 * This file has NO BRIPe scoring/decision logic. The only BRIPe-aware
 * dependency is bripeMcpAdapter (imported by mig-mcp-adapter.ts as a
 * default), which stays swappable via the MigDownstreamAdapter interface.
 */

import { getMigAgent, isAgentUsable, setMigAgentStatus } from "./mig-agent-registry";
import { getIntentDefinition } from "./mig-intent-library";
import { signMigTicket, verifyMigTicketSignature, generateTicketId, peekTicketAgentId } from "./mig-auth";
import { buildAndPersistCapabilityManifest } from "./mig-manifest";
import {
  checkAgentDrift, checkIntentDrift, checkPolicyDrift,
  checkNewCapabilityDrift, checkNewDomainDrift, checkRiskEscalationDrift, checkDeclaredIntentDrift,
  checkFrequencyDrift,
} from "./mig-drift-detector";
import { bripeToolCatalog } from "./mig-bripe-adapter";
import { buildBripeAuthorizationCatalog } from "./mig-bripe-adapter";
import { authorizeEnterpriseRequest, authorizeLegacyMigTicketRequest } from "./mig-enterprise-authorization";
import type { VerifiedCredentialIdentity } from "./mig-authorization-context";
import { captureDiscoveryEvent, recordDriftEvent, checkDiscoverySafety, getLatestApprovedProfile } from "./mig-discovery";
import { storage } from "../storage";
import type { MigRiskZone, MigGateResult, MigDownstreamAdapter, MigExecutionStrategy, MigExternalDecision } from "./mig-types";
import type { MigCapabilityManifest, MigTicket } from "@shared/schema";
import { validateCapabilityContract, type OntologyBoundCapabilityContract } from "@shared/enterprise-ontology/contract-ontology";
import { CEO_CURRENT_VERSION } from "@shared/enterprise-ontology/ontology-version";
import { createScopedCEOStore } from "../standalone/enterprise-owner";
import { recordMigAuditEvent, listMigAuditEvents, hashPayload } from "./mig-audit";
import { getGatedToolList, executeGatedTool, checkGatedToolAuthorization, getGatedAuthorityAssertionInput } from "./mig-mcp-adapter";
import { evaluateMigStructuralDecision, appendMigStructuralExecutionResult } from "./mig-structural-pdp";
import type { StructuralDecisionRequestV1 } from "../../shared/contracts/mig-structural-pdp-v1";
import { materializeMigActivityReality, buildMigOperationSignals } from "./mig-structural-reality";
import { resolveMigContextualApprovals } from "./mig-structural-approval";
import { evaluateMigHardBoundaries } from "./mig-hard-boundaries";
import { randomUUID } from "crypto";
import { evaluateConsequentialMigOperation, isMigEnforcementDispatchable, prepareMigOperationForExecution, resolveMigStructuralEnvelope } from "./mig-consequential-operation";
import { issueMigDelegation } from "./mig-delegation";
import {
  createIntentAccessProjection, persistIntentAccessLineage,
  readCurrentSealedBaseline, readCurrentRuntimeProjection, accessProjectionSignals,
  requireConsequentialBaseline, assertBaselineCurrent,
  assertIntentAccessBinding,
  assertNoCallerStructuralFacts,
} from "./mig-intent-access-projection";

const TICKET_TTL_SECONDS = 30 * 60;

export function mapMigExternalDecision(
  enforcement: "ALLOW" | "ALLOW_WITH_CONTROL" | "REQUIRE_APPROVAL" | "BLOCK",
): MigExternalDecision {
  return enforcement === "ALLOW_WITH_CONTROL" ? "CONSTRAIN"
    : enforcement === "REQUIRE_APPROVAL" ? "ESCALATE"
    : enforcement === "BLOCK" ? "STOP"
    : "ALLOW";
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export interface IssueTicketInput {
  agentId: string;
  intentId: string;
  sessionId: string;
}

export interface IssuedTicket {
  token: string;
  jti: string;
  expires_at: string;
}

export async function issueTicket(input: IssueTicketInput): Promise<MigGateResult<IssuedTicket>> {
  const agent = await getMigAgent(input.agentId);
  if (!isAgentUsable(agent)) {
    const result = { decision: "deny" as const, reason: "agent_not_active_or_unknown" };
    await recordMigAuditEvent({
      eventType: "ticket_issued", decision: "deny",
      agentId: input.agentId, intentId: input.intentId, sessionId: input.sessionId,
      policyDecision: "agent_unusable",
    });
    return result;
  }

  const intent = await getIntentDefinition(input.intentId);
  const intentDrift = checkIntentDrift(intent);
  if (intentDrift.drifted || !intent) {
    await recordMigAuditEvent({
      eventType: "ticket_issued", decision: "deny",
      agentId: input.agentId, intentId: input.intentId, sessionId: input.sessionId,
      policyDecision: intentDrift.reason ?? "intent_unusable",
    });
    return { decision: "deny", reason: intentDrift.reason ?? "intent_unusable" };
  }

  // A discovery-mode agent is intentionally unscoped so its real behavior can
  // be observed and later synthesized into a draft profile; the scope check
  // below only applies once an agent has been reviewing/locked/active.
  const agentIntents = Array.isArray(agent.allowedIntents) ? (agent.allowedIntents as string[]) : [];
  if (agent.lifecycleState !== "discovery" && agentIntents.length > 0 && !agentIntents.includes(intent.intentId)) {
    await recordMigAuditEvent({
      eventType: "ticket_issued", decision: "deny",
      agentId: input.agentId, intentId: input.intentId, sessionId: input.sessionId,
      riskZone: intent.riskZone as MigRiskZone,
      policyDecision: "agent_not_scoped_to_intent",
    });
    return { decision: "deny", reason: "agent_not_scoped_to_intent" };
  }

  const jti = generateTicketId();
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    jti,
    agent_id: agent.agentId,
    tenant_id: agent.tenantId,
    intent_library_id: intent.libraryId,
    intent_id: intent.intentId,
    risk_zone: intent.riskZone as MigRiskZone,
    session_id: input.sessionId,
    iat: now,
    exp: now + TICKET_TTL_SECONDS,
  };

  const token = signMigTicket(payload, agent.ticketSecret);

  await storage.createMigTicket({
    jti,
    agentId: agent.agentId,
    tenantId: agent.tenantId,
    intentLibraryId: intent.libraryId,
    intentId: intent.intentId,
    riskZone: intent.riskZone,
    sessionId: input.sessionId,
    expiresAt: new Date(payload.exp * 1000),
  });

  await recordMigAuditEvent({
    eventType: "ticket_issued", decision: "allow",
    ticketJti: jti, agentId: agent.agentId, tenantId: agent.tenantId,
    sessionId: input.sessionId, intentId: intent.intentId, riskZone: intent.riskZone as MigRiskZone,
    policyDecision: "ticket_issued",
  });

  return {
    decision: "allow",
    reason: "ticket_issued",
    data: { token, jti, expires_at: new Date(payload.exp * 1000).toISOString() },
  };
}

interface ResolvedTicketContext {
  agent: Awaited<ReturnType<typeof getMigAgent>>;
  ticketRow: MigTicket;
  intent: Awaited<ReturnType<typeof getIntentDefinition>>;
}

export async function resolveAndValidateTicket(token: string): Promise<MigGateResult<ResolvedTicketContext>> {
  const peekedAgentId = peekTicketAgentId(token);
  if (!peekedAgentId) {
    return { decision: "deny", reason: "malformed_ticket" };
  }

  const agent = await getMigAgent(peekedAgentId);
  if (!agent) {
    return { decision: "deny", reason: "unknown_agent" };
  }

  const verification = verifyMigTicketSignature(token, agent.ticketSecret);
  if (!verification.valid || !verification.payload) {
    await recordMigAuditEvent({
      eventType: "discovery", decision: "deny", agentId: peekedAgentId,
      policyDecision: verification.reason ?? "signature_invalid",
    });
    await captureDiscoveryEvent({
      agent, requestKind: "discover", wasDenied: true,
      denialReason: verification.reason ?? "signature_invalid",
    });
    return { decision: "deny", reason: verification.reason ?? "signature_invalid" };
  }

  const ticketRow = await storage.getMigTicketByJti(verification.payload.jti);
  if (!ticketRow || ticketRow.revoked) {
    await captureDiscoveryEvent({ agent, requestKind: "discover", wasDenied: true, denialReason: "ticket_revoked_or_unknown" });
    return { decision: "deny", reason: "ticket_revoked_or_unknown" };
  }
  if (new Date(ticketRow.expiresAt).getTime() < Date.now()) {
    await captureDiscoveryEvent({ agent, sessionId: ticketRow.sessionId, requestKind: "discover", wasDenied: true, denialReason: "ticket_expired" });
    return { decision: "deny", reason: "ticket_expired" };
  }

  const agentDrift = checkAgentDrift(agent);
  if (agentDrift.drifted) {
    await recordMigAuditEvent({
      eventType: "drift_detected", decision: "deny",
      ticketJti: ticketRow.jti, agentId: agent.agentId, tenantId: agent.tenantId,
      policyDecision: agentDrift.reason ?? "agent_drift",
    });
    await captureDiscoveryEvent({
      agent, sessionId: ticketRow.sessionId, requestKind: "discover",
      wasDenied: true, denialReason: agentDrift.reason ?? "agent_drift",
    });
    return { decision: "drift_blocked", reason: agentDrift.reason };
  }

  const intent = await getIntentDefinition(ticketRow.intentId);
  const intentDrift = checkIntentDrift(intent);
  if (intentDrift.drifted) {
    await recordMigAuditEvent({
      eventType: "drift_detected", decision: "deny",
      ticketJti: ticketRow.jti, agentId: agent.agentId, tenantId: agent.tenantId, intentId: ticketRow.intentId,
      policyDecision: intentDrift.reason ?? "intent_drift",
    });
    await captureDiscoveryEvent({
      agent, sessionId: ticketRow.sessionId, requestKind: "discover", domainHints: (intent?.domainScope as string[] | undefined) ?? [],
      wasDenied: true, denialReason: intentDrift.reason ?? "intent_drift",
    });
    return { decision: "drift_blocked", reason: intentDrift.reason };
  }

  return { decision: "allow", reason: "ticket_valid", data: { agent, ticketRow, intent: intent! } };
}

export interface DiscoveryResult {
  manifest: MigCapabilityManifest;
  tools: ReturnType<typeof getGatedToolList>;
}

export async function authorizeDiscovery(token: string): Promise<MigGateResult<DiscoveryResult>> {
  const resolution = await resolveAndValidateTicket(token);
  if (resolution.decision !== "allow" || !resolution.data) {
    return { decision: resolution.decision, reason: resolution.reason };
  }
  const { agent, ticketRow, intent } = resolution.data;
  const manifestResult = await buildAndPersistCapabilityManifest({
    agent: agent!,
    intent: intent!,
    ticketPayload: {
      jti: ticketRow.jti,
      agent_id: agent!.agentId,
      tenant_id: agent!.tenantId,
      intent_library_id: ticketRow.intentLibraryId,
      intent_id: ticketRow.intentId,
      risk_zone: ticketRow.riskZone as MigRiskZone,
      session_id: ticketRow.sessionId,
      iat: Math.floor(new Date(ticketRow.issuedAt).getTime() / 1000),
      exp: Math.floor(new Date(ticketRow.expiresAt).getTime() / 1000),
    },
    adapterTools: bripeToolCatalog(),
  });

  const tools = getGatedToolList(manifestResult.manifest);

  await recordMigAuditEvent({
    eventType: "discovery", decision: "allow",
    ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
    agentId: agent!.agentId, tenantId: agent!.tenantId, sessionId: ticketRow.sessionId,
    intentId: ticketRow.intentId, riskZone: ticketRow.riskZone as MigRiskZone,
    policyDecision: `${tools.length}_tools_exposed`,
  });

  await captureDiscoveryEvent({
    agent: agent!,
    sessionId: ticketRow.sessionId,
    requestKind: "discover",
    domainHints: (intent!.domainScope as string[] | undefined) ?? [],
    inputShapeKeys: tools.map(t => t.tool_name),
  });

  return { decision: "allow", reason: "discovery_authorized", data: { manifest: manifestResult.manifest, tools } };
}

export async function authorizeExecution(
  token: string,
  toolName: string,
  input: unknown,
  ctx: {
    tenantId: string;
    requestCorrelationId?: string;
    enterpriseAuthorization?: {
      verifiedCredential: VerifiedCredentialIdentity;
      domainId: string;
      resourceRef: string;
      resourceVersion?: string;
      resourceState?: string;
      requestCorrelationId?: string;
      beforeHash?: string;
      afterHash?: string;
      transaction?: { createdByPrincipalId?: string; subjectPrincipalId?: string; governedKind?: string };
      canonicalKnowledge?: import("../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority").CanonicalKnowledgeResource;
      canonicalKnowledgeOperation?: import("../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority").CBAuthorityOperation;
      canonicalKnowledgeResolver?: import("./mig-enterprise-authorization").MigCanonicalKnowledgeResolver;
    };
    // Attached only by the authenticated MIG journey route. It runs after
    // enterprise authorization, projection, and (when material) structural
    // PDP, but before the adapter/tool dispatch.
    journeyAuthorization?: (authority: {
      toolName: string; capabilityId: string; semanticAction: string; domainId: string; resourceRef: string;
      riskZone: "low" | "medium" | "high" | "critical"; structuralDecisionRef?: string; structuralAllowed?: boolean;
      authorizationManifestId: string;
      structuralExecution?: {
        principalId: string; requestId: string; realityVersion: string; deltaId: string;
        operationInputHash: string; approvalId?: string; toolName: string;
      };
    }) => Promise<{ allowed: boolean; reason: string }>;
    journeyPreauthorization?: (authority: {
      toolName: string; capabilityId: string; semanticAction: string; domainId: string; resourceRef: string;
      riskZone: "low" | "medium" | "high" | "critical"; authorizationManifestId: string;
    }) => Promise<{ allowed: boolean; reason: string }>;
    downstreamAdapter?: MigDownstreamAdapter;
    executionStrategy?: MigExecutionStrategy;
    requestedMcpTargetId?: string;
    journeyAccessContext?: {
      tenantId: string; journeyId: string; rootIntentId: string; currentCallId: string;
      rootPrincipalId?: string; targetComponentId: string; steps: import("./mig-intent-access-projection").AccessStep[];
    };
  },
): Promise<MigGateResult<unknown>> {
  const resolution = await resolveAndValidateTicket(token);
  if (resolution.decision !== "allow" || !resolution.data) {
    const evt = await recordMigAuditEvent({
      eventType: "execution", decision: "deny", toolName,
      policyDecision: resolution.reason ?? "ticket_invalid",
    });
    return { decision: resolution.decision, reason: resolution.reason, transition_proof_id: evt.transition_proof_id };
  }
  const { agent, ticketRow, intent } = resolution.data;
  // Tenant is authenticated by the ticket/agent relationship, never by the
  // caller-selected execution context.
  if (ctx.tenantId !== agent!.tenantId || ticketRow.tenantId !== agent!.tenantId ||
      (ctx.enterpriseAuthorization?.verifiedCredential.tenantId !== undefined &&
        ctx.enterpriseAuthorization.verifiedCredential.tenantId !== ticketRow.tenantId)) {
    const evt = await recordMigAuditEvent({
      eventType: "execution", decision: "deny", ticketJti: ticketRow.jti,
      agentId: agent!.agentId, tenantId: agent!.tenantId, toolName,
      policyDecision: "tenant_context_mismatch",
    });
    return { decision: "deny", reason: "tenant_context_mismatch", transition_proof_id: evt.transition_proof_id };
  }

  const manifestResult = await buildAndPersistCapabilityManifest({
    agent: agent!,
    intent: intent!,
    ticketPayload: {
      jti: ticketRow.jti,
      agent_id: agent!.agentId,
      tenant_id: agent!.tenantId,
      intent_library_id: ticketRow.intentLibraryId,
      intent_id: ticketRow.intentId,
      risk_zone: ticketRow.riskZone as MigRiskZone,
      session_id: ticketRow.sessionId,
      iat: Math.floor(new Date(ticketRow.issuedAt).getTime() / 1000),
      exp: Math.floor(new Date(ticketRow.expiresAt).getTime() / 1000),
    },
    adapterTools: bripeToolCatalog(),
  });

  // Safe-discovery sandbox (task-1800 step 2): while unscoped, an agent may
  // only exercise non-destructive tools unless an admin explicitly granted
  // an exception. This is checked BEFORE any drift/policy logic because it
  // is a hard sandbox boundary, not a scope-comparison — no draft profile
  // exists yet for a discovery-mode agent to be compared against.
  if (agent!.lifecycleState === "discovery") {
    const toolEntry = bripeToolCatalog().find(t => t.tool_name === toolName);
    if (toolEntry) {
      const safety = checkDiscoverySafety(agent!, toolEntry);
      if (!safety.safe) {
        const evt = await recordMigAuditEvent({
          eventType: "execution", decision: "deny",
          ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
          agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
          policyDecision: safety.reason ?? "discovery_sandbox_blocked",
        });
        await captureDiscoveryEvent({
          agent: agent!, sessionId: ticketRow.sessionId, requestKind: "execute", toolName,
          domainHints: (intent!.domainScope as string[] | undefined) ?? [],
          wasDenied: true, denialReason: safety.reason,
        });
        return { decision: "deny", reason: safety.reason, transition_proof_id: evt.transition_proof_id };
      }
    }
  }

  const driftResult = checkPolicyDrift(agent!, intent!, manifestResult.manifest);
  if (driftResult.drifted) {
    const evt = await recordMigAuditEvent({
      eventType: "drift_detected", decision: "deny",
      ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
      agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
      policyDecision: driftResult.reason ?? "policy_drift",
    });
    await captureDiscoveryEvent({
      agent: agent!, sessionId: ticketRow.sessionId, requestKind: "execute", toolName,
      domainHints: (intent!.domainScope as string[] | undefined) ?? [],
      wasDenied: true, denialReason: driftResult.reason,
    });
    return { decision: "drift_blocked", reason: driftResult.reason, transition_proof_id: evt.transition_proof_id };
  }

  // Behavioral drift (task-1800 step 6): once an agent has an approved
  // profile, compare its live request against that baseline rather than
  // only against admin-side policy-graph changes. Any critical-severity
  // finding auto-suspends the agent — a locked agent whose declared intent
  // no longer matches what it was locked to, or whose risk zone jumps by
  // 2+ tiers, is treated as a containment event, not a warning.
  const approvedProfile = await getLatestApprovedProfile(agent!.agentId);
  if (approvedProfile && (agent!.lifecycleState === "locked" || agent!.lifecycleState === "active")) {
    const FREQUENCY_WINDOW_MS = 5 * 60 * 1000;
    const recentAuditEvents = await listMigAuditEvents({ agentId: agent!.agentId, limit: 500 });
    const windowStart = Date.now() - FREQUENCY_WINDOW_MS;
    const recentCallCount = recentAuditEvents.filter(e =>
      e.eventType === "execution" && e.decision === "allow" && e.toolName === toolName &&
      new Date(e.createdAt).getTime() >= windowStart,
    ).length;

    const behavioralChecks = [
      checkNewCapabilityDrift(toolName, (approvedProfile.proposedAllowedToolNames as string[]) ?? []),
      checkNewDomainDrift((intent!.domainScope as string[] | undefined) ?? [], (approvedProfile.proposedDomainScope as string[]) ?? []),
      checkRiskEscalationDrift(ticketRow.riskZone as MigRiskZone, approvedProfile.proposedRiskZone as MigRiskZone),
      checkDeclaredIntentDrift(ticketRow.intentId, approvedProfile.resultingIntentId ?? undefined),
      checkFrequencyDrift(recentCallCount),
    ];
    for (const check of behavioralChecks) {
      if (!check.drifted) continue;
      await recordDriftEvent({
        agent: agent!,
        driftType: check.driftType ?? "behavioral_drift",
        toolName,
        detail: check.reason ?? "behavioral_drift_detected",
        severity: check.severity ?? "warning",
      });
      if (check.severity === "critical") {
        await setMigAgentStatus(agent!.agentId, "suspended");
        const evt = await recordMigAuditEvent({
          eventType: "drift_detected", decision: "deny",
          ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
          agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
          policyDecision: `auto_suspended:${check.reason ?? check.driftType}`,
        });
        return { decision: "drift_blocked", reason: check.reason, transition_proof_id: evt.transition_proof_id };
      }
    }
  }

  // CEO OntologyBoundCapabilityContract gate (Task #2129).
  // If the agent declares an ontology_capability_contract for the requested tool,
  // the contract is validated against the live admitted-objects store.
  // MIG fails CLOSED: any validation failure denies execution before the tool runs.
  const agentMetadata = (agent!.metadata as Record<string, unknown> | null) ?? {};
  const agentCapabilityContracts = agentMetadata.ontology_capability_contracts as Record<string, unknown>[] | undefined;
  if (agentCapabilityContracts && Array.isArray(agentCapabilityContracts)) {
    const contractForTool = agentCapabilityContracts.find(
      c => (c as OntologyBoundCapabilityContract).governs_tool === toolName
    ) as OntologyBoundCapabilityContract | undefined;

    if (contractForTool) {
      const ceoStore = createScopedCEOStore(ctx.tenantId);
      // Explicit 5000: capability validation must be exhaustive; a low cap causes
      // false-closed denials when admitted capabilities fall outside the window.
      const admittedObjects = await ceoStore.listEnterpriseObjects(ctx.tenantId, { objectType: "Capability" }, 5000);
      const admittedCapabilityIds = new Set(admittedObjects.map(o => o.canonicalName));
      // Also include by ID
      for (const o of admittedObjects) admittedCapabilityIds.add(o.id);

      const contractValidation = validateCapabilityContract(contractForTool, {
        admitted_capability_ids: admittedCapabilityIds,
        current_ontology_version: CEO_CURRENT_VERSION,
        agent_risk_zone: ticketRow.riskZone as string | undefined,
        // Extract runtime region and intent scope from agent metadata so that
        // regulated_data_residency and intent_scope conditions can be evaluated.
        // Without these, the contract gate fails CLOSED per doctrine.
        operation_region: (agentMetadata.operation_region as string | undefined) ??
          (agentMetadata.deployment_region as string | undefined),
        agent_intent_scope: (agentMetadata.intent_scope as string | undefined) ??
          (agentMetadata.declared_intent_scope as string | undefined),
        governance_established: agent!.lifecycleState === "locked" || agent!.lifecycleState === "active",
      });

      if (contractValidation.overall_decision === "deny") {
        const evt = await recordMigAuditEvent({
          eventType: "execution", decision: "deny",
          ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
          agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
          policyDecision: `ceo_contract_gate_denied:${contractValidation.denial_reason ?? "contract_validation_failed"}`,
        });
        return {
          decision: "deny",
          reason: `CEO OntologyBoundCapabilityContract gate denied: ${contractValidation.denial_reason ?? "contract_validation_failed"}`,
          transition_proof_id: evt.transition_proof_id,
        };
      }
    }
  }

  // Consequential operations are projected and evaluated before material tool
  // execution. Read-only tools retain the manifest-governed low-latency path.
  let structuralDecisionId: string | undefined;
  let structuralEnforcement: "ALLOW" | "ALLOW_WITH_CONTROL" | "REQUIRE_APPROVAL" | "BLOCK" = "ALLOW";
  let downstreamInput = input;
  let structuralLineage: { requestId: string; realityVersion: string; deltaId: string; operationInputHash: string;
    pathFingerprint?: string; projectionId?: string; approvalId?: string; interventionId?: string } | undefined;
  const toolDefinition = bripeToolCatalog().find(tool => tool.tool_name === toolName);
  // Manifest enforcement is a hard boundary and intentionally precedes PDP
  // evaluation, so unauthorized tools cannot consume structural resources.
  const manifestAuthorization = checkGatedToolAuthorization(manifestResult.manifest, toolName);
  if (manifestAuthorization.allowed === false) {
    const evt = await recordMigAuditEvent({
      eventType: "execution", decision: "deny", ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
      agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
      policyDecision: manifestAuthorization.reason ?? "execution_denied",
    });
    return { decision: "deny", reason: manifestAuthorization.reason, transition_proof_id: evt.transition_proof_id };
  }
  const hardBoundary = evaluateMigHardBoundaries({ agent: agent!, intent: intent!, tool: toolDefinition, tenantMatches: true });
  if (hardBoundary.allowed === false) {
    const evt = await recordMigAuditEvent({ eventType: "execution", decision: "deny", ticketJti: ticketRow.jti, agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName, policyDecision: hardBoundary.reason });
    return { decision: "deny", reason: hardBoundary.reason, transition_proof_id: evt.transition_proof_id };
  }
  const enterpriseRequest = {
    intentId: ticketRow.intentId,
    capabilityId: toolDefinition!.capability_id,
    semanticAction: toolDefinition!.classification === "read_only" ? "read" :
      toolDefinition!.classification === "execution" ? "execute" : "administer",
    domainId: ctx.enterpriseAuthorization?.domainId ??
      (asStringArray(intent!.domainScope)[0] ?? toolDefinition!.domain_scope[0] ?? "unknown"),
    resourceRef: ctx.enterpriseAuthorization?.resourceRef ?? `mig-session:${ticketRow.sessionId}`,
    resourceVersion: ctx.enterpriseAuthorization?.resourceVersion,
    resourceState: ctx.enterpriseAuthorization?.resourceState,
    requestCorrelationId: ctx.enterpriseAuthorization?.requestCorrelationId ?? ctx.requestCorrelationId ?? ticketRow.jti,
    delegationRef: manifestResult.manifest.manifestId,
    beforeHash: ctx.enterpriseAuthorization?.beforeHash,
    afterHash: ctx.enterpriseAuthorization?.afterHash,
    transaction: ctx.enterpriseAuthorization?.transaction,
    mcpTargetId: ctx.requestedMcpTargetId,
    canonicalKnowledge: ctx.enterpriseAuthorization?.canonicalKnowledge && ctx.enterpriseAuthorization.canonicalKnowledgeOperation
      ? {
        resource: ctx.enterpriseAuthorization.canonicalKnowledge,
        operation: ctx.enterpriseAuthorization.canonicalKnowledgeOperation,
      }
      : undefined,
  } as const;
  const authorizationCatalog = buildBripeAuthorizationCatalog([ticketRow.intentId]);
  const enterprise = ctx.enterpriseAuthorization
    ? await authorizeEnterpriseRequest(
        ctx.enterpriseAuthorization.verifiedCredential,
        enterpriseRequest,
        authorizationCatalog,
        ctx.enterpriseAuthorization.canonicalKnowledgeResolver,
      )
    : await authorizeLegacyMigTicketRequest({
        agent: agent!,
        ticket: ticketRow,
        intent: intent!,
        manifest: manifestResult.manifest,
        request: enterpriseRequest,
        catalog: authorizationCatalog,
      });
  if (enterprise.decision.decision !== "allow") {
    const evt = await recordMigAuditEvent({
      eventType: "execution", decision: "deny", ticketJti: ticketRow.jti,
      manifestId: manifestResult.manifest.manifestId, agentId: agent!.agentId,
      tenantId: ticketRow.tenantId, intentId: ticketRow.intentId, toolName,
      policyDecision: `enterprise_authorization:${enterprise.decision.reason}`,
    });
    return {
      decision: "deny",
      reason: enterprise.decision.reason,
      transition_proof_id: evt.transition_proof_id,
      authorization_manifest_id: enterprise.authorizationManifestId,
    };
  }
  // Normalize and bind the exact downstream payload for every tool, including
  // harmless reads. MIG-only control metadata is never forwarded.
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    const evt = await recordMigAuditEvent({ eventType: "execution", decision: "deny", ticketJti: ticketRow.jti,
      agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
      policyDecision: "operation_projection_failed" });
    return { decision: "deny", reason: "operation_projection_failed", transition_proof_id: evt.transition_proof_id };
  }
  const suppliedForProjection = { ...input as Record<string, unknown> };
  if (ctx.journeyAccessContext &&
      (ctx.journeyAccessContext.tenantId !== agent!.tenantId ||
       ctx.journeyAccessContext.currentCallId !== (ctx.requestCorrelationId ?? ticketRow.jti) ||
       ctx.journeyAccessContext.rootIntentId !== ticketRow.intentId)) {
    const evt = await recordMigAuditEvent({ eventType: "execution", decision: "deny",
      ticketJti: ticketRow.jti, agentId: agent!.agentId, tenantId: ticketRow.tenantId,
      intentId: ticketRow.intentId, toolName, policyDecision: "MIG_JOURNEY_CONTEXT_MISMATCH" });
    return { decision: "deny", reason: "MIG_JOURNEY_CONTEXT_MISMATCH", transition_proof_id: evt.transition_proof_id };
  }
  try {
    assertNoCallerStructuralFacts(
      await getGatedAuthorityAssertionInput(toolName, suppliedForProjection, ctx.downstreamAdapter), true);
  } catch (error) {
    const evt = await recordMigAuditEvent({ eventType: "execution", decision: "deny", ticketJti: ticketRow.jti,
      agentId: agent!.agentId, tenantId: ticketRow.tenantId, intentId: ticketRow.intentId, toolName,
      policyDecision: error instanceof Error ? error.message : "caller_structural_facts_forbidden" });
    return { decision: "deny", reason: "MIG_CALLER_STRUCTURAL_FACTS_FORBIDDEN", transition_proof_id: evt.transition_proof_id };
  }
  delete suppliedForProjection.structural_pdp;
  let projectedOperation;
  try {
    projectedOperation = prepareMigOperationForExecution({
      toolName, classification: toolDefinition!.classification, suppliedInput: suppliedForProjection,
    }, operation => {
      const boundary = evaluateMigHardBoundaries({
        agent: agent!, intent: intent!, tool: toolDefinition, tenantMatches: true, operation,
      });
      if (boundary.allowed === false) throw new Error(`MIG_OPERATION_BOUNDARY:${boundary.reason}`);
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "operation_boundary_failed";
    const reason = message.startsWith("MIG_OPERATION_BOUNDARY:") ? message.slice("MIG_OPERATION_BOUNDARY:".length) : "operation_projection_failed";
    const evt = await recordMigAuditEvent({ eventType: "execution", decision: "deny", ticketJti: ticketRow.jti,
      agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName, policyDecision: reason });
    return { decision: "deny", reason, transition_proof_id: evt.transition_proof_id };
  }
  downstreamInput = projectedOperation.canonical_payload;
  if (ctx.journeyPreauthorization) {
    const pre = await ctx.journeyPreauthorization({
      toolName, capabilityId: toolDefinition!.capability_id, semanticAction: enterpriseRequest.semanticAction,
      domainId: enterpriseRequest.domainId, resourceRef: enterpriseRequest.resourceRef,
      riskZone: toolDefinition!.risk_zone, authorizationManifestId: enterprise.authorizationManifestId!,
    });
    if (pre.allowed === false) return { decision: "deny", reason: pre.reason };
  }
  // This is intentionally built after MIG and Corporate Brain authorization:
  // the projection is evidence of admitted access, never an authority source.
  // It also makes successful read calls durable evidence for a later material
  // step without sending those reads through BRIPe.
  let accessProjection;
  try {
    const targetComponent = ctx.requestedMcpTargetId ?? "default";
    const targetClient = ctx.requestedMcpTargetId
      ? await storage.getActiveMigClientByComponent(agent!.tenantId, ctx.requestedMcpTargetId)
      : undefined;
    const targetPrincipal = targetClient?.principalId ??
      ctx.enterpriseAuthorization?.verifiedCredential.principalId ?? agent!.principalId ?? agent!.agentId;
    const baselineStream = `${agent!.tenantId}:${targetPrincipal}:${targetComponent}`;
    const runtimePrincipal = ctx.journeyAccessContext?.rootPrincipalId ?? targetPrincipal;
    const streamKey = ctx.journeyAccessContext
      ? `${agent!.tenantId}:${runtimePrincipal}:${ctx.journeyAccessContext.journeyId}`
      : baselineStream;
    const baseline = await readCurrentSealedBaseline(
      agent!.tenantId, targetPrincipal, baselineStream,
    );
    const runtimeLeaf = await readCurrentRuntimeProjection(
      agent!.tenantId,
      ctx.journeyAccessContext?.rootPrincipalId ??
        (ctx.enterpriseAuthorization?.verifiedCredential.principalId ?? agent!.agentId),
      streamKey,
    );
    if (!baseline) throw new Error("MIG_INTENT_ACCESS_BASELINE_INSUFFICIENT");
    if (toolDefinition!.classification !== "read_only") {
      requireConsequentialBaseline(baseline);
      assertBaselineCurrent(baseline!);
    }
    const step = {
      step_id: `${ticketRow.jti}:${toolName}`,
      tool: toolName, capability: toolDefinition!.capability_id,
      operation: enterpriseRequest.semanticAction,
      resource_refs: [enterpriseRequest.resourceRef],
      authorization_ref: enterprise.authorizationManifestId!,
      knowledge_authorization_refs: ctx.enterpriseAuthorization?.canonicalKnowledge
        ? [enterprise.authorizationManifestId!] : [],
      evidence_severity: toolDefinition!.risk_zone === "critical" ? 1 :
        toolDefinition!.risk_zone === "high" ? .8 :
          toolDefinition!.risk_zone === "medium" ? .5 : .2,
      destination: typeof (projectedOperation.canonical_payload as Record<string, unknown>).destination === "string"
        ? (projectedOperation.canonical_payload as Record<string, unknown>).destination as string : undefined,
    };
    const priorSteps = ctx.journeyAccessContext?.steps ?? [];
    const configSteps = baseline.steps;
    const allSteps = [...configSteps, ...priorSteps, step];
    const uniqueSteps = [...new Map(allSteps.map(item => [item.step_id, item])).values()];
    accessProjection = createIntentAccessProjection({
      tenant_id: agent!.tenantId, principal_id: runtimePrincipal,
      execution_id: ctx.journeyAccessContext?.journeyId ?? (ticketRow.sessionId ?? ticketRow.jti),
      intent_id: ctx.journeyAccessContext?.rootIntentId ?? ticketRow.intentId,
      root_intent_id: ctx.journeyAccessContext?.rootIntentId ?? ticketRow.intentId,
      manifest_ref: manifestResult.manifest.manifestId,
      credential_ref: ctx.enterpriseAuthorization?.verifiedCredential.credentialRef ?? ticketRow.jti,
      steps: uniqueSteps, payload: projectedOperation.canonical_payload,
      predecessor_projection_id: runtimeLeaf?.projection_id,
      stream_key: streamKey,
    });
    await persistIntentAccessLineage(accessProjection, runtimeLeaf?.projection_id);
    assertIntentAccessBinding(accessProjection, projectedOperation.canonical_payload, accessProjection.steps);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "intent_access_projection_failed";
    if (toolDefinition!.classification !== "read_only") {
      const evt = await recordMigAuditEvent({ eventType: "execution", decision: "deny",
        ticketJti: ticketRow.jti, agentId: agent!.agentId, tenantId: agent!.tenantId,
        intentId: ticketRow.intentId, toolName, policyDecision: reason });
      return { decision: "deny", reason, transition_proof_id: evt.transition_proof_id };
    }
    // Reads are independently authorized, but evidence persistence is still
    // mandatory; never pretend a projection was recorded.
    const evt = await recordMigAuditEvent({ eventType: "execution", decision: "deny",
      ticketJti: ticketRow.jti, agentId: agent!.agentId, tenantId: agent!.tenantId,
      intentId: ticketRow.intentId, toolName, policyDecision: reason });
    return { decision: "deny", reason, transition_proof_id: evt.transition_proof_id };
  }
  if (toolDefinition && toolDefinition.classification !== "read_only") {
    const supplied = (input ?? {}) as Record<string, unknown>;
    const envelope = resolveMigStructuralEnvelope(supplied);
    const structural = supplied.structural_pdp as { approval_ids?: unknown; purpose?: unknown; project_or_process?: unknown; operation?: unknown; request_id?: unknown } | undefined;
    if (!envelope || typeof structural?.purpose !== "string" || typeof structural.project_or_process !== "string" ||
        !Array.isArray(structural.approval_ids) || "approvals" in (structural as object) || "operation" in (structural as object) || "request_id" in (structural as object)) {
      const evt = await recordMigAuditEvent({
        eventType: "execution", decision: "deny", ticketJti: ticketRow.jti,
        manifestId: manifestResult.manifest.manifestId, agentId: agent!.agentId,
        tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
        policyDecision: "structural_pdp_context_required",
      });
      return { decision: "deny", reason: "structural_pdp_context_required", transition_proof_id: evt.transition_proof_id };
    }
    const approvalIds = structural.approval_ids.filter((id): id is string => typeof id === "string");
    let prepared;
    try {
      prepared = await evaluateConsequentialMigOperation({
        toolName, classification: toolDefinition.classification, suppliedInput: supplied,
        control: { approval_ids: approvalIds, purpose: structural.purpose, project_or_process: structural.project_or_process },
        preparedOperation: projectedOperation, hardBoundaryAlreadyChecked: true,
      }, {
        hardBoundary: operation => {
          const boundary = evaluateMigHardBoundaries({ agent: agent!, intent: intent!, tool: toolDefinition, tenantMatches: true, operation });
          if (boundary.allowed === false) throw new Error(`MIG_HARD_BOUNDARY:${boundary.reason}`);
        },
        resolveApprovals: ids => resolveMigContextualApprovals(
          agent!.tenantId,
          ctx.enterpriseAuthorization?.verifiedCredential.principalId ?? agent!.agentId,
          ids,
        ),
        reserveActivity: operation => materializeMigActivityReality({
          tenantId: agent!.tenantId,
          principalId: ctx.enterpriseAuthorization?.verifiedCredential.principalId ?? agent!.agentId,
          credentialRef: ctx.enterpriseAuthorization?.verifiedCredential.credentialRef ?? ticketRow.jti,
          intentId: ticketRow.intentId, toolName, operation, purpose: structural.purpose,
          projectOrProcess: structural.project_or_process, sessionId: ticketRow.sessionId ?? undefined,
        }),
        evaluateCanonical: async (materialized, approvals, operation) => {
          const request: StructuralDecisionRequestV1 = {
            schema_version: "mig.structural-pdp.v1", request_id: createMigStructuralRequestId(), tenant_id: agent!.tenantId,
            principal_activity: materialized.activity, proposed_delta: materialized.delta,
            normalized_evidence: [...accessProjectionSignals(accessProjection),
              ...buildMigOperationSignals(materialized.activity, materialized.delta,
              toolDefinition.risk_zone === "critical" ? 1 : toolDefinition.risk_zone === "high" ? .8 : toolDefinition.risk_zone === "medium" ? .5 : .2)],
            business_context: materialized.activity.business_context!, approvals,
            applicable_outcome_classes: ["ALLOW", "ALLOW_WITH_CONTROL", "REQUIRE_APPROVAL", "BLOCK"],
            canonical_bripe_envelope: {
              ...envelope,
              intent_access_projection_id: accessProjection.projection_id,
              intent_access_path_fingerprint: accessProjection.path_fingerprint,
              intent_access_payload_hash: accessProjection.payload_hash,
            } as StructuralDecisionRequestV1["canonical_bripe_envelope"],
          };
          const enforcement = await evaluateMigStructuralDecision(request, {
            criticality: ticketRow.riskZone === "critical" ? "critical" : undefined,
            tolerance: ticketRow.riskZone === "high" ? 0.5 : 0.8,
            require_human_approval: manifestResult.policy.requires_human_approval,
          });
          return { request, enforcement, operation };
        },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "structural_context_resolution_failed";
      const reason = message.startsWith("MIG_HARD_BOUNDARY:") ? message.slice("MIG_HARD_BOUNDARY:".length) : "structural_context_resolution_failed";
      const evt = await recordMigAuditEvent({ eventType: "execution", decision: "deny", ticketJti: ticketRow.jti, agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName, policyDecision: reason });
      return { decision: "deny", reason, transition_proof_id: evt.transition_proof_id };
    }
    downstreamInput = prepared.canonicalPayload;
    const { request, enforcement } = prepared.enforcement;
    try {
      structuralDecisionId = enforcement.decision_id;
      structuralEnforcement = enforcement.enforcement;
      structuralLineage = { requestId: request.request_id, realityVersion: request.principal_activity.reality_version,
        deltaId: request.proposed_delta.delta_id, operationInputHash: prepared.operation.operation_input_hash,
        pathFingerprint: accessProjection?.path_fingerprint, projectionId: accessProjection?.projection_id,
        approvalId: enforcement.approval_id };
    } catch { throw new Error("MIG_STRUCTURAL_LINEAGE_INVALID"); }
    if (!isMigEnforcementDispatchable(enforcement.enforcement)) {
      // Preserve the actual canonical PDP decision on the journey denial even
      // though the operation never reaches journey admission or adapter
      // dispatch. The route seals this canonical denial against the current
      // immutable call; a later journey rule must not replace BRIPe's reason.
      await appendMigStructuralExecutionResult({
        tenantId: agent!.tenantId, principalId: agent!.agentId, decisionId: structuralDecisionId!,
        requestId: structuralLineage!.requestId, realityVersion: structuralLineage!.realityVersion,
        deltaId: structuralLineage!.deltaId, operationInputHash: structuralLineage!.operationInputHash,
        executedPayloadHash: structuralLineage!.operationInputHash,
        pathFingerprint: structuralLineage!.pathFingerprint, projectionId: structuralLineage!.projectionId,
        policyIdentity: { version: "mig-policy-v1", hash: hashPayload({ risk_zone: ticketRow.riskZone }), risk_zone: ticketRow.riskZone },
        approvalId: structuralLineage!.approvalId, outcome: "not_executed", downstreamDispatched: false,
        executionError: enforcement.reason,
      });
      if (accessProjection) await persistIntentAccessLineage(accessProjection,
        accessProjection.predecessor_projection_id, "blocked");
      const evt = await recordMigAuditEvent({
        eventType: "execution", decision: "deny", ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
        agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
        policyDecision: enforcement.enforcement, reason: enforcement.reason,
      });
      return { decision: "deny", reason: enforcement.reason, transition_proof_id: evt.transition_proof_id };
    }
  }

  if (!enterprise.authorizationManifestId) {
    const evt = await recordMigAuditEvent({
      eventType: "execution", decision: "deny", ticketJti: ticketRow.jti,
      manifestId: manifestResult.manifest.manifestId, agentId: agent!.agentId,
      tenantId: ticketRow.tenantId, intentId: ticketRow.intentId, toolName,
      policyDecision: "authorization_manifest_missing",
    });
    return { decision: "deny", reason: "authorization_manifest_missing", transition_proof_id: evt.transition_proof_id };
  }
  if (ctx.journeyAuthorization) {
    const journey = await ctx.journeyAuthorization({
      toolName, capabilityId: toolDefinition!.capability_id, semanticAction: enterpriseRequest.semanticAction,
      domainId: enterpriseRequest.domainId, resourceRef: enterpriseRequest.resourceRef,
      riskZone: toolDefinition!.risk_zone,
      structuralDecisionRef: structuralDecisionId,
      structuralAllowed: toolDefinition!.classification !== "read_only" && Boolean(structuralDecisionId),
      authorizationManifestId: enterprise.authorizationManifestId,
      structuralExecution: structuralLineage ? {
        principalId: ctx.enterpriseAuthorization?.verifiedCredential.principalId ?? agent!.agentId,
        requestId: structuralLineage.requestId, realityVersion: structuralLineage.realityVersion,
        deltaId: structuralLineage.deltaId, operationInputHash: structuralLineage.operationInputHash,
        approvalId: structuralLineage.approvalId, toolName,
      } : undefined,
    });
    if (journey.allowed === false) {
      const evt = await recordMigAuditEvent({
        eventType: "execution", decision: "deny", ticketJti: ticketRow.jti, manifestId: enterprise.authorizationManifestId,
        agentId: agent!.agentId, tenantId: ticketRow.tenantId, intentId: ticketRow.intentId, toolName,
        policyDecision: journey.reason,
      });
      return { decision: "deny", reason: journey.reason, transition_proof_id: evt.transition_proof_id,
        authorization_manifest_id: enterprise.authorizationManifestId };
    }
  }
  if (accessProjection) {
    // Only a successful journey admission can promote the proposed
    // projection into the restart-visible accumulated evidence stream.
    await persistIntentAccessLineage(accessProjection, accessProjection.predecessor_projection_id, "admitted");
  }
  if (ctx.executionStrategy === "external_decision_only") {
    const decision = mapMigExternalDecision(structuralEnforcement);
    return {
      decision: "allow",
      reason: structuralEnforcement,
      authorization_manifest_id: enterprise.authorizationManifestId,
      data: {
        decision,
        structural_decision_ref: structuralDecisionId,
        control_ref: decision === "CONSTRAIN" ? structuralDecisionId : undefined,
      },
    };
  }
  const delegationRequestId = enterpriseRequest.requestCorrelationId ?? ticketRow.jti;
  const principalId = ctx.enterpriseAuthorization?.verifiedCredential.principalId ??
    agent!.principalId ?? `mig-agent:${agent!.agentId}`;
  const { token: delegationToken } = issueMigDelegation({
    tenantId: ticketRow.tenantId,
    actorPrincipalId: ctx.enterpriseAuthorization?.verifiedCredential.actorPrincipalId ?? principalId,
    clientPrincipalId: ctx.enterpriseAuthorization?.verifiedCredential.clientPrincipalId ?? principalId,
    executorPrincipalId: ctx.enterpriseAuthorization?.verifiedCredential.executorPrincipalId ?? principalId,
    intentId: ticketRow.intentId,
    requestId: delegationRequestId,
    mcpMethod: "tools/call",
    resourceRef: enterpriseRequest.resourceRef,
    resourceVersion: enterpriseRequest.resourceVersion,
    effectiveScopes: enterprise.decision.effectivePermissions,
    tools: [{
      toolName,
      capabilityId: toolDefinition!.capability_id,
      semanticAction: enterpriseRequest.semanticAction,
      domainId: enterpriseRequest.domainId,
      resourceType: toolDefinition!.resource_types?.[0] ?? "tenant_resource",
      mutationClass: toolDefinition!.mutation_class === "none" ? "none"
        : toolDefinition!.mutation_class === "append_only" ? "append_only"
        : "governed_transition",
      canonicalService: toolDefinition!.canonical_service ?? toolDefinition!.capability_id,
      authorizationManifestId: enterprise.authorizationManifestId,
      authorizationDecisionId: enterprise.authorizationManifestId,
      policyVersion: authorizationCatalog.version,
    }],
  });

  let execResult;
  try {
    // The dispatch payload is the exact payload that was admitted.  Rebind it
    // immediately before the external call so a superseded projection or
    // mutated payload can never reuse a prior BRIPe decision.
    if (accessProjection) {
      const currentLeaf = await readCurrentRuntimeProjection(
        agent!.tenantId,
        ctx.journeyAccessContext?.rootPrincipalId ??
          (ctx.enterpriseAuthorization?.verifiedCredential.principalId ?? agent!.agentId),
        accessProjection.stream_key, true,
      );
      if (!currentLeaf || currentLeaf.projection_id !== accessProjection.projection_id ||
          currentLeaf.path_fingerprint !== accessProjection.path_fingerprint) {
        throw new Error("MIG_INTENT_ACCESS_SUPERSEDED_OR_STALE");
      }
      assertIntentAccessBinding(accessProjection, downstreamInput, accessProjection.steps);
      if (structuralLineage && structuralLineage.operationInputHash !== projectedOperation.operation_input_hash) {
        throw new Error("MIG_INTENT_ACCESS_OPERATION_BINDING_INVALID");
      }
    }
    execResult = await executeGatedTool(manifestResult.manifest, toolName, downstreamInput, {
      ...ctx,
      delegationToken,
      delegationExpectation: {
        requestId: delegationRequestId,
        mcpMethod: "tools/call",
        resourceRef: enterpriseRequest.resourceRef,
        resourceVersion: enterpriseRequest.resourceVersion,
        toolName,
      },
    }, ctx.downstreamAdapter);
  } catch (error) {
    if (accessProjection) await persistIntentAccessLineage(accessProjection,
      accessProjection.predecessor_projection_id, "failed");
    if (structuralDecisionId) {
      await appendMigStructuralExecutionResult({ tenantId: agent!.tenantId, principalId: agent!.agentId, decisionId: structuralDecisionId,
        requestId: structuralLineage!.requestId, realityVersion: structuralLineage!.realityVersion, deltaId: structuralLineage!.deltaId,
        operationInputHash: structuralLineage!.operationInputHash, executedPayloadHash: structuralLineage!.operationInputHash,
        pathFingerprint: structuralLineage!.pathFingerprint, projectionId: structuralLineage!.projectionId,
        policyIdentity: { version: "mig-policy-v1", hash: hashPayload({ risk_zone: ticketRow.riskZone }), risk_zone: ticketRow.riskZone }, approvalId: structuralLineage!.approvalId, outcome: "failed",
        executionError: error instanceof Error ? error.message : "unknown_execution_error" });
    }
    const evt = await recordMigAuditEvent({
      eventType: "execution", decision: "deny", ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
      agentId: agent!.agentId, tenantId: agent!.tenantId, intentId: ticketRow.intentId, toolName,
      policyDecision: "material_execution_failed", reason: error instanceof Error ? error.message : "unknown_execution_error",
    });
    return { decision: "deny", reason: "material_execution_failed", transition_proof_id: evt.transition_proof_id };
  }

  if (execResult.allowed === false) {
    if (accessProjection) await persistIntentAccessLineage(accessProjection,
      accessProjection.predecessor_projection_id, "failed");
    if (structuralDecisionId) {
      await appendMigStructuralExecutionResult({ tenantId: agent!.tenantId, principalId: agent!.agentId, decisionId: structuralDecisionId,
        requestId: structuralLineage!.requestId, realityVersion: structuralLineage!.realityVersion, deltaId: structuralLineage!.deltaId,
        operationInputHash: structuralLineage!.operationInputHash, executedPayloadHash: structuralLineage!.operationInputHash,
        pathFingerprint: structuralLineage!.pathFingerprint, projectionId: structuralLineage!.projectionId,
        policyIdentity: { version: "mig-policy-v1", hash: hashPayload({ risk_zone: ticketRow.riskZone }), risk_zone: ticketRow.riskZone }, approvalId: structuralLineage!.approvalId, outcome: "failed",
        executionError: execResult.reason });
    }
    const evt = await recordMigAuditEvent({
      eventType: "execution", decision: "deny",
      ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
      agentId: agent!.agentId, tenantId: agent!.tenantId, sessionId: ticketRow.sessionId,
      intentId: ticketRow.intentId, riskZone: ticketRow.riskZone as MigRiskZone, toolName,
      inputHash: undefined,
      policyDecision: execResult.reason ?? "execution_denied",
    });

    // A locked/active agent reaching outside its approved draft-profile
    // scope is drift, not ordinary policy noise — record it on the
    // dedicated drift surface so an admin has a resolvable queue for it.
    if (execResult.reason === "tool_not_in_authorized_manifest") {
      await recordDriftEvent({
        agent: agent!,
        driftType: "unauthorized_tool_call",
        toolName,
        detail: `Agent attempted tool "${toolName}" which is outside its approved intent scope.`,
        severity: "warning",
      });
    }

    await captureDiscoveryEvent({
      agent: agent!, sessionId: ticketRow.sessionId, requestKind: "execute", toolName,
      domainHints: (intent!.domainScope as string[] | undefined) ?? [],
      wasDenied: true, denialReason: execResult.reason,
    });

    return { decision: "deny", reason: execResult.reason, transition_proof_id: evt.transition_proof_id };
  }

  if (structuralDecisionId) {
    await appendMigStructuralExecutionResult({ tenantId: agent!.tenantId, principalId: agent!.agentId, decisionId: structuralDecisionId,
      requestId: structuralLineage!.requestId, realityVersion: structuralLineage!.realityVersion, deltaId: structuralLineage!.deltaId,
      operationInputHash: structuralLineage!.operationInputHash, executedPayloadHash: structuralLineage!.operationInputHash,
      pathFingerprint: structuralLineage!.pathFingerprint, projectionId: structuralLineage!.projectionId,
      policyIdentity: { version: "mig-policy-v1", hash: hashPayload({ risk_zone: ticketRow.riskZone }), risk_zone: ticketRow.riskZone }, approvalId: structuralLineage!.approvalId,
      outcome: "succeeded", resultHash: hashPayload(execResult.output) });
  }
  if (accessProjection) await persistIntentAccessLineage(accessProjection,
    accessProjection.predecessor_projection_id, "succeeded");

  await recordMigAuditEvent({
    eventType: "execution", decision: "allow",
    ticketJti: ticketRow.jti, manifestId: manifestResult.manifest.manifestId,
    agentId: agent!.agentId, tenantId: agent!.tenantId, sessionId: ticketRow.sessionId,
    intentId: ticketRow.intentId, riskZone: ticketRow.riskZone as MigRiskZone, toolName,
    policyDecision: "execution_allowed",
  });

  await captureDiscoveryEvent({
    agent: agent!,
    sessionId: ticketRow.sessionId,
    requestKind: "execute",
    toolName,
    domainHints: (intent!.domainScope as string[] | undefined) ?? [],
  });

  return {
    decision: "allow", reason: "execution_allowed", data: execResult.output,
    authorization_manifest_id: enterprise.authorizationManifestId,
  };
}

export function createMigStructuralRequestId(): string {
  return `mig_req_${randomUUID()}`;
}
export async function revokeTicket(jti: string, reason: string): Promise<void> {
  await storage.revokeMigTicket(jti, reason);
  await recordMigAuditEvent({
    eventType: "ticket_revoked", decision: "info", ticketJti: jti, policyDecision: reason,
  });
}
