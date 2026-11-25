/**
 * server/mig/mig-discovery.ts
 *
 * Discovery Mode & Intent Approval — reuses the existing MIG substrate
 * (mig_remote_agents.lifecycleState, mig_intent_libraries/definitions,
 * mig_audit_log) and adds exactly three new tables for genuinely new
 * concepts:
 *
 *   mig_discovery_events        — per-request capture while an agent's
 *                                 lifecycleState === "discovery"
 *   mig_draft_intent_profiles   — auto-synthesized proposal aggregated from
 *                                 those events, reviewed by an admin
 *   mig_drift_events            — first-class, resolvable record of a
 *                                 locked/active agent trying something
 *                                 outside its approved scope
 *
 * Lifecycle: discovery -> reviewing -> locked -> active
 *   discovery  — agent is unscoped; every discover/execute request is
 *                captured, never blocked purely for being unscoped.
 *   reviewing  — a draft profile has been synthesized and is awaiting an
 *                admin decision (informational state; still captures).
 *   locked     — draft approved; agent has been assigned exactly the
 *                approved intent and MUST NOT be issued tickets for
 *                anything outside it. Any denied execution against a
 *                locked/active agent is recorded as a drift event.
 *   active     — the pre-existing default state for agents that never went
 *                through discovery (fully manually scoped, as before).
 *
 * This module contains NO BRIPe/MCP-specific tool knowledge — it only
 * aggregates whatever tool/capability names discovery events observed.
 */

import { storage } from "../storage";
import { getMigAgent, updateMigAgentScope, setMigAgentStatus } from "./mig-agent-registry";
import { createIntentLibrary, createIntentDefinition } from "./mig-intent-library";
import type { MigAdapterToolEntry } from "./mig-types";
import type {
  MigRemoteAgent,
  MigDiscoveryEvent,
  MigDraftIntentProfile,
  MigDriftEvent,
} from "@shared/schema";
import {
  deriveCanonicalCapabilityBinding,
  type BindingMetadata,
} from "./mig-canonical-capability-binding";
import type { CanonicalMCPKnowledgeBinding } from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";
import { canonicalKnowledgeAuthorityService } from "../standalone/knowledge-owner";
import type { CanonicalKnowledgeAuthorityRepository } from "../standalone/knowledge-owner";

const DISCOVERY_INTENT_LIBRARY_ID = "mig-discovery-derived";

/**
 * Build governed MCP knowledge candidates from the advertised schema and
 * server-owned metadata. This is intentionally separate from intent synthesis:
 * discovery may observe a capability, but it cannot confirm or grant it.
 */
export function deriveDiscoveryKnowledgeBindings(input: {
  tools: readonly MigAdapterToolEntry[];
  metadata: BindingMetadata;
}): CanonicalMCPKnowledgeBinding[] {
  return input.tools
    .map(tool => deriveCanonicalCapabilityBinding(tool, input.metadata))
    .filter((binding): binding is CanonicalMCPKnowledgeBinding => Boolean(binding));
}

/** Persist discovery output through the server-owned CB MCP binding API. */
export async function persistDiscoveryKnowledgeBindings(
  input: { tools: readonly MigAdapterToolEntry[]; metadata: BindingMetadata },
  repository?: CanonicalKnowledgeAuthorityRepository,
): Promise<CanonicalMCPKnowledgeBinding[]> {
  const candidates = deriveDiscoveryKnowledgeBindings(input);
  const persisted: CanonicalMCPKnowledgeBinding[] = [];
  for (const candidate of candidates) {
    persisted.push(await canonicalKnowledgeAuthorityService.bindMcpCapability(candidate, repository));
  }
  return persisted;
}

function genId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

export async function startDiscoveryMode(agentId: string): Promise<MigRemoteAgent | undefined> {
  return updateMigAgentScope(agentId, { lifecycleState: "discovery" } as Partial<import("@shared/schema").InsertMigRemoteAgent>);
}

/**
 * Sends an agent that is under review (or already locked, if an admin wants
 * to re-observe it) back into discovery so more behavior can be captured
 * before a decision is made. Does not touch any existing draft profile —
 * the admin can generate a fresh one once satisfied.
 */
export async function requestMoreDiscovery(agentId: string): Promise<MigRemoteAgent | undefined> {
  return updateMigAgentScope(agentId, { lifecycleState: "discovery" } as Partial<import("@shared/schema").InsertMigRemoteAgent>);
}

/** Admin-only escape hatch to let a specific discovery-mode agent exercise higher-risk tools while still unscoped. */
export async function setDiscoveryException(agentId: string, granted: boolean): Promise<MigRemoteAgent | undefined> {
  return updateMigAgentScope(agentId, { discoveryExceptionGranted: granted } as Partial<import("@shared/schema").InsertMigRemoteAgent>);
}

/** Admin action to immediately suspend an agent regardless of lifecycle state (discovery, reviewing, locked, or active). */
export async function suspendAgent(agentId: string): Promise<MigRemoteAgent | undefined> {
  return setMigAgentStatus(agentId, "suspended");
}

export interface DiscoverySafetyCheck {
  safe: boolean;
  reason?: string;
}

/**
 * Safe-discovery rule (task-1800 step 2): while an agent is in discovery
 * mode it is sandbox/non-destructive by default. Any tool classified
 * "admin" (privilege-escalation-shaped) or scoped to "high"/"critical" risk
 * is blocked UNLESS an admin has explicitly granted a discovery exception
 * for this agent. This never affects reviewing/locked/active agents — those
 * are governed purely by their approved intent's policy.
 */
export function checkDiscoverySafety(agent: MigRemoteAgent, tool: MigAdapterToolEntry): DiscoverySafetyCheck {
  if (agent.lifecycleState !== "discovery") return { safe: true };
  if (agent.discoveryExceptionGranted) return { safe: true };

  const isHighRisk = tool.risk_zone === "high" || tool.risk_zone === "critical";
  const isPrivileged = tool.classification === "admin";
  if (isHighRisk || isPrivileged) {
    return {
      safe: false,
      reason: `discovery_sandbox_blocks_${isPrivileged ? "privileged" : "high_risk"}_tool:${tool.tool_name}`,
    };
  }
  return { safe: true };
}

export interface CaptureDiscoveryEventInput {
  agent: MigRemoteAgent;
  sessionId?: string;
  requestKind: "discover" | "execute";
  toolName?: string;
  capabilityId?: string;
  domainHints?: string[];
  inputShapeKeys?: string[];
  /** Set when this attempt was blocked/denied rather than allowed, so synthesizeDraftProfile's policyFindings can surface it to the reviewer. */
  wasDenied?: boolean;
  denialReason?: string;
}

/** No-op unless the agent is currently in discovery mode. Never throws/blocks. Captures both allowed AND denied/blocked attempts, so the admin-facing draft profile reflects everything the agent actually tried. */
export async function captureDiscoveryEvent(input: CaptureDiscoveryEventInput): Promise<MigDiscoveryEvent | undefined> {
  if (input.agent.lifecycleState !== "discovery") return undefined;
  return storage.recordMigDiscoveryEvent({
    eventId: genId("dsc"),
    agentId: input.agent.agentId,
    tenantId: input.agent.tenantId,
    sessionId: input.sessionId,
    requestKind: input.requestKind,
    toolName: input.toolName,
    capabilityId: input.capabilityId,
    domainHints: input.domainHints ?? [],
    inputShapeKeys: input.inputShapeKeys ?? [],
    wasDenied: input.wasDenied ?? false,
    denialReason: input.denialReason,
  });
}

export async function listDiscoveryEvents(agentId: string, limit?: number): Promise<MigDiscoveryEvent[]> {
  return storage.listMigDiscoveryEvents(agentId, limit);
}

/**
 * Deterministic 0-100 confidence heuristic: more total events and a smaller
 * distinct-tool "surface" (i.e. the agent keeps calling the same handful of
 * tools rather than a different one every time) both raise confidence that
 * the proposed scope reflects the agent's real, stable behavior rather than
 * a thin/noisy sample. No ML — purely a function of the observed counts.
 */
function computeConfidence(eventCount: number, distinctToolCount: number): number {
  if (eventCount === 0) return 0;
  const volumeScore = Math.min(1, eventCount / 20); // saturates once we've seen 20+ events
  const repetitionScore = Math.min(1, eventCount / Math.max(1, distinctToolCount * 3)); // rewards repeat calls per tool
  return Math.round(Math.min(1, (volumeScore + repetitionScore) / 2) * 100);
}

const EXECUTION_TOOL_INDICATORS = new Set([
  "run_bripe_decision", "start_autopilot_objective",
]);

const DISCOVERY_TOOL_INDICATORS = new Set([
  "list_domains", "get_domain_package", "list_capabilities", "search_capabilities",
  "get_capability_contract", "list_bripe_layers", "get_required_layers",
  "list_doctrines", "get_doctrine", "get_doctrines_by_layer", "list_active_odps",
  "get_odp_registry_status", "validate_domain_package", "list_adam_phases",
  "get_governance_contract", "check_odp_activation", "validate_decision_manifest",
  "retrieve_adaptation_memories",
]);

/**
 * Derives a plain-English business name for a draft intent from the set of
 * tools observed during discovery. Never exposes agent IDs or event counts
 * as the primary label.
 */
function deriveDraftIntentName(toolNames: Set<string>): string {
  const hasExecution = Array.from(toolNames).some(t => EXECUTION_TOOL_INDICATORS.has(t));
  const hasDiscovery = Array.from(toolNames).some(t => DISCOVERY_TOOL_INDICATORS.has(t));

  if (hasExecution && hasDiscovery) return "Structural Intelligence Access";
  if (hasExecution) return "Structural Risk Analysis";
  if (hasDiscovery) {
    const domainTools = ["list_domains", "get_domain_package", "list_active_odps", "get_odp_registry_status"];
    const onlyDomainTools = Array.from(toolNames).every(t => domainTools.includes(t));
    if (onlyDomainTools) return "Domain Discovery";
    return "Intelligence Read Access";
  }
  return "Intelligence Read Access";
}

/**
 * Aggregates every discovery event captured for an agent into a single
 * pending draft profile. Purely observational — proposes the union of what
 * was seen, never invents scope. Moves the agent to "reviewing" so it's
 * clear a decision is pending without changing what it's allowed to do.
 * Also surfaces policy findings (denied attempts logged for this agent
 * while it was in discovery) so the reviewing admin can see risky/blocked
 * behavior alongside the proposed allow-list, never just the happy path.
 */
export async function synthesizeDraftProfile(agentId: string): Promise<MigDraftIntentProfile & { workload_profile_recommendation?: WorkloadProfileRecommendation }> {
  const agent = await getMigAgent(agentId);
  if (!agent) throw new Error("agent_not_found");

  const events = await storage.listMigDiscoveryEvents(agentId, 5000);
  const toolNames = new Set<string>();
  const capabilityIds = new Set<string>();
  const domainScope = new Set<string>();

  for (const e of events) {
    if (e.toolName) toolNames.add(e.toolName);
    if (e.capabilityId) capabilityIds.add(e.capabilityId);
    const hints = Array.isArray(e.domainHints) ? (e.domainHints as string[]) : [];
    for (const h of hints) domainScope.add(h);
  }

  const auditEvents = await storage.listMigAuditEvents({ agentId, limit: 5000 });
  const deniedDuringDiscovery = auditEvents.filter(a => a.decision === "deny");
  const policyFindings = deniedDuringDiscovery.slice(0, 25).map(a => ({
    event_type: a.eventType,
    tool_name: a.toolName ?? undefined,
    reason: a.reason ?? a.policyDecision,
    at: a.createdAt,
  }));

  const confidence = computeConfidence(events.length, toolNames.size);

  const proposedName = deriveDraftIntentName(toolNames);
  const agentLabel = agent.displayName || agent.agentId;
  const proposedDescription = `Auto-synthesized access scope for ${agentLabel} based on ${events.length} observed discovery event(s).`;

  // ── Workload profile recommendation — best-effort, never blocks synthesis ─
  // Derive the primary technology hint from the collected domain hints and
  // attempt to surface a matching WorkloadProfile for the reviewing admin.
  const domainHintsList = Array.from(domainScope);
  const workloadRec = await recommendWorkloadProfile(
    agentId,
    undefined,
    "Production",
    domainHintsList,
  ).catch(() => undefined);

  const workloadSuffix = workloadRec
    ? ` Workload profile matched: "${workloadRec.profile_name}" (criticality: ${workloadRec.criticality}, internet-facing: ${workloadRec.internet_exposure}).`
    : "";

  const draft = await storage.createMigDraftProfile({
    draftId: genId("draft"),
    agentId: agent.agentId,
    tenantId: agent.tenantId,
    proposedName,
    proposedDescription,
    proposedAllowedToolNames: Array.from(toolNames),
    proposedCapabilityIds: Array.from(capabilityIds),
    proposedDomainScope: domainScope.size > 0 ? Array.from(domainScope) : ["*"],
    proposedRiskZone: "low",
    observedEventCount: events.length,
    confidence,
    policyFindings,
    evidenceSummary: `${events.length} discovery event(s) across ${toolNames.size} distinct tool(s); ${deniedDuringDiscovery.length} denied attempt(s) observed.${workloadSuffix}`,
    status: "pending",
  });

  await updateMigAgentScope(agentId, { lifecycleState: "reviewing" } as Partial<import("@shared/schema").InsertMigRemoteAgent>);
  // Attach the workload profile recommendation as a typed first-class field.
  // The DB record (MigDraftIntentProfile) carries the summary text in evidenceSummary;
  // callers that need the structured recommendation (admin UI, API responses,
  // downstream automation) consume this typed field rather than parsing the text.
  return Object.assign(draft, { workload_profile_recommendation: workloadRec ?? undefined });
}

export async function getDraftProfile(draftId: string): Promise<MigDraftIntentProfile | undefined> {
  return storage.getMigDraftProfile(draftId);
}

export async function listDraftProfiles(agentId?: string): Promise<MigDraftIntentProfile[]> {
  return storage.listMigDraftProfiles(agentId);
}

/**
 * The most recently approved draft profile for an agent, if any — the
 * baseline that behavioral drift checks (mig-drift-detector.ts) compare a
 * locked/active agent's live requests against. Returns undefined for
 * agents that have never been through discovery/approval (nothing to
 * compare against, so those checks are simply skipped).
 */
export async function getLatestApprovedProfile(agentId: string): Promise<MigDraftIntentProfile | undefined> {
  const profiles = await storage.listMigDraftProfiles(agentId);
  const approved = profiles.filter(p => p.status === "approved");
  if (approved.length === 0) return undefined;
  return approved.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0];
}

export interface ApproveDraftInput {
  draftId: string;
  reviewedBy: string;
  reviewNotes?: string;
  /** Optional admin edits applied on top of the synthesized proposal before it becomes real scope. */
  edits?: {
    allowedToolNames?: string[];
    capabilityIds?: string[];
    domainScope?: string[];
    riskZone?: string;
    name?: string;
    description?: string;
  };
}

/**
 * Turns an approved draft into a real mig_intent_definition (reusing the
 * existing intent library machinery), assigns it as the agent's sole
 * allowed intent, and locks the agent to it. This is the ONLY path by which
 * a discovery-mode agent gains a durable, enforced scope.
 */
export async function approveDraftProfile(input: ApproveDraftInput): Promise<{ draft: MigDraftIntentProfile; intentId: string }> {
  const draft = await storage.getMigDraftProfile(input.draftId);
  if (!draft) throw new Error("draft_not_found");
  if (draft.status !== "pending") throw new Error("draft_already_reviewed");

  await createIntentLibrary({
    libraryId: DISCOVERY_INTENT_LIBRARY_ID,
    name: "Discovery-Derived Intents",
    version: "1.0.0",
    status: "published",
  });

  const allowedToolNames = input.edits?.allowedToolNames ?? (draft.proposedAllowedToolNames as string[]);
  const allowedCapabilityIds = input.edits?.capabilityIds ?? (draft.proposedCapabilityIds as string[]);
  const rawDomainScope = input.edits?.domainScope ?? (draft.proposedDomainScope as string[]);
  const domainScope = rawDomainScope.length > 0 ? rawDomainScope : ["*"];
  const riskZone = input.edits?.riskZone ?? draft.proposedRiskZone;
  const intentId = genId("intent-derived");

  await createIntentDefinition({
    intentId,
    libraryId: DISCOVERY_INTENT_LIBRARY_ID,
    name: input.edits?.name ?? draft.proposedName,
    description: input.edits?.description ?? draft.proposedDescription,
    allowedCapabilityIds,
    deniedCapabilityIds: [],
    allowedToolNames,
    deniedToolNames: [],
    domainScope,
    packageScope: ["*"],
    riskZone: (riskZone as import("@shared/schema").MigRiskZone) ?? "low",
    payloadClasses: [],
    requiresHumanApproval: false,
    requiresEvidence: false,
    requiresManifest: true,
    status: "published",
  });

  await updateMigAgentScope(draft.agentId, {
    allowedIntents: [intentId],
    lifecycleState: "locked",
  } as Partial<import("@shared/schema").InsertMigRemoteAgent>);

  // Behavioral drift (mig-drift-detector.ts / authorizeExecution) compares a
  // locked agent's live requests against this draft's proposed* fields as
  // the baseline. If an admin edited the proposal at approval time, the
  // baseline MUST reflect the final approved values, not the original
  // pre-edit synthesis — otherwise the agent would immediately "drift" away
  // from a scope it was never actually locked to (or worse, stay unflagged
  // for exercising something the admin never approved).
  const updatedDraft = await storage.updateMigDraftProfile(input.draftId, {
    status: "approved",
    resultingIntentId: intentId,
    reviewedBy: input.reviewedBy,
    reviewNotes: input.reviewNotes,
    reviewedAt: new Date(),
    proposedName: input.edits?.name ?? draft.proposedName,
    proposedDescription: input.edits?.description ?? draft.proposedDescription,
    proposedAllowedToolNames: allowedToolNames,
    proposedCapabilityIds: allowedCapabilityIds,
    proposedDomainScope: domainScope,
    proposedRiskZone: riskZone,
  });

  return { draft: updatedDraft!, intentId };
}

export async function rejectDraftProfile(draftId: string, reviewedBy: string, reviewNotes?: string): Promise<MigDraftIntentProfile | undefined> {
  const draft = await storage.getMigDraftProfile(draftId);
  if (!draft) throw new Error("draft_not_found");
  const updated = await storage.updateMigDraftProfile(draftId, {
    status: "rejected",
    reviewedBy,
    reviewNotes,
    reviewedAt: new Date(),
  });
  // Send the agent back to discovery so a new profile can be synthesized after further observation.
  await updateMigAgentScope(draft.agentId, { lifecycleState: "discovery" } as Partial<import("@shared/schema").InsertMigRemoteAgent>);
  return updated;
}

export interface RecordDriftEventInput {
  agent: MigRemoteAgent;
  driftType: string;
  toolName?: string;
  detail: string;
  severity?: "info" | "warning" | "critical";
}

/** Only meaningful once an agent is locked/active — a discovery-mode agent has no scope to drift from. */
export async function recordDriftEvent(input: RecordDriftEventInput): Promise<MigDriftEvent | undefined> {
  if (input.agent.lifecycleState !== "locked" && input.agent.lifecycleState !== "active") return undefined;
  return storage.recordMigDriftEvent({
    eventId: genId("drift"),
    agentId: input.agent.agentId,
    tenantId: input.agent.tenantId,
    driftType: input.driftType,
    toolName: input.toolName,
    detail: input.detail,
    severity: input.severity ?? "warning",
  });
}

export async function listDriftEvents(filters?: { tenantId?: string; agentId?: string; resolved?: boolean }): Promise<MigDriftEvent[]> {
  return storage.listMigDriftEvents(filters);
}

export async function resolveDriftEvent(eventId: string, resolvedBy: string): Promise<MigDriftEvent | undefined> {
  return storage.resolveMigDriftEvent(eventId, resolvedBy);
}

// ── Workload Profile integration ─────────────────────────────────────────────
// After technology identification in discovery, recommend a matching
// WorkloadProfile so the admin can see the operational intent baseline.

export interface WorkloadProfileRecommendation {
  technology: string;
  deployment_type: string;
  profile_name: string;
  criticality: string;
  internet_exposure: boolean;
  business_purpose: string;
  recommended: boolean;
  reason: string;
}

/**
 * Best-effort workload profile recommendation based on technology hints
 * observed during discovery events. Never throws — returns undefined when
 * no profile can be matched.
 *
 * Resolution order:
 *   1. technologyHint (explicit) × deploymentTypeHint
 *   2. incomingDomainHints scanned against the registry (first match wins)
 *   3. DB-fetched domain hints from this agent's discovery events (first match wins)
 *   4. Returns undefined — never falls back to an arbitrary technology name
 */
export async function recommendWorkloadProfile(
  agentId: string,
  technologyHint?: string,
  deploymentTypeHint?: string,
  incomingDomainHints?: string[],
): Promise<WorkloadProfileRecommendation | undefined> {
  try {
    const { workloadProfileRegistry } = await import("@shared/workload-profiles/registry");
    await import("@shared/workload-profiles/index");

    const deploymentType = (deploymentTypeHint ?? "Production") as import("../../shared/protocol/shared/workload-profiles/contract").WorkloadDeploymentType;

    // Step 1: explicit technology hint
    if (technologyHint) {
      if (!workloadProfileRegistry.has(technologyHint, deploymentType)) return undefined;
      const profile = workloadProfileRegistry.resolve(technologyHint, deploymentType);
      return {
        technology: profile.technology,
        deployment_type: profile.deployment_type,
        profile_name: profile.profile_name,
        criticality: profile.criticality,
        internet_exposure: profile.internet_exposure,
        business_purpose: profile.business_purpose,
        recommended: true,
        reason: `Explicit technology hint matched: technology="${technologyHint}", deploymentType="${deploymentType}"`,
      };
    }

    // Step 2: scan incomingDomainHints against the registry (first match wins)
    const hintsToScan = [...(incomingDomainHints ?? [])];

    // Step 3: augment with DB-fetched hints if caller did not provide any
    if (hintsToScan.length === 0) {
      const events = await storage.listMigDiscoveryEvents(agentId, 100);
      for (const e of events) {
        const h = Array.isArray(e.domainHints) ? (e.domainHints as string[]) : [];
        for (const hint of h) hintsToScan.push(hint);
      }
    }

    // No hints available at all — return undefined (never invent a technology)
    if (hintsToScan.length === 0) return undefined;

    for (const hint of hintsToScan) {
      if (workloadProfileRegistry.has(hint, deploymentType)) {
        const profile = workloadProfileRegistry.resolve(hint, deploymentType);
        return {
          technology: profile.technology,
          deployment_type: profile.deployment_type,
          profile_name: profile.profile_name,
          criticality: profile.criticality,
          internet_exposure: profile.internet_exposure,
          business_purpose: profile.business_purpose,
          recommended: true,
          reason: `Domain hint matched registered workload profile: hint="${hint}", deploymentType="${deploymentType}"`,
        };
      }
    }

    // No hint matched the registry
    return undefined;
  } catch {
    return undefined;
  }
}
