/**
 * server/mig/mig-policy-graph.ts
 *
 * Pure policy resolution: intersects what an agent is allowed to do with
 * what a specific declared intent grants, and derives the effective set of
 * capability ids / tool names a ticket may exercise. No I/O, no adapter
 * knowledge — this is the deterministic core of MIG's authorization logic.
 */

import type { MigRemoteAgent, MigIntentDefinition } from "@shared/schema";
import type { MigPolicyResolution, MigRiskZone } from "./mig-types";

const RISK_ORDER: Record<MigRiskZone, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const CLASSIFICATION_ORDER: Record<string, number> = { read_only: 0, execution: 1, admin: 2 };

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/**
 * Resolves the effective policy for a (agent, intent) pair.
 * Denial reasons are always populated so audit/UI can explain why a
 * capability or tool was suppressed rather than silently dropping it.
 */
export function resolvePolicy(agent: MigRemoteAgent, intent: MigIntentDefinition): MigPolicyResolution {
  const denial_reasons: Record<string, string> = {};

  const agentIntents = asStringArray(agent.allowedIntents);
  const agentRiskZones = asStringArray(agent.allowedRiskZones) as MigRiskZone[];
  const agentDomains = asStringArray(agent.allowedDomains);

  if (agentIntents.length > 0 && !agentIntents.includes(intent.intentId)) {
    return {
      allowed_tool_names: [],
      denied_tool_names: asStringArray(intent.allowedToolNames),
      allowed_capability_ids: [],
      suppressed_capability_ids: asStringArray(intent.allowedCapabilityIds),
      risk_zone: intent.riskZone as MigRiskZone,
      requires_human_approval: true,
      denial_reasons: { "*": "agent_not_scoped_to_intent" },
    };
  }

  const riskAllowed =
    agentRiskZones.length === 0 ||
    agentRiskZones.some(z => RISK_ORDER[z] >= RISK_ORDER[intent.riskZone as MigRiskZone]);

  if (!riskAllowed) {
    return {
      allowed_tool_names: [],
      denied_tool_names: asStringArray(intent.allowedToolNames),
      allowed_capability_ids: [],
      suppressed_capability_ids: asStringArray(intent.allowedCapabilityIds),
      risk_zone: intent.riskZone as MigRiskZone,
      requires_human_approval: true,
      denial_reasons: { "*": "risk_zone_exceeds_agent_authorization" },
    };
  }

  const domainScope = asStringArray(intent.domainScope);
  if (agentDomains.length > 0 && domainScope.length > 0) {
    const overlap = domainScope.some(d => agentDomains.includes(d));
    if (!overlap) {
      return {
        allowed_tool_names: [],
        denied_tool_names: asStringArray(intent.allowedToolNames),
        allowed_capability_ids: [],
        suppressed_capability_ids: asStringArray(intent.allowedCapabilityIds),
        risk_zone: intent.riskZone as MigRiskZone,
        requires_human_approval: true,
        denial_reasons: { "*": "domain_scope_not_authorized_for_agent" },
      };
    }
  }

  const maxClass = CLASSIFICATION_ORDER[agent.maxCapabilityClassification] ?? 0;

  const allowedToolNames = asStringArray(intent.allowedToolNames).filter(
    name => !asStringArray(intent.deniedToolNames).includes(name),
  );
  const allowedCapabilityIds = asStringArray(intent.allowedCapabilityIds).filter(
    id => !asStringArray(intent.deniedCapabilityIds).includes(id),
  );

  for (const name of asStringArray(intent.deniedToolNames)) {
    denial_reasons[name] = "explicitly_denied_by_intent";
  }
  for (const id of asStringArray(intent.deniedCapabilityIds)) {
    denial_reasons[id] = "explicitly_denied_by_intent";
  }

  return {
    allowed_tool_names: allowedToolNames,
    denied_tool_names: asStringArray(intent.deniedToolNames),
    allowed_capability_ids: allowedCapabilityIds,
    suppressed_capability_ids: [],
    risk_zone: intent.riskZone as MigRiskZone,
    requires_human_approval: intent.requiresHumanApproval || agent.requiresHumanApproval,
    denial_reasons,
  };
}

/** Caps a candidate tool classification against the agent's max authorized classification. */
export function classificationAllowedForAgent(
  agent: MigRemoteAgent,
  classification: "read_only" | "execution" | "admin",
): boolean {
  const maxClass = CLASSIFICATION_ORDER[agent.maxCapabilityClassification] ?? 0;
  return CLASSIFICATION_ORDER[classification] <= maxClass;
}

// ─────────────────────────────────────────────────────────────────────────────
// § 2  Constraint-Aware DAP tool risk tiers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * MIG risk tier overrides for Constraint-Aware DAP tools.
 *
 * These tiers supersede the heuristic riskZoneForClassification() mapping
 * in mig-bripe-adapter.ts for these specific tools.
 *
 * Tier semantics:
 *   low      — safe read; no mutation risk
 *   medium   — analytical execution; reads + evaluates, no system change
 *   high     — structural execution; produces a governed decision record
 *   critical — irreversible or system-changing action; requires explicit grant
 */
export const CADAP_TOOL_RISK_TIERS: Readonly<Record<string, MigRiskZone>> = {
  list_workload_profiles:          "low",
  get_workload_profile:            "low",
  review_workload_configuration:   "low",
  evaluate_exposure_context:       "medium",
  evaluate_workload:               "medium",
  propose_feasible_fixes:          "medium",
  verify_fix:                      "medium",
  run_constraint_aware_dap:        "high",
  execute_approved_fix:            "critical",
};

/**
 * Tools that require an explicit critical-permission grant.
 * These tools perform irreversible or system-changing operations and may
 * not execute with standard high-risk authorization alone.
 */
export const CRITICAL_TIER_TOOL_NAMES: readonly string[] = [
  "execute_approved_fix",
];

/**
 * Resolve the MIG risk tier for a Constraint-Aware DAP tool.
 * Returns null for tools not in the CADAP registry.
 */
export function resolveConstraintAwareToolTier(toolName: string): MigRiskZone | null {
  return CADAP_TOOL_RISK_TIERS[toolName] ?? null;
}

/**
 * Returns true when the tool requires an explicit critical-permission grant
 * beyond standard high-risk authorization.
 */
export function requiresCriticalPermission(toolName: string): boolean {
  return CRITICAL_TIER_TOOL_NAMES.includes(toolName);
}

/**
 * Authorize a Constraint-Aware DAP tool invocation.
 *
 * Rules:
 *   1. Unknown tool → deny (unknown_tool).
 *   2. Critical-tier tool without explicit grant → deny (critical_permission_required).
 *   3. Otherwise → allow.
 *
 * This function is deterministic and pure — it never reads from the database
 * or performs any I/O. The caller is responsible for resolving the grant flag.
 */
export function authorizeConstraintAwareTool(
  toolName: string,
  agentHasCriticalGrant: boolean,
): { decision: "allow" | "deny"; reason?: string } {
  const tier = resolveConstraintAwareToolTier(toolName);

  if (!tier) {
    return { decision: "deny", reason: "unknown_tool" };
  }

  if (requiresCriticalPermission(toolName) && !agentHasCriticalGrant) {
    return {
      decision: "deny",
      reason: "critical_permission_required: execute_approved_fix requires an explicit critical-permission grant from a MIG admin. Standard high-risk authorization is insufficient.",
    };
  }

  return { decision: "allow" };
}
