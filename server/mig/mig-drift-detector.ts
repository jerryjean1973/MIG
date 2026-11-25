/**
 * server/mig/mig-drift-detector.ts
 *
 * Detects when the world has changed underneath an already-issued
 * ticket/manifest: the agent was suspended/revoked, the intent definition
 * was deprecated or edited, or the intent's policy inputs no longer match
 * what was captured at manifest build time. Drift is checked on every
 * execution request — MIG never trusts a manifest purely because it has
 * not expired yet.
 */

import type { MigRemoteAgent, MigIntentDefinition, MigCapabilityManifest } from "@shared/schema";
import { resolvePolicy } from "./mig-policy-graph";
import { hashPayload } from "./mig-audit";
import type { MigRiskZone } from "./mig-types";

export interface DriftCheckResult {
  drifted: boolean;
  reason?: string;
}

export function checkAgentDrift(agent: MigRemoteAgent | undefined): DriftCheckResult {
  if (!agent) return { drifted: true, reason: "agent_no_longer_exists" };
  if (agent.status !== "active") return { drifted: true, reason: `agent_status_${agent.status}` };
  return { drifted: false };
}

export function checkIntentDrift(intent: MigIntentDefinition | undefined): DriftCheckResult {
  if (!intent) return { drifted: true, reason: "intent_no_longer_exists" };
  if (intent.status !== "published" && intent.status !== "active") {
    return { drifted: true, reason: `intent_status_${intent.status}` };
  }
  return { drifted: false };
}

/**
 * Recomputes policy from CURRENT agent/intent state and compares it to
 * what the manifest recorded. If admin narrows scope after a manifest was
 * issued, this catches it before the narrower policy has a chance to leak
 * a now-forbidden tool through a stale manifest.
 */
export function checkPolicyDrift(
  agent: MigRemoteAgent,
  intent: MigIntentDefinition,
  manifest: MigCapabilityManifest,
): DriftCheckResult {
  const currentPolicy = resolvePolicy(agent, intent);
  const recordedAllowed = new Set(
    Array.isArray(manifest.allowedCapabilities) ? (manifest.allowedCapabilities as string[]) : [],
  );
  const currentAllowed = new Set(currentPolicy.allowed_capability_ids);

  const nowForbidden = [...recordedAllowed].filter(c => !currentAllowed.has(c));
  if (nowForbidden.length > 0) {
    return { drifted: true, reason: `capabilities_revoked_since_manifest_issued:${nowForbidden.join(",")}` };
  }
  return { drifted: false };
}

// ─────────────────────────────────────────────────────────────────────────────
// Locked-agent behavioral drift checks (task-1800 step 6) — these compare a
// locked/active agent's *live* request against the approved draft profile it
// was locked to, rather than the intent/policy-graph checks above (which
// compare against admin-side state changes). Each check is intentionally
// narrow and pure so mig-core.ts can call whichever apply per request and
// mig-discovery.ts can turn any "drifted" result into a first-class
// mig_drift_events row with a severity.
// ─────────────────────────────────────────────────────────────────────────────

export interface BehavioralDriftCheckResult extends DriftCheckResult {
  driftType?: string;
  severity?: "info" | "warning" | "critical";
}

/** New tool/resource/prompt/capability the agent's approved profile never granted. */
export function checkNewCapabilityDrift(toolName: string, approvedToolNames: string[]): BehavioralDriftCheckResult {
  if (!approvedToolNames.includes(toolName)) {
    return {
      drifted: true,
      driftType: "new_capability_requested",
      severity: "warning",
      reason: `tool_outside_approved_profile:${toolName}`,
    };
  }
  return { drifted: false };
}

/** New domain/data-category hint outside the approved profile's domain scope (unless the profile is wildcard-scoped). */
export function checkNewDomainDrift(domainHints: string[], approvedDomainScope: string[]): BehavioralDriftCheckResult {
  if (approvedDomainScope.includes("*")) return { drifted: false };
  const unknown = domainHints.filter(d => !approvedDomainScope.includes(d));
  if (unknown.length > 0) {
    return {
      drifted: true,
      driftType: "new_data_category_or_domain",
      severity: "warning",
      reason: `domain_outside_approved_profile:${unknown.join(",")}`,
    };
  }
  return { drifted: false };
}

/** The live intent's risk zone is higher than what the profile was approved/locked at. */
export function checkRiskEscalationDrift(currentRiskZone: MigRiskZone, approvedRiskZone: MigRiskZone): BehavioralDriftCheckResult {
  const order: Record<MigRiskZone, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  if (order[currentRiskZone] > order[approvedRiskZone]) {
    return {
      drifted: true,
      driftType: "risk_zone_escalation",
      severity: order[currentRiskZone] - order[approvedRiskZone] >= 2 ? "critical" : "warning",
      reason: `risk_zone_escalated_from_${approvedRiskZone}_to_${currentRiskZone}`,
    };
  }
  return { drifted: false };
}

/**
 * Abnormal request frequency for one tool within a short window — a crude,
 * dependency-free heuristic (recent event count vs. a configurable
 * threshold) rather than a full rate-limiter; good enough to flag a locked
 * agent suddenly hammering a tool it previously called rarely.
 */
export function checkFrequencyDrift(recentCallCount: number, threshold = 50): BehavioralDriftCheckResult {
  if (recentCallCount > threshold) {
    return {
      drifted: true,
      driftType: "abnormal_frequency",
      severity: recentCallCount > threshold * 2 ? "critical" : "warning",
      reason: `call_count_${recentCallCount}_exceeds_threshold_${threshold}`,
    };
  }
  return { drifted: false };
}

/** The ticket's declared intent no longer matches the single intent the agent was locked to. */
export function checkDeclaredIntentDrift(requestedIntentId: string, lockedIntentId: string | undefined): BehavioralDriftCheckResult {
  if (lockedIntentId && requestedIntentId !== lockedIntentId) {
    return {
      drifted: true,
      driftType: "declared_intent_mismatch",
      severity: "critical",
      reason: `requested_intent_${requestedIntentId}_differs_from_locked_intent_${lockedIntentId}`,
    };
  }
  return { drifted: false };
}
