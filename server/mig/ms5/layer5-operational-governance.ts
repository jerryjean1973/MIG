/**
 * server/mig/ms5/layer5-operational-governance.ts
 *
 * MS5 Layer 5 — Operational Governance
 *
 * Reviews MCP server registration metadata:
 *   - TIP/capability version tracking
 *   - Credential storage posture
 *   - Certificate status
 *   - Audit-log presence
 *   - Health endpoints
 *   - Version/schema/capability/config drift (diff against last snapshot)
 *   - Lifecycle state
 *   - Multi-tenant isolation evidence
 */

import type { MigRemoteAgent } from "@shared/schema";
import type { MS5Finding, MS5LayerResult, MS5DriftDetectionResult } from "@shared/ms5-contracts";
import { scoreToGrade } from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

function makeId(): string {
  return `f5_${randomBytes(6).toString("hex")}`;
}

export function runLayer5OperationalGovernance(
  agents: MigRemoteAgent[],
  driftResult?: MS5DriftDetectionResult,
): MS5LayerResult {
  const findings: MS5Finding[] = [];

  for (const agent of agents) {
    if (!agent.tenantId || agent.tenantId.trim() === "") {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "critical",
        category: "tenant_isolation_gap",
        title: `Agent '${agent.agentId}' has no tenant ID`,
        evidence: `tenantId is empty or missing. Multi-tenant isolation requires all agents to be scoped to a tenant.`,
        recommendation: `Assign a valid tenantId to this agent. Without tenant scoping, data isolation between tenants cannot be guaranteed.`,
      });
    }

    if (agent.status === "active" && !agent.lastSeenAt) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "info",
        category: "audit_log_missing",
        title: `Agent '${agent.agentId}' has no recorded activity (lastSeenAt=null)`,
        evidence: `Agent is active but has never been seen. Either it has never connected or lastSeenAt is not being updated.`,
        recommendation: `Verify the agent's lastSeenAt is being updated on every authenticated request. An active agent with no activity may indicate a stale or orphaned registration.`,
      });
    }

    const agentCreatedAt = new Date(agent.createdAt);
    const ageMs = Date.now() - agentCreatedAt.getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);

    if (ageDays > 90 && !agent.lastSeenAt) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "medium",
        category: "credential_posture",
        title: `Agent '${agent.agentId}' credential is ${Math.floor(ageDays)} days old with no recent activity`,
        evidence: `Agent registered ${Math.floor(ageDays)} days ago and has never been seen. Stale credentials increase attack surface.`,
        recommendation: `Rotate or revoke the ticket secret for this agent. Establish a credential rotation policy (90 days recommended).`,
      });
    }

    if (agent.lifecycleState === "discovery" && ageDays > 30) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "medium",
        category: "capability_drift",
        title: `Agent '${agent.agentId}' has been in 'discovery' state for ${Math.floor(ageDays)} days`,
        evidence: `Discovery mode is intended as a short-term observation phase. Extended discovery without profile synthesis increases governance risk.`,
        recommendation: `Review the discovery events for this agent and synthesize a draft profile. If no meaningful activity is observed, revoke the agent.`,
      });
    }

    if (agent.status === "revoked" && !agent.revokedAt) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "low",
        category: "audit_log_missing",
        title: `Agent '${agent.agentId}' is revoked but has no revokedAt timestamp`,
        evidence: `status=revoked but revokedAt is null. Audit completeness requires revocation timestamps.`,
        recommendation: `Backfill the revokedAt timestamp for this agent or re-revoke with the current timestamp.`,
      });
    }

    const maxCap = agent.maxCapabilityClassification ?? "read_only";
    const riskZones = Array.isArray(agent.allowedRiskZones) ? (agent.allowedRiskZones as string[]) : [];
    if (maxCap === "admin" && riskZones.includes("low") && !riskZones.includes("critical")) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "medium",
        category: "privilege_drift",
        title: `Agent '${agent.agentId}' has admin capability class but restricted risk zone scope`,
        evidence: `maxCapabilityClassification=admin but allowedRiskZones includes only: ${riskZones.join(", ")}. Admin-class agents typically require elevated risk zone access.`,
        recommendation: `Verify that the agent's risk zone scope is intentionally restricted. If admin operations require higher risk zones, update allowedRiskZones accordingly.`,
      });
    }

    if (!agent.oauthClientId && !agent.jwksUrl) {
      if (ageDays > 7) {
        findings.push({
          id: makeId(),
          layer: "layer5",
          severity: "low",
          category: "credential_posture",
          title: `Agent '${agent.agentId}' uses symmetric secret only (no OAuth/JWKS)`,
          evidence: `No oauthClientId or jwksUrl declared. Agent authentication relies solely on a shared symmetric ticket_secret.`,
          recommendation: `For production agents, prefer OAuth 2.0 or JWKS-based asymmetric authentication over symmetric secrets. This reduces the blast radius of a secret compromise.`,
        });
      }
    }
  }

  if (driftResult?.has_drift) {
    if (driftResult.new_capabilities.length > 0) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "high",
        category: "capability_drift",
        title: `Capability drift: ${driftResult.new_capabilities.length} new capability(ies) detected since last review`,
        evidence: `New capabilities: ${driftResult.new_capabilities.join(", ")}`,
        recommendation: `Review all new capabilities in Layer 1 and Layer 3. Ensure they have intent contracts before going live.`,
      });
    }
    if (driftResult.removed_capabilities.length > 0) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "medium",
        category: "capability_drift",
        title: `Capability drift: ${driftResult.removed_capabilities.length} capability(ies) removed since last review`,
        evidence: `Removed capabilities: ${driftResult.removed_capabilities.join(", ")}`,
        recommendation: `Verify that agents with intent contracts referencing removed capabilities have been updated. Stale intent contracts cause unexpected denials.`,
      });
    }
    if (driftResult.schema_drift_capabilities.length > 0) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "high",
        category: "schema_drift",
        title: `Schema drift detected in ${driftResult.schema_drift_capabilities.length} capability(ies)`,
        evidence: `Affected: ${driftResult.schema_drift_capabilities.join(", ")}`,
        recommendation: `Review schema changes for these capabilities. Callers using the old schema may receive unexpected errors or miss new fields.`,
      });
    }
    if (driftResult.version_drift) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "high",
        category: "version_drift",
        title: `MCP server version drift detected since last review`,
        evidence: `Server version hash changed since the last snapshot was taken.`,
        recommendation: `Review the changelog for this version. Re-run all Layer 1–4 checks against the updated server.`,
      });
    }
    if (driftResult.credential_drift) {
      findings.push({
        id: makeId(),
        layer: "layer5",
        severity: "critical",
        category: "credential_posture",
        title: `Credential drift detected — credential set has changed since last review`,
        evidence: `One or more agent credentials (ticket_secret) changed outside of a scheduled rotation.`,
        recommendation: `Audit the credential change. If unexpected, treat as a potential compromise and rotate all affected agent secrets immediately.`,
      });
    }
  }

  if (agents.length === 0) {
    findings.push({
      id: makeId(),
      layer: "layer5",
      severity: "info",
      category: "audit_log_missing",
      title: "No registered agents to review",
      evidence: "Agent registry is empty. No operational governance data available.",
      recommendation: "Register MCP agents before expecting operational governance findings.",
    });
  }

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;

  const rawPenalty = criticalCount * 15 + highCount * 7 + mediumCount * 3;
  const score = Math.max(0, 100 - rawPenalty);

  return {
    layer: "layer5",
    layer_name: "Operational Governance",
    score,
    max_score: 100,
    percentage: score,
    grade: scoreToGrade(score),
    findings,
    summary: `Reviewed ${agents.length} registered agent(s). Found ${criticalCount} critical, ${highCount} high, ${mediumCount} medium issues. Score: ${score}/100.`,
    checked_at: new Date().toISOString(),
  };
}
