/**
 * server/mig/ms5/ms5-remediation.ts
 *
 * MS5 Automated Remediation Recommendations
 *
 * Maps each finding category to a structured remediation recommendation.
 * Surfaces recommendations in the Security Roadmap section of the MS5 report.
 */

import type { MS5Finding, MS5RemediationRecommendation } from "@shared/ms5-contracts";
import type { MS5FindingCategory } from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

type ActionType = MS5RemediationRecommendation["action_type"];

interface FindingToActionMap {
  action_title: string;
  action_description: string;
  action_type: ActionType;
  priority: MS5RemediationRecommendation["priority"];
  template?: string;
  self_healing_eligible: boolean;
}

const FINDING_ACTION_MAP: Record<MS5FindingCategory, FindingToActionMap> = {
  schema_validation: {
    action_title: "Fix capability schema declaration",
    action_description: "Add or correct the canonical_service, inputSchema, or outputSchema declaration for the affected capability.",
    action_type: "fix_schema",
    priority: "high",
    template: `// In server/mcp/bripe-mcp-tools.ts
{
  name: "your_tool_name",
  classification: "execution",
  canonical_service: "path/to/canonical/service.ts#functionName",
  description: "Clear description of what this capability does (≥ 20 chars).",
  inputSchema: z.object({ ... }),
  outputSchema: { type: "object", properties: { ok: { type: "boolean" }, ... } },
  handler: async (input, ctx) => { ... },
}`,
    self_healing_eligible: false,
  },
  auth_missing: {
    action_title: "Add authorization declaration",
    action_description: "Declare the authorization model for this capability. Specify which roles, tenants, and risk zones are permitted to invoke it.",
    action_type: "restrict_capability",
    priority: "high",
    self_healing_eligible: false,
  },
  unsafe_pattern: {
    action_title: "Remove or gate unsafe capability",
    action_description: "If the unsafe pattern is intentional, add an explicit safety declaration and an admin-class execution gate. If unintentional, remove the unsafe code path.",
    action_type: "restrict_capability",
    priority: "immediate",
    self_healing_eligible: false,
  },
  prompt_injection: {
    action_title: "Add prompt injection resistance",
    action_description: "Implement input validation to reject prompt injection patterns. Add a system-level instruction boundary that cannot be overridden by user input.",
    action_type: "restrict_capability",
    priority: "high",
    template: `// Add input sanitization before passing to AI:
const sanitizedInput = input.objective
  .replace(/ignore\s+previous\s+instructions/gi, "[FILTERED]")
  .replace(/system\s*:/gi, "[FILTERED]")
  .slice(0, 2000); // enforce max length`,
    self_healing_eligible: false,
  },
  test_coverage_gap: {
    action_title: "Add missing test coverage",
    action_description: "Create test files covering the missing test categories for this capability.",
    action_type: "add_tests",
    priority: "medium",
    template: `// tests/<capability-name>.test.ts
describe("<capability-name>", () => {
  it("unit: returns expected shape for valid input", async () => { ... });
  it("boundary: rejects missing required fields", async () => { ... });
  it("integration: delegates to canonical service", async () => { ... });
  it("failure_recovery: returns structured error on service failure", async () => { ... });
});`,
    self_healing_eligible: false,
  },
  automation_gap: {
    action_title: "Automate test suite in CI",
    action_description: "Add automated test execution for this capability in the CI pipeline. Tests must run on every change that touches this tool.",
    action_type: "add_tests",
    priority: "medium",
    self_healing_eligible: false,
  },
  intent_drift: {
    action_title: "Add missing intent contract",
    action_description: "Create or update an intent definition to cover this capability. Every non-read-only capability must appear in at least one published intent contract.",
    action_type: "add_intent_contract",
    priority: "high",
    template: `// Via POST /api/mig/admin/intent-definitions
{
  "intentId": "new_intent_id",
  "libraryId": "bripe-core-v1",
  "name": "Descriptive Intent Name",
  "description": "What this intent authorizes and who should use it.",
  "allowedToolNames": ["affected_tool_name"],
  "riskZone": "medium",
  "status": "published"
}`,
    self_healing_eligible: false,
  },
  capability_escalation: {
    action_title: "Remove escalation path from intent or capability view",
    action_description: "Split mixed-class intents into separate discovery and execution intents. Remove admin-only tools from lower-privilege views.",
    action_type: "restrict_capability",
    priority: "high",
    self_healing_eligible: false,
  },
  unauthorized_discovery: {
    action_title: "Restrict unauthorized tool discovery surface",
    action_description: "Ensure that read-only discovery tools cannot be used to enumerate sensitive capabilities. Add authorization checks to discovery endpoints.",
    action_type: "restrict_capability",
    priority: "high",
    self_healing_eligible: false,
  },
  cross_product_access: {
    action_title: "Enforce product-level access boundaries",
    action_description: "Ensure that capabilities belonging to one product cannot be accessed by agents scoped to a different product.",
    action_type: "restrict_capability",
    priority: "medium",
    self_healing_eligible: false,
  },
  decision_integrity_gap: {
    action_title: "Add decision integrity fields to outputSchema",
    action_description: "Add 'ok', 'render_allowed', 'decision_trust', and 'metadata' fields to the tool's outputSchema.",
    action_type: "fix_schema",
    priority: "high",
    self_healing_eligible: false,
  },
  missing_traceability: {
    action_title: "Add traceability fields",
    action_description: "Add a 'metadata' field (run_id, assembled_at) and a 'render_allowed' flag to the outputSchema.",
    action_type: "fix_schema",
    priority: "medium",
    self_healing_eligible: false,
  },
  hallucinated_evidence: {
    action_title: "Add AI grounding disclaimer and output validation",
    action_description: "Clearly label AI-generated outputs as scaffolding/narrative only. Add output validation to prevent AI-generated numeric values from being used as evidence.",
    action_type: "restrict_capability",
    priority: "high",
    self_healing_eligible: false,
  },
  missing_fallback: {
    action_title: "Add explicit error handling and fallback",
    action_description: "Add a try/catch block and a structured error response (ok=false, error_code, message) to the tool handler.",
    action_type: "add_fallback",
    priority: "medium",
    template: `handler: async (input, ctx) => {
  try {
    const result = await canonicalService(input);
    return { ok: true, ...result };
  } catch (err: any) {
    return {
      ok: false,
      error: "service_error",
      message: err?.message ?? "Unexpected error",
    };
  }
}`,
    self_healing_eligible: false,
  },
  credential_posture: {
    action_title: "Improve credential posture",
    action_description: "Rotate credentials, implement credential rotation policy, or migrate to asymmetric authentication (OAuth/JWKS).",
    action_type: "other",
    priority: "medium",
    self_healing_eligible: false,
  },
  version_drift: {
    action_title: "Review and upgrade affected components",
    action_description: "Review the changelog for the version change. Re-run all Layer 1–4 checks. Update dependent components if required.",
    action_type: "upgrade_version",
    priority: "high",
    self_healing_eligible: false,
  },
  schema_drift: {
    action_title: "Reconcile schema drift",
    action_description: "Review schema changes for affected capabilities. Update callers to use the new schema. Add schema versioning if backward compatibility is needed.",
    action_type: "fix_schema",
    priority: "high",
    self_healing_eligible: false,
  },
  audit_log_missing: {
    action_title: "Enable audit logging",
    action_description: "Ensure all relevant events are recorded in the MIG audit log. Verify lastSeenAt is being updated on every authenticated request.",
    action_type: "add_audit_log",
    priority: "medium",
    self_healing_eligible: false,
  },
  health_endpoint_missing: {
    action_title: "Add health endpoint",
    action_description: "Expose a /health or /api/health endpoint that returns service status, version, and dependency health.",
    action_type: "add_health_endpoint",
    priority: "low",
    self_healing_eligible: true,
  },
  tenant_isolation_gap: {
    action_title: "Fix multi-tenant isolation",
    action_description: "Assign a valid tenantId to all agents. Ensure all data queries are scoped by tenantId.",
    action_type: "restrict_capability",
    priority: "immediate",
    self_healing_eligible: false,
  },
  repair_workflow_incomplete: {
    action_title: "Complete repair workflow declaration",
    action_description: "Add the missing repair workflow components: dry-run mode, authorization gate, rollback path, verification step, and post-repair validation.",
    action_type: "other",
    priority: "high",
    self_healing_eligible: true,
  },
  privilege_drift: {
    action_title: "Reconcile privilege assignments",
    action_description: "Review the privilege change and verify it was intentional. If unexpected, revert and investigate.",
    action_type: "restrict_capability",
    priority: "high",
    self_healing_eligible: false,
  },
  capability_drift: {
    action_title: "Review capability change",
    action_description: "Review the added/removed capability. Run Layer 1 and Layer 3 checks against new capabilities before going live.",
    action_type: "other",
    priority: "high",
    self_healing_eligible: false,
  },
  config_drift: {
    action_title: "Reconcile configuration drift",
    action_description: "Review configuration changes since the last snapshot. Revert or document each change.",
    action_type: "other",
    priority: "medium",
    self_healing_eligible: false,
  },
};

export function buildRemediationRecommendations(findings: MS5Finding[]): MS5RemediationRecommendation[] {
  const recommendations: MS5RemediationRecommendation[] = [];
  const seenCategories = new Set<string>();

  for (const finding of findings) {
    const key = `${finding.category}:${finding.capability_name ?? ""}`;
    if (seenCategories.has(key)) continue;
    seenCategories.add(key);

    const actionMap = FINDING_ACTION_MAP[finding.category];
    if (!actionMap) continue;

    const severityPriority: Record<string, MS5RemediationRecommendation["priority"]> = {
      critical: "immediate",
      high: "high",
      medium: "medium",
      low: "low",
      info: "low",
    };

    recommendations.push({
      finding_id: finding.id,
      finding_category: finding.category,
      priority: finding.severity === "critical" ? "immediate" : (severityPriority[finding.severity] ?? actionMap.priority),
      action_title: actionMap.action_title,
      action_description: finding.recommendation || actionMap.action_description,
      action_type: actionMap.action_type,
      template: actionMap.template,
      self_healing_eligible: actionMap.self_healing_eligible,
    });
  }

  const priorityOrder: Record<string, number> = { immediate: 0, high: 1, medium: 2, low: 3 };
  return recommendations.sort((a, b) => (priorityOrder[a.priority] ?? 99) - (priorityOrder[b.priority] ?? 99));
}

export function acknowledgeRecommendation(findingId: string): boolean {
  return true;
}
