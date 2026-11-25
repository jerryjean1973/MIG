/**
 * server/mig/ms5/remediation-engine.ts
 *
 * Remediation Recommendation Engine — for each finding derives:
 *   - root cause (from finding category + capability metadata)
 *   - recommended fix (human-readable)
 *   - a structured patch descriptor (which file, declaration, what change)
 *
 * Maps finding categories to patch templates.
 */

import type {
  MS5Finding,
  MS5RemediationRecommendation,
  MS5PatchDescriptor,
  PatchTemplate,
  MS5FindingCategory,
} from "@shared/ms5-contracts";

const CATEGORY_TO_TEMPLATE: Record<MS5FindingCategory, PatchTemplate> = {
  schema_validation:          "schema_constraint",
  auth_missing:               "auth_guard_addition",
  unsafe_pattern:             "restrict_capability_visibility",
  prompt_injection:           "auth_guard_addition",
  test_coverage_gap:          "schema_constraint",
  automation_gap:             "schema_constraint",
  intent_drift:               "intent_contract_addition",
  capability_escalation:      "restrict_capability_visibility",
  unauthorized_discovery:     "restrict_capability_visibility",
  cross_product_access:       "auth_guard_addition",
  decision_integrity_gap:     "missing_response_validation",
  missing_traceability:       "output_validator",
  hallucinated_evidence:      "output_validator",
  missing_fallback:           "schema_constraint",
  credential_posture:         "auth_guard_addition",
  version_drift:              "unsafe_default_fix",
  schema_drift:               "schema_constraint",
  audit_log_missing:          "output_validator",
  health_endpoint_missing:    "unsafe_default_fix",
  tenant_isolation_gap:       "auth_guard_addition",
  repair_workflow_incomplete: "restrict_capability_visibility",
  privilege_drift:            "auth_guard_addition",
  capability_drift:           "intent_contract_addition",
  config_drift:               "unsafe_default_fix",
};

const TEMPLATE_TARGET_FILES: Record<PatchTemplate, string> = {
  restrict_capability_visibility: "server/mcp/bripe-mcp-tools.ts",
  unsafe_default_fix:             "server/mcp/bripe-mcp-tools.ts",
  auth_guard_addition:            "server/mcp/bripe-mcp-schemas.ts",
  schema_constraint:              "server/mcp/bripe-mcp-schemas.ts",
  missing_response_validation:    "server/mcp/bripe-mcp-tools.ts",
  intent_contract_addition:       "server/mig/mig-bripe-adapter.ts",
  output_validator:               "shared/ms5-contracts.ts",
};

const TEMPLATE_DECLARATION_TYPES: Record<PatchTemplate, MS5PatchDescriptor["declaration_type"]> = {
  restrict_capability_visibility: "tool_definition",
  unsafe_default_fix:             "tool_definition",
  auth_guard_addition:            "auth_guard",
  schema_constraint:              "schema",
  missing_response_validation:    "tool_definition",
  intent_contract_addition:       "intent_contract",
  output_validator:               "output_validator",
};

const CATEGORY_TITLES: Record<MS5FindingCategory, string> = {
  schema_validation:          "Fix schema validation gap",
  auth_missing:               "Add authorization guard",
  unsafe_pattern:             "Remove or gate unsafe capability",
  prompt_injection:           "Add prompt injection guard",
  test_coverage_gap:          "Add test coverage",
  automation_gap:             "Add automation coverage",
  intent_drift:               "Align with intent contract",
  capability_escalation:      "Restrict capability escalation path",
  unauthorized_discovery:     "Block unauthorized discovery",
  cross_product_access:       "Add cross-product access boundary",
  decision_integrity_gap:     "Add decision integrity check",
  missing_traceability:       "Add output traceability",
  hallucinated_evidence:      "Add evidence validation",
  missing_fallback:           "Add structured fallback",
  credential_posture:         "Improve credential posture",
  version_drift:              "Align server version",
  schema_drift:               "Fix schema drift",
  audit_log_missing:          "Add audit logging",
  health_endpoint_missing:    "Add health endpoint",
  tenant_isolation_gap:       "Fix tenant isolation",
  repair_workflow_incomplete: "Complete repair workflow",
  privilege_drift:            "Fix privilege assignment drift",
  capability_drift:           "Align capability declaration",
  config_drift:               "Fix configuration drift",
};

const CATEGORY_PRIORITIES: Record<MS5FindingCategory, MS5RemediationRecommendation["priority"]> = {
  unsafe_pattern:             "immediate",
  capability_escalation:      "immediate",
  cross_product_access:       "immediate",
  tenant_isolation_gap:       "immediate",
  auth_missing:               "high",
  prompt_injection:           "high",
  unauthorized_discovery:     "high",
  privilege_drift:            "high",
  credential_posture:         "high",
  intent_drift:               "medium",
  capability_drift:           "medium",
  decision_integrity_gap:     "medium",
  missing_traceability:       "medium",
  hallucinated_evidence:      "medium",
  schema_validation:          "medium",
  schema_drift:               "medium",
  test_coverage_gap:          "low",
  automation_gap:             "low",
  missing_fallback:           "low",
  version_drift:              "low",
  audit_log_missing:          "low",
  health_endpoint_missing:    "low",
  repair_workflow_incomplete: "low",
  config_drift:               "low",
};

function buildPatchDescriptor(finding: MS5Finding): MS5PatchDescriptor {
  const template = CATEGORY_TO_TEMPLATE[finding.category] ?? "schema_constraint";
  return {
    target_file: TEMPLATE_TARGET_FILES[template] ?? "server/mcp/bripe-mcp-tools.ts",
    declaration_type: TEMPLATE_DECLARATION_TYPES[template] ?? "tool_definition",
    what_change: `Apply ${template.replace(/_/g, " ")} pattern to address: ${finding.title}`,
    template,
    finding_category: finding.category,
  };
}

export function buildRemediationRecommendationsEnriched(
  findings: MS5Finding[],
): MS5RemediationRecommendation[] {
  return findings.map(finding => {
    const priority = CATEGORY_PRIORITIES[finding.category] ?? "medium";
    const template = CATEGORY_TO_TEMPLATE[finding.category] ?? "schema_constraint";
    const isSelfHealingEligible = ["repair_workflow_incomplete", "automation_gap", "health_endpoint_missing"].includes(finding.category);

    return {
      finding_id: finding.id,
      finding_category: finding.category,
      priority,
      action_title: CATEGORY_TITLES[finding.category] ?? finding.category.replace(/_/g, " "),
      action_description: finding.recommendation,
      action_type: mapTemplateToActionType(template),
      template,
      self_healing_eligible: isSelfHealingEligible,
      patch_descriptor: buildPatchDescriptor(finding),
    };
  });
}

function mapTemplateToActionType(template: PatchTemplate): MS5RemediationRecommendation["action_type"] {
  const mapping: Record<PatchTemplate, MS5RemediationRecommendation["action_type"]> = {
    restrict_capability_visibility: "restrict_capability",
    unsafe_default_fix:             "fix_schema",
    auth_guard_addition:            "fix_schema",
    schema_constraint:              "fix_schema",
    missing_response_validation:    "add_fallback",
    intent_contract_addition:       "add_intent_contract",
    output_validator:               "add_audit_log",
  };
  return mapping[template] ?? "other";
}
