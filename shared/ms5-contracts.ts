/**
 * shared/ms5-contracts.ts
 *
 * Canonical types for the MS5 (MCP Security Five-Layer Model) subsystem.
 * These types are shared between the engine (server/mig/ms5/) and the
 * admin UI (client/src/pages/mig-admin-page.tsx).
 *
 * Layer mapping:
 *   Layer 1 — Capability Correctness
 *   Layer 2 — Capability Assurance
 *   Layer 3 — Intent Governance
 *   Layer 4 — Decision Integrity
 *   Layer 5 — Operational Governance
 */

export type MS5Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export type MS5FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export type MS5Layer = "layer1" | "layer2" | "layer3" | "layer4" | "layer5";

export type MS5FindingCategory =
  | "schema_validation"
  | "auth_missing"
  | "unsafe_pattern"
  | "prompt_injection"
  | "test_coverage_gap"
  | "automation_gap"
  | "intent_drift"
  | "capability_escalation"
  | "unauthorized_discovery"
  | "cross_product_access"
  | "decision_integrity_gap"
  | "missing_traceability"
  | "hallucinated_evidence"
  | "missing_fallback"
  | "credential_posture"
  | "version_drift"
  | "schema_drift"
  | "audit_log_missing"
  | "health_endpoint_missing"
  | "tenant_isolation_gap"
  | "repair_workflow_incomplete"
  | "privilege_drift"
  | "capability_drift"
  | "config_drift";

export interface MS5Finding {
  id: string;
  layer: MS5Layer;
  severity: MS5FindingSeverity;
  category: MS5FindingCategory;
  title: string;
  evidence: string;
  recommendation: string;
  capability_name?: string;
  acknowledged?: boolean;
  acknowledged_at?: string;
  /** Extended attack-surface fields (added by capability-attack-surface.ts) */
  likelihood?: number;
  impact?: number;
  confidence?: number;
  affected_products?: string[];
  patch_descriptor?: MS5PatchDescriptor;
}

export interface MS5LayerResult {
  layer: MS5Layer;
  layer_name: string;
  score: number;
  max_score: number;
  percentage: number;
  grade: MS5Grade;
  findings: MS5Finding[];
  summary: string;
  checked_at: string;
}

// ─── Enriched Capability Inventory ───────────────────────────────────────────

export interface MS5CapabilityInventoryItem {
  capability_name: string;
  capability_id: string;
  classification: string;
  risk_level: "critical" | "high" | "medium" | "low";
  layer1_finding_count: number;
  has_intent_contract: boolean;
  has_test_coverage: boolean;
  prompt_injection_risk: boolean;
  /** Enriched fields from capability-attack-surface.ts */
  description?: string;
  parameters?: string[];
  permission_declarations?: string[];
  execution_type?: string;
  privilege_level?: "read_only" | "execution" | "admin";
  ms5_class?: string;
  caller_products?: string[];
  dependencies?: string[];
  attack_surface_findings?: MS5AttackSurfaceFinding[];
}

// ─── Attack Surface Analysis ──────────────────────────────────────────────────

export type AttackVector =
  | "prompt_injection"
  | "indirect_prompt_injection"
  | "objective_drift"
  | "intent_drift"
  | "unauthorized_discovery"
  | "unauthorized_invocation"
  | "parameter_injection"
  | "command_injection"
  | "schema_abuse"
  | "tool_chaining"
  | "recursive_calls"
  | "privilege_escalation"
  | "capability_escalation"
  | "response_poisoning"
  | "response_hallucination"
  | "cross_product_access"
  | "cross_tenant_access"
  | "information_disclosure"
  | "hidden_tool_discovery"
  | "shadow_capabilities"
  | "fallback_abuse"
  | "capability_spoofing"
  | "unauthorized_repair"
  | "unsafe_defaults";

export interface MS5AttackSurfaceFinding {
  vector: AttackVector;
  severity: MS5FindingSeverity;
  evidence: string;
  likelihood: number;
  impact: number;
  confidence: number;
  affected_products?: string[];
}

export interface MS5CapabilityAttackSurface {
  capability_name: string;
  capability_id: string;
  vectors_evaluated: number;
  findings: MS5AttackSurfaceFinding[];
  overall_attack_surface_score: number;
}

// ─── Certification State ──────────────────────────────────────────────────────

export type MS5CertificationState =
  | "CERTIFIED"
  | "CERTIFIED_WITH_WARNINGS"
  | "CONDITIONAL"
  | "FAILED"
  | "BLOCKED";

export interface MS5CertificationResult {
  state: MS5CertificationState;
  verdict_reason: string;
  blocking_factors: string[];
  warning_factors: string[];
  overall_score: number;
  critical_finding_count: number;
  blocked_capability_count: number;
  certified_at: string;
  production_promotion_allowed: boolean;
  promotion_block_reason?: string;
}

// ─── Escape Route Analysis ────────────────────────────────────────────────────

export interface EscapeRouteNode {
  id: string;
  capability_name: string;
  classification: string;
  ms5_class: string;
  privilege_level: string;
  x?: number;
  y?: number;
}

export interface EscapeRouteEdge {
  from: string;
  to: string;
  label: string;
  risk_weight: number;
}

export interface EscapeRoutePath {
  path_id: string;
  nodes: string[];
  edges: EscapeRouteEdge[];
  path_length: number;
  cumulative_risk_score: number;
  likelihood_score: number;
  terminates_at: string;
  path_type: "shortest" | "highest_risk" | "most_likely";
}

export interface MS5EscapeRouteAnalysis {
  nodes: EscapeRouteNode[];
  edges: EscapeRouteEdge[];
  canonical_paths: EscapeRoutePath[];
  total_paths_discovered: number;
  highest_risk_terminus: string;
}

// ─── Intent Validation ────────────────────────────────────────────────────────

export interface MS5ProductIntentValidation {
  product_id: string;
  product_name: string;
  declared_intent: string;
  visible_capabilities: string[];
  forbidden_capabilities_exposed: string[];
  undeclared_capabilities: string[];
  capability_drift_count: number;
  intent_drift_count: number;
  objective_drift_count: number;
  violations: Array<{
    type: "capability_drift" | "intent_drift" | "objective_drift" | "hidden_capability" | "unauthorized_invocation";
    capability_name: string;
    evidence: string;
    severity: MS5FindingSeverity;
  }>;
  validation_passed: boolean;
}

export interface MS5IntentValidationReport {
  products_validated: number;
  total_violations: number;
  critical_violations: number;
  validations: MS5ProductIntentValidation[];
  generated_at: string;
}

// ─── Automated Test Generation ────────────────────────────────────────────────

export type MS5TestType =
  | "schema"
  | "boundary"
  | "regression"
  | "intent"
  | "prompt_injection"
  | "jailbreak"
  | "chaining"
  | "privilege_escalation";

export interface MS5GeneratedTest {
  id: string;
  capability_id: string;
  capability_name: string;
  test_type: MS5TestType;
  test_name: string;
  input_payload: Record<string, unknown>;
  expected_behavior: string;
  last_pass?: boolean;
  generated_at: string;
}

export interface MS5CapabilityTestCoverage {
  capability_name: string;
  capability_id: string;
  total_tests: number;
  tests_by_type: Record<MS5TestType, number>;
  coverage_pct: number;
  pass_pct: number;
  confidence: number;
  tests: MS5GeneratedTest[];
}

// ─── Patch Descriptor & Patches ───────────────────────────────────────────────

export type PatchTemplate =
  | "restrict_capability_visibility"
  | "unsafe_default_fix"
  | "auth_guard_addition"
  | "schema_constraint"
  | "missing_response_validation"
  | "intent_contract_addition"
  | "output_validator";

export interface MS5PatchDescriptor {
  target_file: string;
  declaration_type: "tool_definition" | "intent_contract" | "schema" | "auth_guard" | "output_validator";
  what_change: string;
  template: PatchTemplate;
  finding_category: MS5FindingCategory;
}

export type MS5PatchStatus = "PENDING" | "APPROVED" | "REJECTED" | "QUEUED" | "MERGED";

export interface MS5Patch {
  id: number;
  finding_id: string;
  mcp_server_id: string;
  tenant_id: string;
  status: MS5PatchStatus;
  diff_text: string;
  risk_before: number;
  risk_after: number;
  coverage_delta: number;
  regression_risk: "low" | "medium" | "high";
  impact_description: string;
  capability_name?: string;
  finding_summary?: string;
  generated_at: string;
  reviewed_at?: string;
  merged_at?: string;
}

// ─── Post-merge Validation ────────────────────────────────────────────────────

export interface MS5PatchValidation {
  id: number;
  patch_id: number;
  mcp_server_id: string;
  tenant_id: string;
  score_before: number;
  score_after: number;
  grade_before: MS5Grade;
  grade_after: MS5Grade;
  certification_before: MS5CertificationState;
  certification_after: MS5CertificationState;
  finding_delta: number;
  coverage_delta: number;
  validation_report: {
    new_findings: string[];
    resolved_findings: string[];
    test_results: Array<{ test_id: string; passed: boolean; test_type: MS5TestType }>;
    summary: string;
  };
  created_at: string;
}

// ─── Scorecard ────────────────────────────────────────────────────────────────

export interface MS5SecurityScorecard {
  overall_score: number;
  overall_grade: MS5Grade;
  layer_scores: Record<MS5Layer, number>;
  layer_grades: Record<MS5Layer, MS5Grade>;
  critical_finding_count: number;
  high_finding_count: number;
  medium_finding_count: number;
  low_finding_count: number;
  total_capabilities_reviewed: number;
  intent_coverage_percentage: number;
  test_coverage_percentage: number;
  prompt_security_score: number;
  self_healing_score: number;
  certification?: MS5CertificationResult;
}

export interface MS5DriftSnapshot {
  snapshot_id: string;
  taken_at: string;
  capability_names: string[];
  schema_hashes: Record<string, string>;
  intent_bindings: string[];
  privilege_assignments: Record<string, string>;
  version_hash: string;
  /** Non-secret fingerprint: hash of each agent's security posture (trustLevel + maxClass + riskZones). */
  credential_fingerprints: Record<string, string>;
}

export interface MS5DriftDetectionResult {
  has_drift: boolean;
  new_capabilities: string[];
  removed_capabilities: string[];
  schema_drift_capabilities: string[];
  intent_drift_capabilities: string[];
  privilege_drift_details: string[];
  credential_drift: boolean;
  version_drift: boolean;
  decision_drift: boolean;
}

export interface MS5RemediationRecommendation {
  finding_id: string;
  finding_category: MS5FindingCategory;
  priority: "immediate" | "high" | "medium" | "low";
  action_title: string;
  action_description: string;
  action_type: "add_tests" | "add_intent_contract" | "disable_capability" | "fix_schema" | "upgrade_version" | "add_audit_log" | "restrict_capability" | "add_health_endpoint" | "add_fallback" | "other";
  template?: string;
  self_healing_eligible: boolean;
  patch_descriptor?: MS5PatchDescriptor;
}

export interface MS5Report {
  report_id: string;
  mcp_server_id: string;
  tenant_id: string;
  generated_at: string;
  overall_score: number;
  overall_grade: MS5Grade;
  layer_results: MS5LayerResult[];
  scorecard: MS5SecurityScorecard;
  capability_inventory: MS5CapabilityInventoryItem[];
  findings: MS5Finding[];
  remediation_recommendations: MS5RemediationRecommendation[];
  drift_detection?: MS5DriftDetectionResult;
  snapshot?: MS5DriftSnapshot;
  prompt_security_score: number;
  self_healing_score: number;
  review_triggered_by: "on_demand" | "registration" | "capability_change" | "scheduled";
  next_scheduled_review?: string;
  certification?: MS5CertificationResult;
  escape_route_analysis?: MS5EscapeRouteAnalysis;
  intent_validation?: MS5IntentValidationReport;
  attack_surface?: {
    per_capability_surfaces: MS5CapabilityAttackSurface[];
  };
}

/** Grade thresholds: score is 0–100. */
export function scoreToGrade(score: number): MS5Grade {
  if (score >= 97) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}
