/**
 * shared/ms5-capability-classification.ts
 *
 * MS5 Capability Classification Taxonomy — seven classes with associated
 * approval policy, risk level, audit requirement, and execution policy.
 *
 * Layer 1 and Layer 4 consume these classifications when scoring and
 * generating findings. Every MCP tool in bripe-mcp-tools.ts is assigned
 * to one of these classes below.
 */

export type MS5CapabilityClass =
  | "READ"
  | "WRITE"
  | "EXECUTE"
  | "REPAIR"
  | "DEPLOY"
  | "ADMIN"
  | "DANGEROUS";

export interface MS5CapabilityClassDefinition {
  class: MS5CapabilityClass;
  label: string;
  description: string;
  risk_level: "critical" | "high" | "medium" | "low";
  approval_policy: "auto" | "human_review" | "human_approval" | "dual_approval";
  audit_required: boolean;
  execution_policy: "unrestricted" | "scoped" | "gated" | "blocked_by_default";
  requires_traceability: boolean;
  requires_evidence: boolean;
}

export const MS5_CAPABILITY_CLASS_DEFINITIONS: Record<MS5CapabilityClass, MS5CapabilityClassDefinition> = {
  READ: {
    class: "READ",
    label: "Read",
    description: "Read-only metadata and registry discovery — no state changes, no execution.",
    risk_level: "low",
    approval_policy: "auto",
    audit_required: false,
    execution_policy: "unrestricted",
    requires_traceability: false,
    requires_evidence: false,
  },
  WRITE: {
    class: "WRITE",
    label: "Write",
    description: "Modifies state in a controlled manner (e.g. ingestion, annotation).",
    risk_level: "medium",
    approval_policy: "human_review",
    audit_required: true,
    execution_policy: "scoped",
    requires_traceability: true,
    requires_evidence: false,
  },
  EXECUTE: {
    class: "EXECUTE",
    label: "Execute",
    description: "Invokes a computational engine to produce a structured decision output.",
    risk_level: "medium",
    approval_policy: "human_review",
    audit_required: true,
    execution_policy: "scoped",
    requires_traceability: true,
    requires_evidence: true,
  },
  REPAIR: {
    class: "REPAIR",
    label: "Repair",
    description: "Self-healing or remediation capability that alters operational state to fix a detected problem.",
    risk_level: "high",
    approval_policy: "human_approval",
    audit_required: true,
    execution_policy: "gated",
    requires_traceability: true,
    requires_evidence: true,
  },
  DEPLOY: {
    class: "DEPLOY",
    label: "Deploy",
    description: "Deploys or activates a new component, domain package, or configuration in a production environment.",
    risk_level: "high",
    approval_policy: "human_approval",
    audit_required: true,
    execution_policy: "gated",
    requires_traceability: true,
    requires_evidence: true,
  },
  ADMIN: {
    class: "ADMIN",
    label: "Admin",
    description: "Administrative control plane operations (package authoring, lifecycle management, tenant administration).",
    risk_level: "high",
    approval_policy: "dual_approval",
    audit_required: true,
    execution_policy: "gated",
    requires_traceability: true,
    requires_evidence: true,
  },
  DANGEROUS: {
    class: "DANGEROUS",
    label: "Dangerous",
    description: "High-impact capability with potential for irreversible side effects, data exfiltration, or privilege escalation.",
    risk_level: "critical",
    approval_policy: "dual_approval",
    audit_required: true,
    execution_policy: "blocked_by_default",
    requires_traceability: true,
    requires_evidence: true,
  },
};

/**
 * Classification of every tool in bripe-mcp-tools.ts ALL_MCP_TOOLS.
 * The MCP tool classification (read_only / execution / admin) maps to
 * the MS5 class as follows, with per-tool overrides where warranted.
 */
export const MS5_TOOL_CLASSIFICATIONS: Record<string, MS5CapabilityClass> = {
  list_domains: "READ",
  get_domain_package: "READ",
  list_capabilities: "READ",
  search_capabilities: "READ",
  get_capability_contract: "READ",
  list_bripe_layers: "READ",
  get_required_layers: "READ",
  list_doctrines: "READ",
  get_doctrine: "READ",
  get_doctrines_by_layer: "READ",
  explain_bripe_output_metrics: "READ",
  list_active_odps: "READ",
  get_odp_registry_status: "READ",
  get_bripe_output_manifest: "READ",
  check_odp_activation: "READ",
  validate_domain_package: "READ",
  list_adam_phases: "READ",
  get_governance_contract: "READ",
  retrieve_adaptation_memories: "READ",
  validate_decision_manifest: "READ",
  run_bripe_decision: "EXECUTE",
  run_safemerge_forecast: "EXECUTE",
  start_autopilot_objective: "ADMIN",
  ingest_replay_record: "WRITE",
  ingest_calibra_record: "WRITE",
};

export function classifyTool(toolName: string): MS5CapabilityClass {
  return MS5_TOOL_CLASSIFICATIONS[toolName] ?? "READ";
}

export function getClassDefinition(cls: MS5CapabilityClass): MS5CapabilityClassDefinition {
  return MS5_CAPABILITY_CLASS_DEFINITIONS[cls];
}
