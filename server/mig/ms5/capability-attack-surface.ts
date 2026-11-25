/**
 * server/mig/ms5/capability-attack-surface.ts
 *
 * Capability Attack Surface Analysis — evaluates all 24 attack vectors per
 * capability and produces structured findings. Results feed Layer 1 and
 * Layer 3 scores in the MS5 engine.
 */

import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { migToolSchemaProperties } from "./tool-schema";
import { classifyTool, getClassDefinition } from "@shared/ms5-capability-classification";
import type {
  MS5CapabilityAttackSurface,
  MS5AttackSurfaceFinding,
  AttackVector,
  MS5FindingSeverity,
  MS5CapabilityInventoryItem,
} from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

function makeId(): string {
  return `as_${randomBytes(6).toString("hex")}`;
}

const FREE_TEXT_PATTERNS = [/free[- ]text/i, /natural[- ]language/i, /user\s+input/i, /llm/i];
const EXECUTION_TOOLS = new Set(["run_bripe_decision", "run_safemerge_forecast", "start_autopilot_objective"]);
const WRITE_TOOLS = new Set(["ingest_replay_record", "ingest_calibra_record"]);
const ADMIN_TOOLS = new Set(["start_autopilot_objective"]);

function hasUnboundedInput(desc: string): boolean {
  return FREE_TEXT_PATTERNS.some(p => p.test(desc));
}

/**
 * Evaluate ALL 24 canonical attack vectors for a tool.
 * Every vector is assessed; a finding is emitted for each one — severity
 * reflects actual risk rather than the vector being skipped silently.
 * `vectors_evaluated` is always set to ALL_VECTORS.length (24).
 */
function evaluateVectorsForTool(
  toolName: string,
  description: string,
  classification: string,
  ms5Class: string,
): MS5AttackSurfaceFinding[] {
  const findings: MS5AttackSurfaceFinding[] = [];
  const isExec = EXECUTION_TOOLS.has(toolName) || classification === "execution";
  const isAdmin = ADMIN_TOOLS.has(toolName) || classification === "admin";
  const isWrite = WRITE_TOOLS.has(toolName);
  const isReadOnly = !isExec && !isAdmin && !isWrite;
  const unbounded = hasUnboundedInput(description);
  const lacksDescription = !description || description.trim().length < 20;

  const add = (
    vector: AttackVector,
    severity: MS5FindingSeverity,
    evidence: string,
    likelihood: number,
    impact: number,
    confidence: number,
    affected_products?: string[],
  ) => findings.push({ vector, severity, evidence, likelihood, impact, confidence, affected_products });

  // 1. prompt_injection
  if (unbounded) {
    add("prompt_injection", "high",
      `'${toolName}' accepts free-text/natural-language input — a direct prompt injection surface.`,
      0.65, 0.8, 0.9);
  } else {
    add("prompt_injection", "low",
      `'${toolName}' uses structured inputs only — prompt injection risk is low but not eliminated.`,
      0.1, 0.4, 0.8);
  }

  // 2. indirect_prompt_injection
  if (unbounded) {
    add("indirect_prompt_injection", "medium",
      `Free-text input on '${toolName}' can carry indirect injection payloads from upstream systems.`,
      0.4, 0.7, 0.75);
  } else {
    add("indirect_prompt_injection", "low",
      `Structured inputs reduce but do not eliminate indirect injection risk on '${toolName}'.`,
      0.15, 0.45, 0.7);
  }

  // 3. objective_drift
  if (unbounded || isExec) {
    add("objective_drift", "medium",
      `'${toolName}' parameters can be manipulated to shift the call's declared objective.`,
      0.5, 0.65, 0.8);
  } else {
    add("objective_drift", "info",
      `'${toolName}' uses tightly-scoped parameters — objective drift risk is minimal.`,
      0.05, 0.2, 0.85);
  }

  // 4. intent_drift
  if (isExec || isAdmin) {
    add("intent_drift", "medium",
      `Execution/admin capabilities like '${toolName}' can be invoked with intent declarations that drift from actual behavior.`,
      0.3, 0.6, 0.75);
  } else {
    add("intent_drift", "low",
      `'${toolName}' is read-only — intent drift limited to disclosure scenarios.`,
      0.1, 0.3, 0.7);
  }

  // 5. unauthorized_discovery
  if (lacksDescription) {
    add("unauthorized_discovery", "medium",
      `'${toolName}' lacks sufficient description — its capabilities can be enumerated by adversarial probing.`,
      0.4, 0.5, 0.85);
  } else {
    add("unauthorized_discovery", "low",
      `'${toolName}' is registered with a description; discovery risk is standard.`,
      0.2, 0.35, 0.8);
  }

  // 6. unauthorized_invocation
  add("unauthorized_invocation", "medium",
    `'${toolName}' requires intent-level authorization but may be invocable by misconfigured agents.`,
    0.25, 0.7, 0.75);

  // 7. parameter_injection
  if (isExec || isWrite) {
    add("parameter_injection", "high",
      `'${toolName}' accepts execution-relevant parameters that may be injected with adversarial values.`,
      0.35, 0.75, 0.8);
  } else {
    add("parameter_injection", "low",
      `'${toolName}' parameters are bounded — injection risk is low.`,
      0.1, 0.4, 0.75);
  }

  // 8. command_injection
  if (isAdmin || isWrite) {
    add("command_injection", "high",
      `Admin/write capability '${toolName}' may accept inputs interpreted as system commands.`,
      0.2, 0.85, 0.75);
  } else {
    add("command_injection", "low",
      `'${toolName}' does not execute system commands — command injection risk is low.`,
      0.05, 0.3, 0.8);
  }

  // 9. schema_abuse
  if (isWrite) {
    add("schema_abuse", "medium",
      `'${toolName}' writes to persistent storage — malformed schema payloads can corrupt state.`,
      0.35, 0.7, 0.85);
  } else {
    add("schema_abuse", "low",
      `'${toolName}' does not write to storage — schema abuse risk is bounded.`,
      0.1, 0.3, 0.75);
  }

  // 10. tool_chaining
  if (isExec || isAdmin) {
    add("tool_chaining", "medium",
      `'${toolName}' accepts inputs from other tools — multi-step chaining can amplify access scope.`,
      0.45, 0.7, 0.8);
  } else {
    add("tool_chaining", "low",
      `'${toolName}' is read-only — chaining risk is limited to information aggregation.`,
      0.15, 0.4, 0.75);
  }

  // 11. recursive_calls
  if (isExec) {
    add("recursive_calls", "medium",
      `Execution capability '${toolName}' could be invoked recursively via agent orchestration loops.`,
      0.2, 0.65, 0.7);
  } else {
    add("recursive_calls", "low",
      `'${toolName}' does not trigger downstream tool calls — recursive call risk is low.`,
      0.05, 0.25, 0.75);
  }

  // 12. privilege_escalation
  if (isExec || isAdmin) {
    add("privilege_escalation", "high",
      `'${toolName}' (${classification}) can be reached via intent chains from lower-privilege callers.`,
      0.3, 0.9, 0.85, ["VendorGate", "BRIPe", "AI360"]);
  } else {
    add("privilege_escalation", "low",
      `'${toolName}' is read-only — privilege escalation via this tool is limited.`,
      0.1, 0.4, 0.75);
  }

  // 13. capability_escalation
  if (isAdmin) {
    add("capability_escalation", "critical",
      `'${toolName}' has admin-class classification — capability escalation risk is critical.`,
      0.25, 1.0, 0.95, ["Byolab", "BRIPe"]);
  } else if (isExec) {
    add("capability_escalation", "medium",
      `Execution capability '${toolName}' can be chained to admin tools — indirect escalation risk.`,
      0.2, 0.7, 0.8);
  } else {
    add("capability_escalation", "low",
      `'${toolName}' is read-only — direct capability escalation is not applicable.`,
      0.05, 0.3, 0.8);
  }

  // 14. response_poisoning
  if (isWrite) {
    add("response_poisoning", "medium",
      `Ingestion capability '${toolName}' can be used to poison the corpus for downstream reads.`,
      0.3, 0.75, 0.8);
  } else {
    add("response_poisoning", "low",
      `'${toolName}' does not write corpus data — response poisoning risk is low.`,
      0.1, 0.35, 0.75);
  }

  // 15. response_hallucination
  if (isExec || unbounded) {
    add("response_hallucination", "medium",
      `'${toolName}' may produce AI-influenced outputs — hallucination risk in structured responses.`,
      0.3, 0.6, 0.7);
  } else {
    add("response_hallucination", "low",
      `'${toolName}' returns deterministic structured data — hallucination risk is minimal.`,
      0.1, 0.3, 0.75);
  }

  // 16. cross_product_access
  if (isExec || isAdmin) {
    add("cross_product_access", "medium",
      `'${toolName}' outputs are consumed by multiple products — cross-product access boundaries must be enforced.`,
      0.2, 0.7, 0.75, ["VendorGate", "BondsValuator", "RealValuator"]);
  } else {
    add("cross_product_access", "low",
      `'${toolName}' outputs are scoped to the calling product — cross-product access risk is low.`,
      0.1, 0.4, 0.7);
  }

  // 17. cross_tenant_access
  if (isAdmin || toolName.includes("admin")) {
    add("cross_tenant_access", "high",
      `Admin capability '${toolName}' must enforce strict tenant isolation — cross-tenant access is critical.`,
      0.2, 0.95, 0.9, ["all"]);
  } else {
    add("cross_tenant_access", "low",
      `'${toolName}' responses are tenant-scoped by default — cross-tenant access risk is low.`,
      0.1, 0.5, 0.8);
  }

  // 18. information_disclosure
  add("information_disclosure", "low",
    `'${toolName}' returns structured data — output must be scoped to tenant to prevent disclosure.`,
    0.2, 0.5, 0.85);

  // 19. hidden_tool_discovery
  if (lacksDescription) {
    add("hidden_tool_discovery", "medium",
      `'${toolName}' lacks a sufficient description — shadow-capability discovery risk is elevated.`,
      0.4, 0.6, 0.9);
  } else {
    add("hidden_tool_discovery", "low",
      `'${toolName}' is well-described — shadow-capability risk is low.`,
      0.1, 0.35, 0.85);
  }

  // 20. shadow_capabilities
  if (isAdmin || isExec) {
    add("shadow_capabilities", "medium",
      `'${toolName}' may expose undocumented behaviors not visible in the intent contract.`,
      0.2, 0.65, 0.7);
  } else {
    add("shadow_capabilities", "info",
      `'${toolName}' is read-only — shadow capability risk is minimal.`,
      0.05, 0.2, 0.7);
  }

  // 21. fallback_abuse
  if (isExec || isAdmin) {
    add("fallback_abuse", "medium",
      `'${toolName}' may fall back to a less-restrictive execution path under error conditions.`,
      0.2, 0.6, 0.75);
  } else {
    add("fallback_abuse", "low",
      `'${toolName}' has no known fallback escalation path — fallback abuse risk is low.`,
      0.05, 0.3, 0.7);
  }

  // 22. capability_spoofing
  add("capability_spoofing", "low",
    `'${toolName}' could be spoofed if the MCP server does not validate caller identity strictly.`,
    0.15, 0.6, 0.7);

  // 23. unauthorized_repair
  if (isAdmin) {
    add("unauthorized_repair", "high",
      `Admin-class capability '${toolName}' could be abused for unauthorized self-repair operations.`,
      0.2, 0.85, 0.8);
  } else {
    add("unauthorized_repair", "low",
      `'${toolName}' cannot trigger repair operations — unauthorized repair risk is low.`,
      0.05, 0.25, 0.75);
  }

  // 24. unsafe_defaults
  add("unsafe_defaults", "low",
    `'${toolName}' may rely on defaults that expose more than intended if not explicitly configured.`,
    0.2, 0.45, 0.7);

  return findings;
}

export function runCapabilityAttackSurfaceAnalysis(): {
  surfaces: MS5CapabilityAttackSurface[];
  enrichedInventory: MS5CapabilityInventoryItem[];
} {
  const surfaces: MS5CapabilityAttackSurface[] = [];
  const enrichedInventory: MS5CapabilityInventoryItem[] = [];

  for (const tool of ALL_MCP_TOOLS) {
    const ms5Class = classifyTool(tool.name);
    const classDef = getClassDefinition(ms5Class);
    const findings = evaluateVectorsForTool(
      tool.name,
      tool.description ?? "",
      tool.classification,
      ms5Class,
    );

    const critCount = findings.filter(f => f.severity === "critical").length;
    const highCount = findings.filter(f => f.severity === "high").length;
    const medCount = findings.filter(f => f.severity === "medium").length;
    const attackScore = Math.max(0, 100 - critCount * 15 - highCount * 8 - medCount * 3);

    surfaces.push({
      capability_name: tool.name,
      capability_id: `mcp_tool.${tool.name}`,
      vectors_evaluated: findings.length, // equals 24 — all vectors evaluated above
      findings,
      overall_attack_surface_score: attackScore,
    });

    const toolParams = migToolSchemaProperties(tool.inputSchema);

    const callerProducts: string[] = ms5Class === "ADMIN"
      ? ["Byolab", "BRIPe", "MIG-Admin"]
      : ms5Class === "EXECUTION"
        ? ["VendorGate", "BRIPe", "AI360", "BondsValuator", "RealValuator"]
        : ["VendorGate", "BRIPe", "BondsValuator", "RealValuator", "StockValuator"];

    const dependencies: string[] = toolParams.length > 0
      ? toolParams.filter(p => ["domain_id", "signal_id", "intent_id", "agent_id"].includes(p))
      : [];

    enrichedInventory.push({
      capability_name: tool.name,
      capability_id: `mcp_tool.${tool.name}`,
      classification: tool.classification,
      risk_level: classDef.risk_level,
      layer1_finding_count: 0,
      has_intent_contract: false,
      has_test_coverage: false,
      prompt_injection_risk: hasUnboundedInput(tool.description ?? ""),
      description: tool.description?.slice(0, 200),
      parameters: toolParams,
      permission_declarations: [classDef.approval_policy],
      execution_type: classDef.execution_policy,
      privilege_level: tool.classification as "read_only" | "execution" | "admin",
      ms5_class: ms5Class,
      attack_surface_findings: findings,
      caller_products: callerProducts,
      dependencies,
    });
  }

  return { surfaces, enrichedInventory };
}
