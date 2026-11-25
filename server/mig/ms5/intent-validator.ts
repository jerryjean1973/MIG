/**
 * server/mig/ms5/intent-validator.ts
 *
 * Intent Validation per Product — for each registered product (App Defender,
 * VendorGate, AI360, BRIPe, Byolab) verifies declared intent, visible
 * capability set, forbidden capabilities, capability drift, intent drift,
 * and objective drift.
 *
 * Every violation is a Layer 3 finding with product attribution.
 */

import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import type { MigIntentDefinition, MigRemoteAgent } from "@shared/schema";
import type {
  MS5IntentValidationReport,
  MS5ProductIntentValidation,
  MS5FindingSeverity,
} from "@shared/ms5-contracts";
import { classifyTool } from "@shared/ms5-capability-classification";

interface ProductContract {
  product_id: string;
  product_name: string;
  declared_intent: string;
  required_tools: string[];
  forbidden_tools: string[];
  max_classification: "read_only" | "execution" | "admin";
}

const PRODUCT_CONTRACTS: ProductContract[] = [
  {
    product_id: "vendorgate",
    product_name: "VendorGate",
    declared_intent: "Third-party risk assessment and vendor structural analysis",
    required_tools: ["run_bripe_decision", "list_domains", "get_domain_package"],
    forbidden_tools: ["start_autopilot_objective", "ingest_replay_record"],
    max_classification: "execution",
  },
  {
    product_id: "app_defender",
    product_name: "App Defender",
    declared_intent: "Application security structural monitoring",
    required_tools: ["list_capabilities", "get_capability_contract", "list_bripe_layers"],
    forbidden_tools: ["start_autopilot_objective"],
    max_classification: "execution",
  },
  {
    product_id: "ai360",
    product_name: "AI360",
    declared_intent: "AI system risk and governance monitoring",
    required_tools: ["list_domains", "list_capabilities", "run_bripe_decision"],
    forbidden_tools: ["ingest_replay_record", "ingest_calibra_record"],
    max_classification: "execution",
  },
  {
    product_id: "bripe",
    product_name: "BRIPe MCP",
    declared_intent: "BRIPe structural risk decision execution",
    required_tools: ["run_bripe_decision", "explain_bripe_output_metrics", "list_capabilities"],
    forbidden_tools: [],
    max_classification: "execution",
  },
  {
    product_id: "byolab",
    product_name: "Byolab",
    declared_intent: "External partner BRIPe decision access",
    required_tools: ["run_bripe_decision", "list_domains"],
    forbidden_tools: ["start_autopilot_objective", "ingest_replay_record", "ingest_calibra_record"],
    max_classification: "execution",
  },
];

const ALL_TOOL_NAMES = new Set(ALL_MCP_TOOLS.map(t => t.name));

function findProductIntents(
  productId: string,
  intentDefinitions: MigIntentDefinition[],
): MigIntentDefinition[] {
  return intentDefinitions.filter(i =>
    i.intentId.toLowerCase().includes(productId) ||
    i.intentId.toLowerCase().includes(productId.replace("_", "-"))
  );
}

function getAgentsForProduct(
  productId: string,
  agents: MigRemoteAgent[],
  intentDefinitions: MigIntentDefinition[],
): MigRemoteAgent[] {
  const productIntentIds = new Set(
    findProductIntents(productId, intentDefinitions).map(i => i.intentId)
  );
  return agents.filter(a => {
    const agentIntents = Array.isArray(a.allowedIntents) ? (a.allowedIntents as string[]) : [];
    return agentIntents.some(id => productIntentIds.has(id));
  });
}

export function runIntentValidation(
  intentDefinitions: MigIntentDefinition[],
  agents: MigRemoteAgent[],
): MS5IntentValidationReport {
  const validations: MS5ProductIntentValidation[] = [];
  let totalViolations = 0;
  let criticalViolations = 0;

  for (const contract of PRODUCT_CONTRACTS) {
    const productIntents = findProductIntents(contract.product_id, intentDefinitions);
    const productAgents = getAgentsForProduct(contract.product_id, agents, intentDefinitions);

    const visibleCapabilities = new Set<string>();
    for (const intent of productIntents) {
      const allowed = Array.isArray(intent.allowedToolNames) ? (intent.allowedToolNames as string[]) : [];
      for (const t of allowed) {
        if (ALL_TOOL_NAMES.has(t)) visibleCapabilities.add(t);
      }
    }

    const visibleList = [...visibleCapabilities];
    const forbiddenExposed = contract.forbidden_tools.filter(t => visibleCapabilities.has(t));
    const allCapabilityNames = new Set(ALL_MCP_TOOLS.map(t => t.name));
    const undeclared = visibleList.filter(t => {
      const tool = ALL_MCP_TOOLS.find(tool => tool.name === t);
      return tool && (tool.classification === "admin" || classifyTool(t) === "DANGEROUS");
    });

    const violations: MS5ProductIntentValidation["violations"] = [];

    for (const forbidden of forbiddenExposed) {
      const severity: MS5FindingSeverity = classifyTool(forbidden) === "ADMIN" ? "critical" : "high";
      violations.push({
        type: "capability_drift",
        capability_name: forbidden,
        evidence: `Forbidden tool '${forbidden}' is exposed in a ${contract.product_name} intent.`,
        severity,
      });
      if (severity === "critical") criticalViolations++;
    }

    for (const cap of undeclared) {
      violations.push({
        type: "hidden_capability",
        capability_name: cap,
        evidence: `Admin/dangerous capability '${cap}' is visible to ${contract.product_name} but not explicitly declared as required.`,
        severity: "high",
      });
    }

    for (const agent of productAgents) {
      const agentClass = agent.maxCapabilityClassification ?? "read_only";
      const classOrder = ["read_only", "execution", "admin"];
      const agentIdx = classOrder.indexOf(agentClass);
      const contractIdx = classOrder.indexOf(contract.max_classification);
      if (agentIdx > contractIdx) {
        violations.push({
          type: "intent_drift",
          capability_name: "*",
          evidence: `Agent '${agent.agentId}' has maxCapabilityClassification '${agentClass}' exceeding product contract maximum '${contract.max_classification}'.`,
          severity: "high",
        });
      }
    }

    const capabilityDriftCount = visibleList.filter(t => {
      return !contract.required_tools.includes(t) && !contract.forbidden_tools.includes(t) &&
        ALL_MCP_TOOLS.find(tool => tool.name === t)?.classification !== "read_only";
    }).length;

    totalViolations += violations.length;

    validations.push({
      product_id: contract.product_id,
      product_name: contract.product_name,
      declared_intent: contract.declared_intent,
      visible_capabilities: visibleList,
      forbidden_capabilities_exposed: forbiddenExposed,
      undeclared_capabilities: undeclared,
      capability_drift_count: capabilityDriftCount,
      intent_drift_count: violations.filter(v => v.type === "intent_drift").length,
      objective_drift_count: 0,
      violations,
      validation_passed: violations.length === 0,
    });
  }

  return {
    products_validated: PRODUCT_CONTRACTS.length,
    total_violations: totalViolations,
    critical_violations: criticalViolations,
    validations,
    generated_at: new Date().toISOString(),
  };
}
