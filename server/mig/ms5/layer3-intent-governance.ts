/**
 * server/mig/ms5/layer3-intent-governance.ts
 *
 * MS5 Layer 3 — Intent Governance
 *
 * Four detection passes:
 *
 *  Pass A — Intent coverage
 *    Which tools have no intent contract at all? Non-read-only tools without any
 *    intent coverage create ungoverned execution paths.
 *
 *  Pass B — Agent × intent policy escalation (authoritative resolvePolicy path)
 *    For each agent bound to an intent, does resolvePolicy grant a tool whose
 *    classification exceeds the agent's maxCapabilityClassification?
 *    Uses resolvePolicy + classificationAllowedForAgent from mig-policy-graph.ts.
 *
 *  Pass C — Per-product intent contract validation (Step 8)
 *    Each known product (VendorGate, App Defender, BRIPe MCP, AI360, Byolab) has a
 *    declared required/forbidden tool set. Agents bound to product intents are
 *    checked against the product contract. Tool sets sourced from mig-bripe-adapter
 *    exports via ms5-governance-contracts.ts — never inline literals.
 *
 *  Pass D — Capability-view minimization (Step 8)
 *    Each standard view tier (External / Read-Only / Product / Automation / Operator /
 *    Administrator) has a forbidden tool group. Agents whose resolved view tier
 *    exposes tools from the forbidden group are flagged.
 *    View contracts sourced from ms5-governance-contracts.ts.
 */

import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import type { MigIntentDefinition, MigRemoteAgent } from "@shared/schema";
import type { MS5Finding, MS5LayerResult } from "@shared/ms5-contracts";
import { scoreToGrade } from "@shared/ms5-contracts";
import {
  BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES,
  BRIPE_EXECUTION_TOOL_NAMES,
} from "../../mig/mig-bripe-adapter";
import { resolvePolicy, classificationAllowedForAgent } from "../../mig/mig-policy-graph";
import {
  buildProductIntentContracts,
  buildCapabilityViewContracts,
  resolveAgentViewTier,
} from "./ms5-governance-contracts";
import { randomBytes } from "crypto";

function makeId(): string {
  return `f3_${randomBytes(6).toString("hex")}`;
}

export interface Layer3Result {
  layer_result: MS5LayerResult;
  intent_coverage_percentage: number;
}

export function runLayer3IntentGovernance(
  intentDefinitions: MigIntentDefinition[],
  agents: MigRemoteAgent[] = [],
): Layer3Result {
  const findings: MS5Finding[] = [];
  const allToolNames = new Set(ALL_MCP_TOOLS.map(t => t.name));

  // ── Pass A: Intent coverage ───────────────────────────────────────────────
  // Which non-read-only tools have no intent contract at all?
  const coveredByIntent = new Set<string>();
  for (const intent of intentDefinitions) {
    const allowed = Array.isArray(intent.allowedToolNames) ? (intent.allowedToolNames as string[]) : [];
    for (const name of allowed) {
      if (allToolNames.has(name)) coveredByIntent.add(name);
    }
  }

  const uncoveredTools = [...allToolNames].filter(n => !coveredByIntent.has(n));
  for (const toolName of uncoveredTools) {
    const tool = ALL_MCP_TOOLS.find(t => t.name === toolName);
    const classification = tool?.classification ?? "unknown";
    if (classification === "read_only") continue;

    findings.push({
      id: makeId(),
      layer: "layer3",
      severity: classification === "execution" ? "high" : "medium",
      category: "intent_drift",
      title: `Tool '${toolName}' is not declared in any intent contract`,
      evidence: `Tool exists in the MCP catalog (classification: ${classification}) but is absent from all intent allowedToolNames lists.`,
      recommendation: `Add this tool to an appropriate intent definition or create a new dedicated intent contract. Non-read-only tools without intent coverage create ungoverned execution paths.`,
      capability_name: toolName,
    });
  }

  // ── Pass B: Agent × intent policy escalation (authoritative resolvePolicy) ──
  for (const agent of agents) {
    const agentIntentIds = Array.isArray(agent.allowedIntents)
      ? (agent.allowedIntents as string[])
      : [];

    const boundIntents = agentIntentIds.length > 0
      ? intentDefinitions.filter(i => agentIntentIds.includes(i.intentId))
      : intentDefinitions;

    for (const intent of boundIntents) {
      const policy = resolvePolicy(agent, intent);
      for (const toolName of policy.allowed_tool_names) {
        const tool = ALL_MCP_TOOLS.find(t => t.name === toolName);
        if (!tool) continue;
        const toolClass = tool.classification as "read_only" | "execution" | "admin";
        if (!classificationAllowedForAgent(agent, toolClass)) {
          findings.push({
            id: makeId(),
            layer: "layer3",
            severity: toolClass === "admin" ? "critical" : "high",
            category: "capability_escalation",
            title: `Agent '${agent.agentId}' gains '${toolName}' (${toolClass}) above its maxCapabilityClassification`,
            evidence: `Agent max class: '${agent.maxCapabilityClassification}'. Intent '${intent.intentId}' resolves '${toolName}' (${toolClass}) for this agent, exceeding the agent's authorization ceiling.`,
            recommendation: `Either lower the tool classification in the intent, raise the agent's maxCapabilityClassification if the escalation is intentional, or scope the intent to exclude this agent.`,
            capability_name: toolName,
          });
        }
      }
    }
  }

  // ── Pass C: Per-product intent contract validation (Step 8) ───────────────
  // Each known product has a required/forbidden tool set derived from
  // mig-bripe-adapter exports. Agents whose allowedIntents contain a product
  // intent ID are checked against the product's contract.
  const productContracts = buildProductIntentContracts();
  for (const product of productContracts) {
    // Identify intents associated with this product (by intentId prefix or product tag).
    const productIntents = intentDefinitions.filter(i =>
      i.intentId.toLowerCase().includes(product.product_id.replace("_", "-")) ||
      i.intentId.toLowerCase().includes(product.product_id)
    );

    for (const intent of productIntents) {
      const allowed = Array.isArray(intent.allowedToolNames) ? (intent.allowedToolNames as string[]) : [];

      // Forbidden tools must never appear in this product's intent
      for (const forbiddenTool of product.forbidden_tools) {
        if (allowed.includes(forbiddenTool)) {
          findings.push({
            id: makeId(),
            layer: "layer3",
            severity: "high",
            category: "intent_drift",
            title: `Product '${product.display_name}': intent '${intent.intentId}' exposes forbidden tool '${forbiddenTool}'`,
            evidence: `The ${product.display_name} product contract (max_classification: ${product.max_classification}) forbids '${forbiddenTool}', but it appears in intent allowedToolNames.`,
            recommendation: `Remove '${forbiddenTool}' from intent '${intent.intentId}' to comply with the ${product.display_name} capability contract. Consider a separate elevated intent if execution is genuinely needed.`,
            capability_name: forbiddenTool,
          });
        }
      }

      // Required tool groups must be covered
      const missingRequired = product.required_tools.filter(
        rt => !allowed.includes(rt) && allToolNames.has(rt)
      );
      if (missingRequired.length > 0 && product.required_tools.length > 0) {
        const missingFraction = missingRequired.length / product.required_tools.length;
        if (missingFraction > 0.5) {
          findings.push({
            id: makeId(),
            layer: "layer3",
            severity: "medium",
            category: "intent_drift",
            title: `Product '${product.display_name}': intent '${intent.intentId}' covers only ${product.required_tools.length - missingRequired.length}/${product.required_tools.length} required tools`,
            evidence: `Missing: ${missingRequired.slice(0, 5).join(", ")}${missingRequired.length > 5 ? ` (+${missingRequired.length - 5} more)` : ""}. A ${product.display_name} intent is expected to cover its full required tool group.`,
            recommendation: `Extend the intent's allowedToolNames to cover the full ${product.display_name} tool group, or split into sub-intents per tool class.`,
          });
        }
      }
    }
  }

  // ── Pass D: Capability-view minimization checks ────────────────────────────
  // Each agent's view tier is resolved; then agents whose combined intent exposure
  // exceeds the view tier's hard_forbidden_tools list are flagged.
  const viewContracts = buildCapabilityViewContracts();

  for (const agent of agents) {
    const agentIntentIds = Array.isArray(agent.allowedIntents)
      ? (agent.allowedIntents as string[])
      : [];
    const agentBoundIntents = agentIntentIds.length > 0
      ? intentDefinitions.filter(i => agentIntentIds.includes(i.intentId))
      : intentDefinitions;

    // Collect all tools exposed to this agent across all bound intents
    const exposedToolNames = new Set<string>();
    for (const intent of agentBoundIntents) {
      const allowed = Array.isArray(intent.allowedToolNames) ? (intent.allowedToolNames as string[]) : [];
      for (const t of allowed) exposedToolNames.add(t);
    }

    const agentTools = [...exposedToolNames];
    const viewTierName = resolveAgentViewTier(
      agent.maxCapabilityClassification ?? "read_only",
      agentTools,
    );
    const viewContract = viewContracts.find(v => v.view_name === viewTierName);
    if (!viewContract) continue;

    for (const forbiddenTool of viewContract.hard_forbidden_tools) {
      if (exposedToolNames.has(forbiddenTool)) {
        findings.push({
          id: makeId(),
          layer: "layer3",
          severity: "high",
          category: "capability_escalation",
          title: `Agent '${agent.agentId}' (${viewTierName} view) exposes forbidden tool '${forbiddenTool}'`,
          evidence: `The ${viewTierName} view tier forbids '${forbiddenTool}'. This tool is exposed to the agent through one or more bound intents. View contracts are derived from the canonical classification tiers.`,
          recommendation: `Remove '${forbiddenTool}' from the agent's bound intents, or change the agent's maxCapabilityClassification to a tier that permits this tool.`,
          capability_name: forbiddenTool,
        });
      }
    }
  }

  // ── Intent status drift: non-active intents with tool assignments ──────────
  for (const intent of intentDefinitions) {
    const allowed = Array.isArray(intent.allowedToolNames) ? (intent.allowedToolNames as string[]) : [];
    const executionTools = allowed.filter(n => BRIPE_EXECUTION_TOOL_NAMES.includes(n));
    const discoveryTools = allowed.filter(n => BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES.includes(n));

    if (executionTools.length > 0 && discoveryTools.length > 0) {
      const execNotInDiscovery = executionTools.filter(e => !BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES.includes(e));
      if (execNotInDiscovery.length > 0) {
        findings.push({
          id: makeId(),
          layer: "layer3",
          severity: "medium",
          category: "capability_escalation",
          title: `Intent '${intent.intentId}' bundles discovery and execution capabilities`,
          evidence: `Intent exposes both discovery tools and execution tools (${execNotInDiscovery.join(", ")}). Mixed-class intents create escalation risk.`,
          recommendation: `Split into separate intents: one for discovery (read-only) and one for execution. This enforces least-privilege principle at the intent level.`,
        });
      }
    }

    if (intent.status !== "published" && intent.status !== "active" && allowed.length > 0) {
      findings.push({
        id: makeId(),
        layer: "layer3",
        severity: "medium",
        category: "intent_drift",
        title: `Intent '${intent.intentId}' is in status '${intent.status}' but has tool assignments`,
        evidence: `Non-active/published intent has ${allowed.length} tools in its allowedToolNames. Agents bound to this intent may hit unexpected denials.`,
        recommendation: `Publish or activate this intent, or remove tool assignments from a non-active intent to avoid governance confusion.`,
      });
    }
  }

  const totalTools = allToolNames.size;
  const intentCoveragePct = totalTools > 0 ? Math.round((coveredByIntent.size / totalTools) * 100) : 0;

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;

  const penaltyPerCritical = 10;
  const penaltyPerHigh = 5;
  const penaltyPerMedium = 2;
  const rawPenalty = criticalCount * penaltyPerCritical + highCount * penaltyPerHigh + mediumCount * penaltyPerMedium;

  const coverageBase = Math.min(intentCoveragePct, 100);
  const score = Math.max(0, coverageBase - rawPenalty);

  return {
    layer_result: {
      layer: "layer3",
      layer_name: "Intent Governance",
      score,
      max_score: 100,
      percentage: score,
      grade: scoreToGrade(score),
      findings,
      summary: `Intent coverage: ${intentCoveragePct}% (${coveredByIntent.size}/${totalTools} tools). Product contracts: ${productContracts.length} products validated. Found ${criticalCount} critical, ${highCount} high, ${mediumCount} medium issues. Score: ${score}/100.`,
      checked_at: new Date().toISOString(),
    },
    intent_coverage_percentage: intentCoveragePct,
  };
}
