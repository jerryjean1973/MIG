/**
 * server/mig/ms5/ms5-governance-contracts.ts
 *
 * MS5 Governance Contracts — derived from the canonical MIG adapter tool groups.
 *
 * PRODUCT INTENT CONTRACTS
 *   Each registered product surface in BCentrisk has a declared capability contract:
 *   which tool groups are authorised, which are forbidden. These are derived from
 *   BRIPE_*_TOOL_NAMES exports — never independently maintained lists.
 *
 * CAPABILITY VIEW CONTRACTS
 *   The six standard agent views (External, Read-Only, Product, Automation, Operator,
 *   Administrator) each map to a maxCapabilityClassification ceiling and a narrow set
 *   of allowed tool groups. Derived from the classification ordering in mig-policy-graph.
 *
 * Layer 3 imports from here so that any change to mig-bripe-adapter.ts automatically
 * propagates to the governance checks without manual sync.
 *
 * CEO INTEGRATION (Canonical Enterprise Ontology — CEO v1.0.0)
 *   OntologyBoundCapabilityContract replaces ungoverned string labels for MIG capability
 *   contracts when ontology admission is in effect. The reference implementation is:
 *   `shared/enterprise-ontology/contract-ontology.ts#validateCapabilityContract`.
 *
 *   To integrate for a product:
 *   1. Resolve the canonical_capability_id from admitted CEO objects (EnterpriseObjectType.Capability).
 *   2. Construct an OntologyBoundCapabilityContract with the resolved ID + current CEO version.
 *   3. Call validateCapabilityContract() with the runtime context (admitted_capability_ids, region, etc.).
 *   4. MIG fails CLOSED if the contract is denied (overall_decision !== "permit").
 *
 *   See: shared/enterprise-ontology/contract-ontology.ts
 */

import {
  BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES,
  BRIPE_DISCOVERY_TOOL_NAMES,
  BRIPE_EXECUTION_TOOL_NAMES,
} from "../../mig/mig-bripe-adapter";

// ─── Product intent contracts ────────────────────────────────────────────────
// Each entry declares which tool groups the product MUST have (required) and
// which it MUST NOT have (forbidden). Tool group membership is sourced from
// the canonical bripe-adapter exports, not from inline literals.

export interface ProductIntentContract {
  product_id: string;
  display_name: string;
  required_tool_groups: string[];
  forbidden_tool_groups: string[];
  /** Tool names the product requires to be covered by at least one intent. */
  required_tools: string[];
  /** Tool names the product must never expose in any intent. */
  forbidden_tools: string[];
  max_classification: "read_only" | "execution" | "admin";
}

export function buildProductIntentContracts(): ProductIntentContract[] {
  return [
    {
      product_id: "vendorgate",
      display_name: "VendorGate",
      required_tool_groups: ["discovery", "execution"],
      forbidden_tool_groups: ["admin"],
      required_tools: BRIPE_DISCOVERY_TOOL_NAMES,
      forbidden_tools: [],
      max_classification: "execution",
    },
    {
      product_id: "app_defender",
      display_name: "App Defender",
      required_tool_groups: ["domain_discovery"],
      forbidden_tool_groups: ["execution", "admin"],
      required_tools: BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES,
      forbidden_tools: BRIPE_EXECUTION_TOOL_NAMES,
      max_classification: "read_only",
    },
    {
      product_id: "bripe_mcp",
      display_name: "BRIPe MCP (External)",
      required_tool_groups: ["discovery", "execution"],
      forbidden_tool_groups: ["admin"],
      required_tools: [...BRIPE_DISCOVERY_TOOL_NAMES, ...BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES],
      forbidden_tools: [],
      max_classification: "execution",
    },
    {
      product_id: "ai360",
      display_name: "AI360",
      required_tool_groups: ["domain_discovery", "discovery"],
      forbidden_tool_groups: ["admin"],
      required_tools: BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES,
      forbidden_tools: [],
      max_classification: "execution",
    },
    {
      product_id: "byolab",
      display_name: "Byolab (Partner Execution)",
      required_tool_groups: ["discovery", "execution"],
      forbidden_tool_groups: ["admin"],
      required_tools: BRIPE_EXECUTION_TOOL_NAMES,
      forbidden_tools: [],
      max_classification: "execution",
    },
  ];
}

// ─── Capability view contracts ────────────────────────────────────────────────
// The six standard agent views map a view tier to:
//   - the max classification ceiling for that view
//   - which tool groups are permitted vs forbidden
// Derived from the 3-tier classification ordering in mig-policy-graph
// (read_only < execution < admin).

export interface CapabilityViewContract {
  view_name: string;
  max_classification: "read_only" | "execution" | "admin";
  allowed_tool_groups: string[];
  forbidden_tool_groups: string[];
  /** Minimum required tool set for this view to be considered functional. */
  min_required_tools: string[];
  /** Tool names that must never appear for this view. */
  hard_forbidden_tools: string[];
}

export function buildCapabilityViewContracts(): CapabilityViewContract[] {
  return [
    {
      view_name: "External",
      max_classification: "read_only",
      allowed_tool_groups: ["domain_discovery"],
      forbidden_tool_groups: ["discovery", "execution", "admin"],
      min_required_tools: [],
      hard_forbidden_tools: BRIPE_EXECUTION_TOOL_NAMES,
    },
    {
      view_name: "Read-Only",
      max_classification: "read_only",
      allowed_tool_groups: ["domain_discovery", "discovery"],
      forbidden_tool_groups: ["execution", "admin"],
      min_required_tools: BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES,
      hard_forbidden_tools: BRIPE_EXECUTION_TOOL_NAMES,
    },
    {
      view_name: "Product",
      max_classification: "execution",
      allowed_tool_groups: ["domain_discovery", "discovery", "execution"],
      forbidden_tool_groups: ["admin"],
      min_required_tools: BRIPE_DISCOVERY_TOOL_NAMES,
      hard_forbidden_tools: [],
    },
    {
      view_name: "Automation",
      max_classification: "execution",
      allowed_tool_groups: ["domain_discovery", "discovery", "execution"],
      forbidden_tool_groups: ["admin"],
      min_required_tools: BRIPE_EXECUTION_TOOL_NAMES,
      hard_forbidden_tools: [],
    },
    {
      view_name: "Operator",
      max_classification: "admin",
      allowed_tool_groups: ["domain_discovery", "discovery", "execution"],
      forbidden_tool_groups: [],
      min_required_tools: [],
      hard_forbidden_tools: [],
    },
    {
      view_name: "Administrator",
      max_classification: "admin",
      allowed_tool_groups: ["domain_discovery", "discovery", "execution", "admin"],
      forbidden_tool_groups: [],
      min_required_tools: [],
      hard_forbidden_tools: [],
    },
  ];
}

/**
 * Resolves which capability view tier best matches an agent's maxCapabilityClassification
 * and declared tool set. Returns the canonical view name.
 */
export function resolveAgentViewTier(
  maxClass: string,
  toolNames: string[],
): string {
  if (maxClass === "admin") return "Operator";
  if (maxClass === "execution") {
    const hasExecution = toolNames.some(n => BRIPE_EXECUTION_TOOL_NAMES.includes(n));
    return hasExecution ? "Automation" : "Product";
  }
  const hasDiscovery = toolNames.some(n => BRIPE_DISCOVERY_TOOL_NAMES.includes(n));
  return hasDiscovery ? "Read-Only" : "External";
}
