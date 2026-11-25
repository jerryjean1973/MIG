/**
 * shared/enterprise-ontology/contract-ontology.ts
 *
 * Contract ontology types for the CEO package:
 *   - EnterpriseContractType: canonical categories of contracts
 *   - ImplicitEnterpriseContractCandidate: auto-detected patterns
 *   - OntologyBoundCapabilityContract: replaces ungoverned string labels in MIG
 *
 * Layer: Canonical Enterprise Ontology (shared/enterprise-ontology/)
 */
import type { ADAMInformationState } from "../protocol/shared/enterprise-ontology/information-states";

import type { RegulatedDataCategory } from "../protocol/shared/enterprise-ontology/data-classification";

export interface OntologyBoundCapabilityContract {
  contract_id: string;
  contract_version: string;
  /** Must resolve to an admitted EnterpriseObject of type "Capability". */
  canonical_capability_id: string;
  capability_name: string;
  ontology_version: string;
  classification: "read_only" | "execution" | "admin";
  authorization_conditions: AuthorizationCondition[];
  regulated_data_categories?: RegulatedDataCategory[];
  residency_requirement?: string;
  adam_state_required: ADAMInformationState;
  /** Whether MIG should fail closed when ontology version mismatches. */
  strict_version_gate: boolean;
  created_at: string;
  last_validated_at?: string;
  validation_status: "unvalidated" | "valid" | "version_mismatch" | "capability_missing" | "authorization_failed";
  /**
   * The MIG tool name this contract governs. When set, MIG's authorizeExecution()
   * resolves this contract for the matching tool_name and validates it before
   * the tool runs. MIG fails CLOSED on any validation failure.
   */
  governs_tool?: string;
}

export interface AuthorizationCondition {
  condition_id: string;
  condition_type: "intent_scope" | "risk_zone" | "governance_established" | "regulated_data_residency" | "custom";
  required_value: unknown;
  current_value?: unknown;
  satisfied?: boolean;
  failure_reason?: string;
}

export interface MIGContractValidationResult {
  contract_id: string;
  overall_decision: "permit" | "deny";
  denial_reason?: string;
  conditions_evaluated: AuthorizationCondition[];
  ontology_version_compatible: boolean;
  capability_admitted: boolean;
  residency_compliant: boolean;
  evaluated_at: string;
}

export function validateCapabilityContract(
  contract: OntologyBoundCapabilityContract,
  context: {
    admitted_capability_ids: Set<string>;
    current_ontology_version: string;
    /** Must be supplied when contract has regulated_data_categories + residency_requirement. */
    operation_region?: string;
    /** Agent's declared risk zone. Required to evaluate risk_zone conditions. */
    agent_risk_zone?: string;
    /** Agent's declared intent scope. Required to evaluate intent_scope conditions. */
    agent_intent_scope?: string;
    governance_established?: boolean;
  },
): MIGContractValidationResult {
  const evaluatedConditions: AuthorizationCondition[] = [];
  const denialReasons: string[] = [];

  // Gate 1: Capability must exist as admitted in the CEO
  const capabilityAdmitted = context.admitted_capability_ids.has(contract.canonical_capability_id);
  if (!capabilityAdmitted) {
    denialReasons.push(`capability_not_admitted:${contract.canonical_capability_id}`);
  }

  // Gate 2: Ontology major version must match (strict gate only)
  const capMajor = parseInt(contract.ontology_version.split(".")[0], 10);
  const currMajor = parseInt(context.current_ontology_version.split(".")[0], 10);
  const versionCompatible = capMajor === currMajor;
  if (!versionCompatible && contract.strict_version_gate) {
    denialReasons.push(`ontology_version_mismatch:contract=${contract.ontology_version},engine=${context.current_ontology_version}`);
  }

  // Gate 3: Residency enforcement — fail CLOSED when regulated data present.
  // If residency_requirement is declared but operation_region is not provided,
  // compliance CANNOT be asserted and the gate MUST deny.
  let residencyCompliant = true;
  if (contract.regulated_data_categories && contract.regulated_data_categories.length > 0) {
    if (contract.residency_requirement) {
      if (!context.operation_region) {
        residencyCompliant = false;
        denialReasons.push(
          `regulated_data_residency_unverifiable:required=${contract.residency_requirement},no_operation_region_in_context`,
        );
      } else if (contract.residency_requirement !== context.operation_region) {
        residencyCompliant = false;
        denialReasons.push(
          `regulated_data_residency_violation:required=${contract.residency_requirement},actual=${context.operation_region}`,
        );
      }
    }
  }

  // Gate 4: Authorization conditions — fail CLOSED on any unsatisfied or unevaluable condition.
  for (const condition of contract.authorization_conditions) {
    const evaluated: AuthorizationCondition = { ...condition };

    switch (condition.condition_type) {
      case "governance_established": {
        evaluated.satisfied = context.governance_established === true;
        if (!evaluated.satisfied) {
          evaluated.failure_reason = "governance_not_established";
          denialReasons.push("governance_not_established");
        }
        break;
      }

      case "risk_zone": {
        if (context.agent_risk_zone === undefined) {
          // Cannot evaluate without runtime context — fail closed
          evaluated.satisfied = false;
          evaluated.failure_reason = "risk_zone_not_provided_in_context";
          denialReasons.push("risk_zone_not_provided_in_context");
        } else {
          const required = condition.required_value as string | string[];
          const allowed = Array.isArray(required) ? required : [required];
          evaluated.current_value = context.agent_risk_zone;
          evaluated.satisfied = allowed.includes(context.agent_risk_zone);
          if (!evaluated.satisfied) {
            evaluated.failure_reason = `risk_zone_not_allowed:required=${allowed.join("|")},actual=${context.agent_risk_zone}`;
            denialReasons.push(evaluated.failure_reason);
          }
        }
        break;
      }

      case "intent_scope": {
        if (context.agent_intent_scope === undefined) {
          // Cannot evaluate without runtime context — fail closed
          evaluated.satisfied = false;
          evaluated.failure_reason = "intent_scope_not_provided_in_context";
          denialReasons.push("intent_scope_not_provided_in_context");
        } else {
          const required = condition.required_value as string;
          evaluated.current_value = context.agent_intent_scope;
          const actualScopes = Array.isArray(context.agent_intent_scope)
            ? context.agent_intent_scope
            : [context.agent_intent_scope];
          evaluated.satisfied = actualScopes.includes(required);
          if (!evaluated.satisfied) {
            evaluated.failure_reason = `intent_scope_mismatch:required=${required},actual=${context.agent_intent_scope}`;
            denialReasons.push(evaluated.failure_reason);
          }
        }
        break;
      }

      case "regulated_data_residency": {
        // Handled in Gate 3 above; mirror the residency result here
        evaluated.satisfied = residencyCompliant;
        if (!evaluated.satisfied) {
          evaluated.failure_reason = "see_regulated_data_residency_gate";
        }
        break;
      }

      case "custom": {
        // Custom conditions require an external evaluator that MIG does not have.
        // Fail CLOSED — never silently pass conditions that cannot be assessed.
        evaluated.satisfied = false;
        evaluated.failure_reason = "custom_condition_unevaluable_at_runtime:register_evaluator_or_remove_condition";
        denialReasons.push("custom_condition_cannot_be_evaluated_at_runtime");
        break;
      }

      default: {
        // Unknown condition type — fail CLOSED; do not pass what cannot be evaluated.
        evaluated.satisfied = false;
        evaluated.failure_reason = `unknown_condition_type:${condition.condition_type}`;
        denialReasons.push(`unknown_condition_type_denied:${condition.condition_type}`);
        break;
      }
    }

    evaluatedConditions.push(evaluated);
  }

  const overallDenied = denialReasons.length > 0;

  return {
    contract_id: contract.contract_id,
    overall_decision: overallDenied ? "deny" : "permit",
    denial_reason: overallDenied ? denialReasons.join("; ") : undefined,
    conditions_evaluated: evaluatedConditions,
    ontology_version_compatible: versionCompatible,
    capability_admitted: capabilityAdmitted,
    residency_compliant: residencyCompliant,
    evaluated_at: new Date().toISOString(),
  };
}
