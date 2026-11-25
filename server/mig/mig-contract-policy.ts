/**
 * server/mig/mig-contract-policy.ts
 *
 * MIG Negotiation Policy Validator — enforces 16 rejection conditions before any
 * proposal advances in the negotiation lifecycle. Returns a typed MigContractPolicyResult
 * with allowed | rejected and a list of findings.
 *
 * Integrates with the existing mig-core.ts authorizeExecution flow — does NOT replace it.
 */

import type {
  MCPCapabilityContract,
  MigContractPolicyResult,
  MigContractPolicyFinding,
  ContractAuthorizationBlock,
  ContractConstraintsBlock,
  TermNegotiability,
} from "../../shared/protocol/shared/mcp-contract-types";

export interface TenantPolicy {
  allowedRegions?: string[];
  prohibitedRegions?: string[];
  maxRateLimit?: number;
  maxExecutionTimeMs?: number;
  requireMigAttestation?: boolean;
  minConfidenceThreshold?: number;
  allowedClassifications?: string[];
  sovereigntyFrameworks?: string[];
}

export interface CapabilityRegistryEntry {
  capability_id: string;
  capability_name: string;
  classification: string;
  eligible_domains: readonly string[];
}

/**
 * validateNegotiationProposal — enforces 16 MIG rejection conditions.
 *
 * Rejection conditions:
 *  1.  Proposal weakens governance terms (mig_attestation_required → false)
 *  2.  Proposal expands privilege classification beyond server ceiling
 *  3.  Proposal requests sovereignty/residency regions outside tenant policy
 *  4.  Proposal prohibits a region required by tenant policy
 *  5.  Proposal allows cross-border transfer when tenant prohibits it
 *  6.  Proposal removes required regulatory frameworks
 *  7.  Proposal sets rate_limit above server maximum
 *  8.  Proposal sets execution_time above server maximum
 *  9.  Proposal sets confidence threshold below tenant minimum
 * 10.  Proposal marks server_mandatory terms as negotiable
 * 11.  Proposal marks policy_mandatory terms as negotiable
 * 12.  Proposal removes required examples
 * 13.  Proposal requests capability_id outside registered capability set
 * 14.  Proposal changes tenant_id or client_id fields
 * 15.  Proposal sets validUntil beyond server maximum (10 years)
 * 16.  Proposal modifies contractId or serverIdentity
 */
export function validateNegotiationProposal(
  proposal: Partial<MCPCapabilityContract>,
  capabilityRegistry: CapabilityRegistryEntry | null,
  tenantPolicy: TenantPolicy,
): MigContractPolicyResult {
  const findings: MigContractPolicyFinding[] = [];

  // ── Condition 1: Governance weakening ─────────────────────────────────────
  if (proposal.authorization?.mig_attestation_required === false) {
    findings.push({
      code: "NEGOTIATION_GOVERNANCE_WEAKENING",
      message: "Proposal sets mig_attestation_required=false — MIG attestation is server_mandatory and cannot be removed.",
      severity: "error",
      field: "authorization.mig_attestation_required",
    });
  }

  // ── Condition 2: Privilege expansion ──────────────────────────────────────
  if (proposal.authorization?.required_classification) {
    const rank: Record<string, number> = { read_only: 0, execution: 1, admin: 2 };
    const serverCeiling = capabilityRegistry?.classification ?? "read_only";
    const proposed = proposal.authorization.required_classification;
    if ((rank[proposed] ?? 0) > (rank[serverCeiling] ?? 0)) {
      findings.push({
        code: "NEGOTIATION_PRIVILEGE_EXPANSION",
        message: `Proposal requests classification "${proposed}" which exceeds server capability ceiling "${serverCeiling}".`,
        severity: "error",
        field: "authorization.required_classification",
      });
    }
  }

  // ── Condition 3: Sovereignty — disallowed regions ─────────────────────────
  if (proposal.constraints?.sovereignty?.data_residency_regions && tenantPolicy.allowedRegions) {
    const disallowed = proposal.constraints.sovereignty.data_residency_regions.filter(
      r => !tenantPolicy.allowedRegions!.includes(r),
    );
    if (disallowed.length > 0) {
      findings.push({
        code: "NEGOTIATION_SOVEREIGNTY_VIOLATION",
        message: `Proposed data residency regions not in tenant policy: ${disallowed.join(", ")}`,
        severity: "error",
        field: "constraints.sovereignty.data_residency_regions",
      });
    }
  }

  // ── Condition 4: Prohibited regions ───────────────────────────────────────
  if (proposal.constraints?.sovereignty?.data_residency_regions && tenantPolicy.prohibitedRegions) {
    const prohibited = proposal.constraints.sovereignty.data_residency_regions.filter(
      r => tenantPolicy.prohibitedRegions!.includes(r),
    );
    if (prohibited.length > 0) {
      findings.push({
        code: "NEGOTIATION_SOVEREIGNTY_VIOLATION",
        message: `Proposed data residency includes prohibited regions: ${prohibited.join(", ")}`,
        severity: "error",
        field: "constraints.sovereignty.data_residency_regions",
      });
    }
  }

  // ── Condition 5: Cross-border transfer ───────────────────────────────────
  if (proposal.constraints?.sovereignty?.cross_border_transfer_allowed === true &&
      tenantPolicy.allowedRegions?.length === 1) {
    findings.push({
      code: "NEGOTIATION_RESIDENCY_VIOLATION",
      message: "Tenant policy restricts to a single region — cross-border transfer cannot be enabled.",
      severity: "error",
      field: "constraints.sovereignty.cross_border_transfer_allowed",
    });
  }

  // ── Condition 6: Regulatory framework removal ─────────────────────────────
  if (proposal.constraints?.sovereignty?.regulatory_frameworks && tenantPolicy.sovereigntyFrameworks) {
    const missing = tenantPolicy.sovereigntyFrameworks.filter(
      f => !proposal.constraints!.sovereignty.regulatory_frameworks.includes(f),
    );
    if (missing.length > 0) {
      findings.push({
        code: "NEGOTIATION_CONFIDENTIALITY_VIOLATION",
        message: `Proposal removes required regulatory frameworks: ${missing.join(", ")}`,
        severity: "error",
        field: "constraints.sovereignty.regulatory_frameworks",
      });
    }
  }

  // ── Condition 7: Rate limit too high ─────────────────────────────────────
  if (proposal.constraints?.rate_limits?.requests_per_minute !== undefined && tenantPolicy.maxRateLimit !== undefined) {
    if (proposal.constraints.rate_limits.requests_per_minute > tenantPolicy.maxRateLimit) {
      findings.push({
        code: "NEGOTIATION_PRIVILEGE_EXPANSION",
        message: `Proposed rate limit (${proposal.constraints.rate_limits.requests_per_minute}/min) exceeds tenant maximum (${tenantPolicy.maxRateLimit}/min).`,
        severity: "error",
        field: "constraints.rate_limits.requests_per_minute",
      });
    }
  }

  // ── Condition 8: Execution time too high ──────────────────────────────────
  if (proposal.constraints?.execution_limits?.max_execution_time_ms !== undefined &&
      tenantPolicy.maxExecutionTimeMs !== undefined) {
    if (proposal.constraints.execution_limits.max_execution_time_ms > tenantPolicy.maxExecutionTimeMs) {
      findings.push({
        code: "NEGOTIATION_PRIVILEGE_EXPANSION",
        message: `Proposed execution time (${proposal.constraints.execution_limits.max_execution_time_ms}ms) exceeds tenant maximum (${tenantPolicy.maxExecutionTimeMs}ms).`,
        severity: "error",
        field: "constraints.execution_limits.max_execution_time_ms",
      });
    }
  }

  // ── Condition 9: Confidence threshold too low ─────────────────────────────
  if (proposal.dataQuality?.confidence_threshold !== undefined && tenantPolicy.minConfidenceThreshold !== undefined) {
    if (proposal.dataQuality.confidence_threshold < tenantPolicy.minConfidenceThreshold) {
      findings.push({
        code: "NEGOTIATION_GOVERNANCE_WEAKENING",
        message: `Proposed confidence threshold (${proposal.dataQuality.confidence_threshold}) is below tenant minimum (${tenantPolicy.minConfidenceThreshold}).`,
        severity: "error",
        field: "dataQuality.confidence_threshold",
      });
    }
  }

  // ── Condition 10: server_mandatory terms changed ──────────────────────────
  checkNegotiabilityViolations(proposal, "server_mandatory", findings);

  // ── Condition 11: policy_mandatory terms changed ──────────────────────────
  checkNegotiabilityViolations(proposal, "policy_mandatory", findings);

  // ── Condition 12: Required examples count < 9 ────────────────────────────
  if (Array.isArray(proposal.examples) && proposal.examples.length < 9) {
    findings.push({
      code: "NEGOTIATION_GOVERNANCE_WEAKENING",
      message: `Contract must include at least 9 examples; proposal provides ${proposal.examples.length}.`,
      severity: "error",
      field: "examples",
    });
  }

  // ── Condition 13: capabilityId mismatch ───────────────────────────────────
  if (capabilityRegistry && proposal.capabilityId && proposal.capabilityId !== capabilityRegistry.capability_id) {
    findings.push({
      code: "NEGOTIATION_ELIGIBILITY_DENIED",
      message: `Proposal capability_id "${proposal.capabilityId}" does not match registered capability "${capabilityRegistry.capability_id}".`,
      severity: "error",
      field: "capabilityId",
    });
  }

  // ── Condition 14: tenantId / clientId cannot be changed ──────────────────
  // (checked at route layer via original negotiation session — warning here)
  if (proposal.tenantId !== undefined) {
    findings.push({
      code: "NEGOTIATION_GOVERNANCE_WEAKENING",
      message: "tenantId cannot be changed via negotiation.",
      severity: "error",
      field: "tenantId",
    });
  }

  // ── Condition 15: validUntil too far ─────────────────────────────────────
  if (proposal.validUntil) {
    const maxFuture = new Date();
    maxFuture.setFullYear(maxFuture.getFullYear() + 10);
    if (new Date(proposal.validUntil) > maxFuture) {
      findings.push({
        code: "NEGOTIATION_PRIVILEGE_EXPANSION",
        message: "Proposed validUntil exceeds maximum allowed contract duration (10 years).",
        severity: "error",
        field: "validUntil",
      });
    }
  }

  // ── Condition 16: contractId / serverIdentity immutable ──────────────────
  if (proposal.contractId !== undefined || proposal.serverIdentity !== undefined) {
    findings.push({
      code: "NEGOTIATION_GOVERNANCE_WEAKENING",
      message: "contractId and serverIdentity are server_mandatory and cannot be changed by a client proposal.",
      severity: "error",
      field: "contractId",
    });
  }

  const errorCount = findings.filter(f => f.severity === "error").length;
  return {
    allowed: errorCount === 0,
    findings,
    attestationEligible: errorCount === 0,
  };
}

function checkNegotiabilityViolations(
  proposal: Partial<MCPCapabilityContract>,
  negotiability: TermNegotiability,
  findings: MigContractPolicyFinding[],
): void {
  const checkBlock = (block: Record<string, unknown> | undefined, path: string) => {
    if (!block) return;
    if (block.negotiability === negotiability) {
      findings.push({
        code: "NEGOTIATION_GOVERNANCE_WEAKENING",
        message: `Term at "${path}" is tagged "${negotiability}" and cannot be changed via negotiation.`,
        severity: "error",
        field: path,
      });
    }
  };

  checkBlock(proposal.authorization as any, "authorization");
  checkBlock(proposal.requestContract as any, "requestContract");
  checkBlock(proposal.errorsAndPartialResults as any, "errorsAndPartialResults");
}


/**
 * validateAcceptedContractForAttestation — validates a mutually-accepted contract
 * for MIG attestation issuance.
 *
 * This is DISTINCT from validateNegotiationProposal(), which validates a *delta*
 * (what the client wants to change). An accepted contract already has all mandatory
 * blocks in their correct server-issued form — checking their negotiability tag would
 * always flag them, even though they are unchanged from the server offer.
 *
 * This validator only enforces invariants applicable to the full accepted contract:
 *  - governance must not have been weakened (mig_attestation_required must be true)
 *  - classification must not exceed server capability ceiling
 *  - sovereignty constraints must be within tenant policy
 *  - confidence threshold must meet the tenant minimum
 *  - contractId / serverIdentity must be present and non-empty
 *  - validUntil must not exceed 10 years
 *  - capabilityId must match the registry entry
 *
 * Conditions 10/11 (negotiability tag checks) are intentionally excluded — they
 * apply to proposals (deltas), not to the complete accepted contract.
 */
export function validateAcceptedContractForAttestation(
  contract: MCPCapabilityContract,
  capabilityRegistry: CapabilityRegistryEntry | null,
  tenantPolicy: TenantPolicy,
): MigContractPolicyResult {
  const findings: MigContractPolicyFinding[] = [];

  // Governance: mig_attestation_required must remain true
  if (contract.authorization?.mig_attestation_required === false) {
    findings.push({
      code: "NEGOTIATION_GOVERNANCE_WEAKENING",
      message: "Accepted contract has mig_attestation_required=false — MIG attestation is mandatory.",
      severity: "error",
      field: "authorization.mig_attestation_required",
    });
  }

  // Classification ceiling
  if (contract.authorization?.required_classification && capabilityRegistry) {
    const rank: Record<string, number> = { read_only: 0, execution: 1, admin: 2 };
    const serverCeiling = capabilityRegistry.classification ?? "read_only";
    const accepted = contract.authorization.required_classification;
    if ((rank[accepted] ?? 0) > (rank[serverCeiling] ?? 0)) {
      findings.push({
        code: "NEGOTIATION_PRIVILEGE_EXPANSION",
        message: `Accepted contract classification "${accepted}" exceeds server capability ceiling "${serverCeiling}".`,
        severity: "error",
        field: "authorization.required_classification",
      });
    }
  }

  // Sovereignty: allowed regions
  if (contract.constraints?.sovereignty?.data_residency_regions && tenantPolicy.allowedRegions) {
    const disallowed = contract.constraints.sovereignty.data_residency_regions.filter(
      r => !tenantPolicy.allowedRegions!.includes(r),
    );
    if (disallowed.length > 0) {
      findings.push({
        code: "NEGOTIATION_SOVEREIGNTY_VIOLATION",
        message: `Accepted contract contains data residency regions outside tenant policy: ${disallowed.join(", ")}`,
        severity: "error",
        field: "constraints.sovereignty.data_residency_regions",
      });
    }
  }

  // Confidence threshold
  if (contract.dataQuality?.confidence_threshold !== undefined && tenantPolicy.minConfidenceThreshold !== undefined) {
    if (contract.dataQuality.confidence_threshold < tenantPolicy.minConfidenceThreshold) {
      findings.push({
        code: "NEGOTIATION_GOVERNANCE_WEAKENING",
        message: `Accepted contract confidence threshold (${contract.dataQuality.confidence_threshold}) is below tenant minimum.`,
        severity: "error",
        field: "dataQuality.confidence_threshold",
      });
    }
  }

  // validUntil within 10 years
  if (contract.validUntil) {
    const maxFuture = new Date();
    maxFuture.setFullYear(maxFuture.getFullYear() + 10);
    if (new Date(contract.validUntil) > maxFuture) {
      findings.push({
        code: "NEGOTIATION_PRIVILEGE_EXPANSION",
        message: "Accepted contract validUntil exceeds maximum allowed duration (10 years).",
        severity: "error",
        field: "validUntil",
      });
    }
  }

  // contractId and serverIdentity must be present
  if (!contract.contractId || !contract.serverIdentity) {
    findings.push({
      code: "NEGOTIATION_GOVERNANCE_WEAKENING",
      message: "Accepted contract is missing contractId or serverIdentity — attestation refused.",
      severity: "error",
      field: "contractId",
    });
  }

  // capabilityId consistency
  if (capabilityRegistry && contract.capabilityId && contract.capabilityId !== capabilityRegistry.capability_id) {
    findings.push({
      code: "NEGOTIATION_ELIGIBILITY_DENIED",
      message: `Contract capabilityId "${contract.capabilityId}" does not match registry entry "${capabilityRegistry.capability_id}".`,
      severity: "error",
      field: "capabilityId",
    });
  }

  const errorCount = findings.filter(f => f.severity === "error").length;
  return {
    allowed: errorCount === 0,
    findings,
    attestationEligible: errorCount === 0,
  };
}
