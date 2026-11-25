/**
 * server/mig/ms5/ms5-certification-engine.ts
 *
 * Certification State Engine — derives a formal certification verdict from
 * an MS5Report's overall score, critical-finding count, and DANGEROUS-class
 * capability flags.
 *
 * States:
 *   CERTIFIED            — score ≥ 90, 0 critical, 0 blocked caps
 *   CERTIFIED_WITH_WARNINGS — score ≥ 75, ≤ 2 critical, 0 blocked caps
 *   CONDITIONAL          — score ≥ 60, ≤ 5 critical, 0 DANGEROUS-blocked caps
 *   FAILED               — score < 60 or > 5 critical findings
 *   BLOCKED              — any DANGEROUS-class capability without full Layer 3
 *                          intent coverage → hard block, no production promotion
 *
 * Production-promotion gate: only CERTIFIED and CERTIFIED_WITH_WARNINGS
 * may proceed. All others return a hard block with reason.
 */

import type { MS5Report, MS5CertificationResult, MS5CertificationState } from "@shared/ms5-contracts";
import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { classifyTool } from "@shared/ms5-capability-classification";

function dangersousCapabilitiesWithoutIntentCoverage(report: MS5Report): string[] {
  const dangerous = ALL_MCP_TOOLS
    .filter(t => classifyTool(t.name) === "DANGEROUS")
    .map(t => t.name);

  const inventoryMap = new Map(
    (report.capability_inventory ?? []).map(c => [c.capability_name, c])
  );

  return dangerous.filter(name => {
    const inv = inventoryMap.get(name);
    return !inv || !inv.has_intent_contract;
  });
}

export function computeCertificationState(report: MS5Report): MS5CertificationResult {
  const score = report.overall_score;
  const allFindings = report.findings ?? [];
  const criticalCount = allFindings.filter(f => f.severity === "critical").length;
  const blockedCaps = dangersousCapabilitiesWithoutIntentCoverage(report);
  const blockingFactors: string[] = [];
  const warningFactors: string[] = [];

  if (blockedCaps.length > 0) {
    blockingFactors.push(
      `${blockedCaps.length} DANGEROUS-class capability(ies) without full Layer 3 intent coverage: ${blockedCaps.slice(0, 3).join(", ")}${blockedCaps.length > 3 ? " …" : ""}`
    );
  }

  if (score < 60) {
    blockingFactors.push(`Overall score ${score}/100 is below the minimum threshold of 60.`);
  }

  if (criticalCount > 5) {
    blockingFactors.push(`${criticalCount} critical findings exceed the FAILED threshold of 5.`);
  }

  if (criticalCount > 2 && criticalCount <= 5 && score >= 60) {
    warningFactors.push(`${criticalCount} critical findings present (threshold for CERTIFIED_WITH_WARNINGS: ≤2).`);
  }

  const highCount = allFindings.filter(f => f.severity === "high").length;
  if (highCount > 5) {
    warningFactors.push(`${highCount} high-severity findings present.`);
  }

  const layer3Score = (report.scorecard as any)?.layer_scores?.layer3 ?? 100;
  if (layer3Score < 70) {
    warningFactors.push(`Layer 3 (Intent Governance) score ${layer3Score}/100 is below 70.`);
  }

  let state: MS5CertificationState;
  let verdictReason: string;

  if (blockedCaps.length > 0) {
    state = "BLOCKED";
    verdictReason = `Hard block: ${blockedCaps.length} DANGEROUS capability(ies) lack full intent coverage. No production promotion until resolved.`;
  } else if (score < 60 || criticalCount > 5) {
    state = "FAILED";
    verdictReason = score < 60
      ? `Score ${score}/100 below minimum (60). ${criticalCount} critical findings.`
      : `${criticalCount} critical findings exceed FAILED threshold of 5. Score: ${score}/100.`;
  } else if (score >= 90 && criticalCount === 0) {
    state = "CERTIFIED";
    verdictReason = `Score ${score}/100, zero critical findings, no blocked capabilities. Full certification granted.`;
  } else if (score >= 75 && criticalCount <= 2) {
    state = "CERTIFIED_WITH_WARNINGS";
    verdictReason = `Score ${score}/100, ${criticalCount} critical finding(s). Certified with warnings — address critical findings before next review.`;
  } else {
    state = "CONDITIONAL";
    verdictReason = `Score ${score}/100, ${criticalCount} critical findings. Conditional status — remediate findings before production use.`;
  }

  const productionPromotionAllowed = state === "CERTIFIED" || state === "CERTIFIED_WITH_WARNINGS";
  const promotionBlockReason = productionPromotionAllowed
    ? undefined
    : `Certification state is ${state}: ${verdictReason}`;

  return {
    state,
    verdict_reason: verdictReason,
    blocking_factors: blockingFactors,
    warning_factors: warningFactors,
    overall_score: score,
    critical_finding_count: criticalCount,
    blocked_capability_count: blockedCaps.length,
    certified_at: new Date().toISOString(),
    production_promotion_allowed: productionPromotionAllowed,
    promotion_block_reason: promotionBlockReason,
  };
}

/**
 * Production-promotion gate check.
 * Returns { allowed: true } or { allowed: false, reason, state }.
 */
export function checkProductionPromotionGate(certification: MS5CertificationResult): {
  allowed: boolean;
  reason?: string;
  state: MS5CertificationState;
} {
  if (certification.production_promotion_allowed) {
    return { allowed: true, state: certification.state };
  }
  return {
    allowed: false,
    reason: certification.promotion_block_reason ?? `Certification state ${certification.state} blocks production promotion.`,
    state: certification.state,
  };
}
