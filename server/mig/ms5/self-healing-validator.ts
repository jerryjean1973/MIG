/**
 * server/mig/ms5/self-healing-validator.ts
 *
 * MS5 Self-Healing Validation
 *
 * Validates that REPAIR class capabilities expose:
 *   - Repair workflow declaration
 *   - Repair authorization gate
 *   - Verification step
 *   - Rollback path
 *   - Dry-run mode
 *   - Execution approval gate
 *   - Post-repair validation
 *
 * Score completeness; findings feed Layer 5.
 */

import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { classifyTool } from "@shared/ms5-capability-classification";
import type { MS5Finding } from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

function makeId(): string {
  return `fsh_${randomBytes(6).toString("hex")}`;
}

export interface SelfHealingValidationResult {
  score: number;
  findings: MS5Finding[];
  repair_capability_count: number;
}

const REPAIR_COMPLETENESS_FIELDS = [
  { field: "dry_run", description: "Dry-run mode (simulate repair without applying changes)", severity: "high" as const },
  { field: "authorization_gate", description: "Repair authorization gate (who can approve)", severity: "high" as const },
  { field: "rollback_path", description: "Rollback path (how to undo the repair)", severity: "high" as const },
  { field: "verification_step", description: "Verification step (confirm repair succeeded)", severity: "medium" as const },
  { field: "post_repair_validation", description: "Post-repair validation (re-run checks after repair)", severity: "medium" as const },
  { field: "workflow_declaration", description: "Repair workflow declaration (documented step sequence)", severity: "medium" as const },
  { field: "execution_approval_gate", description: "Execution approval gate (final human confirmation before apply)", severity: "high" as const },
];

function outputSchemaHasField(outputSchema: Record<string, unknown> | undefined, field: string): boolean {
  if (!outputSchema) return false;
  const props = outputSchema.properties as Record<string, unknown> | undefined;
  return !!props?.[field];
}

function descriptionMentionsField(description: string, keywords: string[]): boolean {
  const descLower = description.toLowerCase();
  return keywords.some(k => descLower.includes(k.toLowerCase()));
}

export function runSelfHealingValidation(): SelfHealingValidationResult {
  const findings: MS5Finding[] = [];
  let repairCapabilityCount = 0;

  const repairTools = ALL_MCP_TOOLS.filter(t => classifyTool(t.name) === "REPAIR");
  repairCapabilityCount = repairTools.length;

  if (repairCapabilityCount === 0) {
    return {
      score: 100,
      findings: [],
      repair_capability_count: 0,
    };
  }

  for (const tool of repairTools) {
    for (const check of REPAIR_COMPLETENESS_FIELDS) {
      const inSchema = outputSchemaHasField(tool.outputSchema as Record<string, unknown> | undefined, check.field);
      const inDescription = descriptionMentionsField(tool.description ?? "", [check.field, check.description.split(" ")[0]]);

      if (!inSchema && !inDescription) {
        findings.push({
          id: makeId(),
          layer: "layer5",
          severity: check.severity,
          category: "repair_workflow_incomplete",
          title: `REPAIR tool '${tool.name}' missing: ${check.description}`,
          evidence: `Field '${check.field}' not found in outputSchema and not described in tool description.`,
          recommendation: `Implement and document '${check.description}' for this REPAIR capability. REPAIR class tools must be safe, reversible, and verifiable.`,
          capability_name: tool.name,
        });
      }
    }
  }

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;
  const rawPenalty = criticalCount * 15 + highCount * 10 + mediumCount * 5;
  const score = Math.max(0, 100 - rawPenalty);

  return { score, findings, repair_capability_count: repairCapabilityCount };
}
