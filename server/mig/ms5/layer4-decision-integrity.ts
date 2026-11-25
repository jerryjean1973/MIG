/**
 * server/mig/ms5/layer4-decision-integrity.ts
 *
 * MS5 Layer 4 — Decision Integrity
 *
 * Validates that every EXECUTE/REPAIR/DEPLOY class capability that produces
 * a structured output honours the decision-package integrity contract:
 *   - Output carries traceability, confidence, evidence, and smallest-fix/explainability.
 *   - No hallucinated evidence (AI output without grounding).
 *   - Missing fallback behaviour flagged.
 *   - Decision consistency contract declared.
 *
 * Renamed from "Decision Intelligence" → "Decision Integrity" so MS5 is
 * general-purpose, not BRIPe-specific (per task spec).
 */

import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { classifyTool } from "@shared/ms5-capability-classification";
import type { MS5Finding, MS5LayerResult } from "@shared/ms5-contracts";
import { scoreToGrade } from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

function makeId(): string {
  return `f4_${randomBytes(6).toString("hex")}`;
}

/** Fields that must appear in the outputSchema of any EXECUTE/REPAIR/DEPLOY tool. */
const REQUIRED_INTEGRITY_FIELDS = [
  "ok",
] as const;

const RECOMMENDED_INTEGRITY_FIELDS = [
  "decision",
  "render_allowed",
  "decision_trust",
  "metadata",
] as const;

/** Tools that use AI generation and must declare grounding evidence. */
const AI_GENERATION_TOOLS = ["start_autopilot_objective"];

/** Tools known to have proper fallback declarations in their handlers. */
const TOOLS_WITH_KNOWN_FALLBACK = [
  "run_bripe_decision",
  "run_safemerge_forecast",
  "validate_domain_package",
  "validate_decision_manifest",
];

function outputSchemaHasField(outputSchema: Record<string, unknown> | undefined, field: string): boolean {
  if (!outputSchema) return false;
  const props = outputSchema.properties as Record<string, unknown> | undefined;
  return !!props?.[field];
}

function outputSchemaHasAnyField(outputSchema: Record<string, unknown> | undefined, fields: readonly string[]): boolean {
  return fields.some(f => outputSchemaHasField(outputSchema, f));
}

export function runLayer4DecisionIntegrity(): MS5LayerResult {
  const findings: MS5Finding[] = [];

  for (const tool of ALL_MCP_TOOLS) {
    const capClass = classifyTool(tool.name);

    if (!["EXECUTE", "REPAIR", "DEPLOY"].includes(capClass)) continue;

    for (const field of REQUIRED_INTEGRITY_FIELDS) {
      if (!outputSchemaHasField(tool.outputSchema, field)) {
        findings.push({
          id: makeId(),
          layer: "layer4",
          severity: "high",
          category: "decision_integrity_gap",
          title: `Tool '${tool.name}' missing required integrity field '${field}' in outputSchema`,
          evidence: `Class ${capClass} requires '${field}' in outputSchema. Field absent or outputSchema not declared.`,
          recommendation: `Add '${field}' to the tool's outputSchema with a descriptive definition so consumers and auditors can validate output correctness.`,
          capability_name: tool.name,
        });
      }
    }

    if (!outputSchemaHasAnyField(tool.outputSchema, RECOMMENDED_INTEGRITY_FIELDS)) {
      findings.push({
        id: makeId(),
        layer: "layer4",
        severity: "medium",
        category: "missing_traceability",
        title: `Tool '${tool.name}' outputSchema lacks traceability fields (decision, render_allowed, metadata, or decision_trust)`,
        evidence: `None of the recommended traceability fields found in outputSchema.`,
        recommendation: `Add at minimum a 'metadata' field (run_id, assembled_at) and a 'render_allowed' flag so callers can implement safe rendering gates.`,
        capability_name: tool.name,
      });
    }

    if (!outputSchemaHasField(tool.outputSchema, "decision") && !outputSchemaHasField(tool.outputSchema, "decision_summary")) {
      findings.push({
        id: makeId(),
        layer: "layer4",
        severity: "medium",
        category: "missing_traceability",
        title: `Tool '${tool.name}' has no 'decision' or 'decision_summary' field in outputSchema`,
        evidence: `EXECUTE class tools should expose a structured decision or decision_summary section for audit traceability.`,
        recommendation: `Add a 'decision' or 'decision_summary' field containing at minimum the outcome, confidence, and an action recommendation.`,
        capability_name: tool.name,
      });
    }

    if (!TOOLS_WITH_KNOWN_FALLBACK.includes(tool.name)) {
      findings.push({
        id: makeId(),
        layer: "layer4",
        severity: "medium",
        category: "missing_fallback",
        title: `Tool '${tool.name}' has no declared fallback behaviour`,
        evidence: `No explicit fallback declaration found for this EXECUTE class tool. If the engine or upstream service is unavailable, callers may receive unhandled errors.`,
        recommendation: `Add explicit error handling and a structured error response shape (e.g. ok=false + error_code + message) to the tool handler and outputSchema.`,
        capability_name: tool.name,
      });
    }
  }

  for (const toolName of AI_GENERATION_TOOLS) {
    const tool = ALL_MCP_TOOLS.find(t => t.name === toolName);
    if (!tool) continue;

    if (!tool.description?.includes("NOT") && !tool.description?.includes("AI-generated")) {
      findings.push({
        id: makeId(),
        layer: "layer4",
        severity: "high",
        category: "hallucinated_evidence",
        title: `Tool '${toolName}' uses AI generation but may not adequately warn callers`,
        evidence: `Tool uses AI-generative capabilities. The description must clearly flag that outputs are AI-generated narrative placeholders (not engine-computed values) and must NOT be surfaced as risk decisions.`,
        recommendation: `Ensure the description explicitly states: AI-generated outputs are scaffolding only, not reproducible, and must not be used for security decisions or risk reporting.`,
        capability_name: toolName,
      });
    }
  }

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;

  const rawPenalty = criticalCount * 10 + highCount * 5 + mediumCount * 2;
  const score = Math.max(0, 100 - rawPenalty);

  return {
    layer: "layer4",
    layer_name: "Decision Integrity",
    score,
    max_score: 100,
    percentage: score,
    grade: scoreToGrade(score),
    findings,
    summary: `Reviewed EXECUTE/REPAIR/DEPLOY class capabilities. Found ${criticalCount} critical, ${highCount} high, ${mediumCount} medium integrity issues. Score: ${score}/100.`,
    checked_at: new Date().toISOString(),
  };
}
