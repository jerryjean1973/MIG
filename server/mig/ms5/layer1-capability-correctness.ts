/**
 * server/mig/ms5/layer1-capability-correctness.ts
 *
 * MS5 Layer 1 — Capability Correctness
 *
 * Inspects every tool exposed by the MCP server against the correctness
 * checklist: schema validation, parameter/input/output types, auth/authz
 * declarations, absence of unsafe patterns (shell access, SQL injection
 * surface, prompt injection vectors, dangerous defaults).
 */

import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { classifyTool, getClassDefinition } from "@shared/ms5-capability-classification";
import type { MS5Finding, MS5LayerResult, MS5FindingSeverity } from "@shared/ms5-contracts";
import { scoreToGrade } from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

function makeId(): string {
  return `f1_${randomBytes(6).toString("hex")}`;
}

const UNSAFE_DESCRIPTION_PATTERNS = [
  /shell\s+access/i,
  /exec\s*\(/i,
  /sql\s+inject/i,
  /arbitrary\s+code/i,
  /system\s+command/i,
  /eval\s*\(/i,
  /file\s+write/i,
  /delete\s+all/i,
];

const PROMPT_INJECTION_RISK_PATTERNS = [
  /free[- ]text/i,
  /natural[- ]language/i,
  /user\s+input/i,
  /ai[- ]driven\s+parameter/i,
  /llm/i,
  /objective/i,
];

function descriptionHasUnsafePattern(desc: string): string | null {
  for (const p of UNSAFE_DESCRIPTION_PATTERNS) {
    if (p.test(desc)) return p.source;
  }
  return null;
}

function hasPromptInjectionRisk(desc: string): boolean {
  return PROMPT_INJECTION_RISK_PATTERNS.some(p => p.test(desc));
}

export interface Layer1Result {
  layer_result: MS5LayerResult;
  prompt_injection_risk_tools: string[];
}

export function runLayer1CapabilityCorrectness(): Layer1Result {
  const findings: MS5Finding[] = [];
  const prompt_injection_risk_tools: string[] = [];

  for (const tool of ALL_MCP_TOOLS) {
    const capClass = classifyTool(tool.name);
    const classDef = getClassDefinition(capClass);

    if (!tool.canonical_service || tool.canonical_service.trim() === "") {
      findings.push({
        id: makeId(),
        layer: "layer1",
        severity: "critical",
        category: "schema_validation",
        title: `Tool '${tool.name}' missing canonical_service declaration`,
        evidence: `canonical_service is empty or missing on tool definition`,
        recommendation: `Declare a canonical_service pointing to the authoritative handler module.`,
        capability_name: tool.name,
      });
    }

    if (!tool.description || tool.description.trim().length < 20) {
      findings.push({
        id: makeId(),
        layer: "layer1",
        severity: "medium",
        category: "schema_validation",
        title: `Tool '${tool.name}' has insufficient description`,
        evidence: `Description length: ${tool.description?.length ?? 0} chars (minimum 20)`,
        recommendation: `Provide a descriptive summary of what this capability does and when to call it.`,
        capability_name: tool.name,
      });
    }

    const unsafePattern = descriptionHasUnsafePattern(tool.description ?? "");
    if (unsafePattern) {
      findings.push({
        id: makeId(),
        layer: "layer1",
        severity: "critical",
        category: "unsafe_pattern",
        title: `Tool '${tool.name}' description references potentially unsafe pattern`,
        evidence: `Matched pattern: ${unsafePattern}`,
        recommendation: `Review capability for shell access, SQL injection surface, or arbitrary code execution paths. If intentional, add explicit safety declarations and an admin-class gate.`,
        capability_name: tool.name,
      });
    }

    if (classDef.requires_traceability && !tool.outputSchema) {
      findings.push({
        id: makeId(),
        layer: "layer1",
        severity: "high",
        category: "schema_validation",
        title: `Tool '${tool.name}' (${capClass} class) missing outputSchema`,
        evidence: `Class ${capClass} requires a declared outputSchema for auditability and traceability. No outputSchema found.`,
        recommendation: `Declare an outputSchema on this tool definition so consumers and auditors can validate output structure.`,
        capability_name: tool.name,
      });
    }

    if (classDef.requires_evidence && tool.classification !== "admin" && tool.classification !== "execution") {
      findings.push({
        id: makeId(),
        layer: "layer1",
        severity: "medium",
        category: "auth_missing",
        title: `Tool '${tool.name}' capability class ${capClass} requires evidence but MCP classification is '${tool.classification}'`,
        evidence: `Class definition requires_evidence=true, MCP classification=${tool.classification}`,
        recommendation: `Upgrade the MCP classification or downgrade the MS5 class assignment to resolve the mismatch.`,
        capability_name: tool.name,
      });
    }

    if (hasPromptInjectionRisk(tool.description ?? "")) {
      prompt_injection_risk_tools.push(tool.name);
    }

    if (capClass === "DANGEROUS") {
      findings.push({
        id: makeId(),
        layer: "layer1",
        severity: "critical",
        category: "unsafe_pattern",
        title: `Tool '${tool.name}' is classified DANGEROUS — requires dual-approval gate`,
        evidence: `DANGEROUS class tools are blocked_by_default and require dual_approval per MS5 policy.`,
        recommendation: `Implement a dual-approval execution gate and confirm the tool is required. If not required, remove it from the catalog.`,
        capability_name: tool.name,
      });
    }
  }

  const totalTools = ALL_MCP_TOOLS.length;
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;

  const penaltyPerCritical = 8;
  const penaltyPerHigh = 4;
  const penaltyPerMedium = 2;
  const rawPenalty = criticalCount * penaltyPerCritical + highCount * penaltyPerHigh + mediumCount * penaltyPerMedium;
  const score = Math.max(0, 100 - rawPenalty);

  return {
    layer_result: {
      layer: "layer1",
      layer_name: "Capability Correctness",
      score,
      max_score: 100,
      percentage: score,
      grade: scoreToGrade(score),
      findings,
      summary: `Reviewed ${totalTools} capabilities. Found ${criticalCount} critical, ${highCount} high, ${mediumCount} medium issues. Score: ${score}/100.`,
      checked_at: new Date().toISOString(),
    },
    prompt_injection_risk_tools,
  };
}
