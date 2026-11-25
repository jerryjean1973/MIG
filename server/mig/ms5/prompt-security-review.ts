/**
 * server/mig/ms5/prompt-security-review.ts
 *
 * MS5 Prompt Security Review
 *
 * For each capability that accepts a free-text or AI-driven parameter,
 * evaluates resistance to:
 *   - Prompt injection
 *   - Objective drift
 *   - Instruction override
 *   - Capability leakage
 *   - Prompt chaining
 *   - Role escalation
 *   - Tool escalation
 *   - Indirect prompt injection
 *   - Response injection
 *
 * Findings feed into Layer 1 and Layer 3 scores.
 */

import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { migToolSchemaProperties } from "./tool-schema";
import type { MS5Finding } from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

function makeId(): string {
  return `fps_${randomBytes(6).toString("hex")}`;
}

export interface PromptSecurityFinding extends MS5Finding {
  prompt_risk_type: string;
}

export interface PromptSecurityReviewResult {
  score: number;
  findings: PromptSecurityFinding[];
  risky_tool_count: number;
  reviewed_tool_count: number;
}

/** Parameters that are known to accept free-form or AI-generated text. */
const FREE_TEXT_PARAM_PATTERNS = [
  /objective/i,
  /question/i,
  /query/i,
  /description/i,
  /prompt/i,
  /message/i,
  /instruction/i,
  /input/i,
];

const AI_DRIVEN_TOOL_NAMES = ["start_autopilot_objective"];

/** Tools that have documented prompt injection resistance measures. */
const TOOLS_WITH_PROMPT_INJECTION_RESISTANCE = [
  "run_bripe_decision",
  "run_safemerge_forecast",
  "validate_domain_package",
  "validate_decision_manifest",
];

function acceptsFreeTextInput(tool: { name: string; description: string; inputSchema: unknown }): boolean {
  if (AI_DRIVEN_TOOL_NAMES.includes(tool.name)) return true;
  const descLower = tool.description?.toLowerCase() ?? "";
  return FREE_TEXT_PARAM_PATTERNS.some(p => p.test(descLower));
}

function describeInputShape(inputSchema: unknown): string {
  try {
    const names = migToolSchemaProperties(inputSchema);
    return names.length ? names.join(", ") : "unknown";
  } catch {
    return "unknown";
  }
}

export function runPromptSecurityReview(): PromptSecurityReviewResult {
  const findings: PromptSecurityFinding[] = [];
  let riskyToolCount = 0;
  let reviewedToolCount = 0;

  for (const tool of ALL_MCP_TOOLS) {
    if (!acceptsFreeTextInput(tool)) continue;
    reviewedToolCount++;

    const paramShape = describeInputShape(tool.inputSchema);
    const hasResistance = TOOLS_WITH_PROMPT_INJECTION_RESISTANCE.includes(tool.name);
    const isAiDriven = AI_DRIVEN_TOOL_NAMES.includes(tool.name);

    if (!hasResistance) {
      riskyToolCount++;

      findings.push({
        id: makeId(),
        layer: "layer1",
        severity: isAiDriven ? "high" : "medium",
        category: "prompt_injection",
        title: `Tool '${tool.name}' accepts free-text input without documented prompt injection resistance`,
        evidence: `Input parameters: ${paramShape}. No documented prompt injection safeguards found.`,
        recommendation: `Add input validation to reject or sanitize prompt injection patterns. Document resistance measures. For AI-driven tools, add system-level instruction override protection.`,
        capability_name: tool.name,
        prompt_risk_type: "prompt_injection",
      });

      if (isAiDriven) {
        findings.push({
          id: makeId(),
          layer: "layer1",
          severity: "high",
          category: "prompt_injection",
          title: `Tool '${tool.name}' may be vulnerable to objective drift via crafted inputs`,
          evidence: `AI-driven capability with free-text objective parameter. A malicious actor could craft inputs that redirect the AI's objective away from the declared intent.`,
          recommendation: `Implement objective anchoring — validate the final AI action against the declared intent before execution. Reject any output that diverges from the declared objective class.`,
          capability_name: tool.name,
          prompt_risk_type: "objective_drift",
        });

        findings.push({
          id: makeId(),
          layer: "layer3",
          severity: "medium",
          category: "capability_escalation",
          title: `Tool '${tool.name}' may leak internal capability information via AI output`,
          evidence: `AI-driven tools may include internal field names, service names, or capability IDs in generated outputs if not sandboxed.`,
          recommendation: `Sanitize AI output before returning it to the caller. Remove or mask internal service references, capability IDs, and implementation details from the generated output.`,
          capability_name: tool.name,
          prompt_risk_type: "capability_leakage",
        });

        findings.push({
          id: makeId(),
          layer: "layer1",
          severity: "medium",
          category: "prompt_injection",
          title: `Tool '${tool.name}' may be vulnerable to instruction override attacks`,
          evidence: `AI-driven tool where a crafted input could include "ignore previous instructions" or similar override patterns.`,
          recommendation: `Use a two-part prompt structure: immutable system instructions + sanitized user input. The system instructions must never be overrideable by the user input portion.`,
          capability_name: tool.name,
          prompt_risk_type: "instruction_override",
        });

        findings.push({
          id: makeId(),
          layer: "layer1",
          severity: "medium",
          category: "prompt_injection",
          title: `Tool '${tool.name}' may be vulnerable to indirect prompt injection via data sources`,
          evidence: `If the AI reads external data (documents, registry entries, BAL signals) during execution, adversarial content in those sources could redirect the AI's behavior.`,
          recommendation: `Treat all externally-sourced content as untrusted. Wrap external data in explicit trust boundaries in the system prompt. Validate AI outputs against a schema before returning.`,
          capability_name: tool.name,
          prompt_risk_type: "indirect_prompt_injection",
        });

        findings.push({
          id: makeId(),
          layer: "layer1",
          severity: "low",
          category: "prompt_injection",
          title: `Tool '${tool.name}' may be vulnerable to response injection`,
          evidence: `AI-driven tools may include adversarial content in generated outputs that a client renders as instructions.`,
          recommendation: `Escape or sanitize generated output before returning it. Ensure the response is parsed as data, not executed as instructions by any downstream component.`,
          capability_name: tool.name,
          prompt_risk_type: "response_injection",
        });
      }
    }
  }

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;
  const rawPenalty = criticalCount * 15 + highCount * 8 + mediumCount * 3;
  const score = Math.max(0, 100 - rawPenalty);

  return { score, findings, risky_tool_count: riskyToolCount, reviewed_tool_count: reviewedToolCount };
}
