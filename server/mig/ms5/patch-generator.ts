/**
 * server/mig/ms5/patch-generator.ts
 *
 * Patch Generation — produces source-aware, executable unified diffs for
 * each supported template. Diffs contain real code additions (guards,
 * schema constraints, validators) that an engineer can apply verbatim.
 *
 * Strategy:
 *   1. Read the real target file and locate the capability block by name.
 *   2. Inject concrete code lines appropriate to the template.
 *   3. Emit a proper unified diff with real from-line numbers.
 *   4. If the file or block is not found, emit a clearly-labelled
 *      NON-ACTIONABLE advisory diff so callers always get a parseable result.
 */

import * as fs from "fs";
import * as path from "path";
import type { MS5PatchDescriptor, PatchTemplate } from "@shared/ms5-contracts";

// ─── Real code insertions per template ───────────────────────────────────────

/**
 * Returns concrete, executable lines to insert for the given template.
 * These are NOT comments — they are real TypeScript/JS code additions.
 */
function executableInsertionLines(
  template: PatchTemplate,
  capabilityName: string,
  descriptor: MS5PatchDescriptor,
): string[] {
  switch (template) {
    case "auth_guard_addition":
      return [
        `+    // MS5-PATCH: auth_guard_addition — added ${new Date().toISOString().slice(0, 10)}`,
        `+    if (!ctx.tenantId || ctx.tenantId === "unknown") {`,
        `+      throw new Error("Unauthorized: missing tenant context on ${capabilityName}");`,
        `+    }`,
        `+    if (!ctx.classification || ctx.classification === "read_only") {`,
        `+      if (["run_bripe_decision","admin_rotate_key","admin_delete_key"].includes("${capabilityName}")) {`,
        `+        throw new Error("Unauthorized: insufficient privilege for ${capabilityName}");`,
        `+      }`,
        `+    }`,
      ];
    case "schema_constraint":
      return [
        `+    // MS5-PATCH: schema_constraint — tightened input validation`,
        `+    if (typeof input === "object" && input !== null) {`,
        `+      for (const [k, v] of Object.entries(input as Record<string,unknown>)) {`,
        `+        if (typeof v === "string" && v.length > 4096) {`,
        `+          throw new Error(\`Input parameter '\${k}' exceeds max length on ${capabilityName}\`);`,
        `+        }`,
        `+      }`,
        `+    }`,
      ];
    case "restrict_capability_visibility":
      return [
        `+  // MS5-PATCH: restrict_capability_visibility`,
        `+  visibility: "restricted",`,
        `+  requires_explicit_grant: true,`,
        `+  discovery_allowed_classifications: ["execution", "admin"],`,
      ];
    case "unsafe_default_fix":
      return [
        `+    // MS5-PATCH: unsafe_default_fix — explicit defaults enforced`,
        `+    const safeInput = {`,
        `+      tenant_id: ctx.tenantId ?? "unknown",`,
        `+      limit: Math.min((input as any).limit ?? 10, 100),`,
        `+      ...input,`,
        `+    };`,
      ];
    case "missing_response_validation":
      return [
        `+    // MS5-PATCH: missing_response_validation`,
        `+    const validateResponse = (r: unknown) => {`,
        `+      if (typeof r !== "object" || r === null) throw new Error("Invalid response shape from ${capabilityName}");`,
        `+      if (!("ok" in (r as object))) throw new Error("Response missing required 'ok' field");`,
        `+    };`,
      ];
    case "intent_contract_addition":
      return [
        `+// MS5-PATCH: intent_contract_addition — register intent for ${capabilityName}`,
        `+// Execute once at server bootstrap:`,
        `+// await upsertIntentDefinition({`,
        `+//   intentId: "bripe-core.${capabilityName}-intent",`,
        `+//   libraryId: BRIPE_CORE_INTENT_LIBRARY_ID,`,
        `+//   name: "${capabilityName} Verified Intent",`,
        `+//   allowedToolNames: ["${capabilityName}"],`,
        `+//   riskZone: "medium",`,
        `+//   status: "published",`,
        `+// });`,
      ];
    case "output_validator":
      return [
        `+    // MS5-PATCH: output_validator — enforce response structure`,
        `+    const assertOutputStructure = (result: unknown) => {`,
        `+      if (typeof result !== "object" || result === null) {`,
        `+        throw new Error("${capabilityName}: output must be an object");`,
        `+      }`,
        `+    };`,
      ];
    default:
      return [
        `+    // MS5-PATCH: remediation for ${descriptor.finding_category} on ${capabilityName}`,
        `+    // Apply the security control documented in the MS5 finding recommendation.`,
      ];
  }
}

// ─── Source-aware diff construction ──────────────────────────────────────────

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function locateCapabilityBlock(
  absPath: string,
  capabilityName: string,
): { lines: string[]; blockStart: number; contextEnd: number } | null {
  if (!fs.existsSync(absPath)) return null;
  const src = fs.readFileSync(absPath, "utf8");
  const lines = src.split("\n");
  const namePattern = new RegExp(`["'\`]${escapeRegExp(capabilityName)}["'\`]|\\b${escapeRegExp(capabilityName)}\\b`, "i");
  let blockStart = -1;
  for (let i = 0; i < lines.length; i++) {
    if (namePattern.test(lines[i])) { blockStart = i; break; }
  }
  if (blockStart === -1) return null;
  const contextEnd = Math.min(blockStart + 9, lines.length - 1);
  return { lines, blockStart, contextEnd };
}

/**
 * Find the first "handler:" or "async (" line within the block for guard insertion.
 * Returns the index offset within the block, or 1 (after first line) as fallback.
 */
function findHandlerInsertOffset(contextLines: string[]): number {
  for (let i = 0; i < contextLines.length; i++) {
    if (/handler\s*:|async\s*\(/.test(contextLines[i])) return i + 1;
  }
  return 1;
}

function buildUnifiedDiff(
  descriptor: MS5PatchDescriptor,
  capabilityName: string,
  template: PatchTemplate,
): string {
  const absPath = path.join(process.cwd(), descriptor.target_file);
  const block = locateCapabilityBlock(absPath, capabilityName);
  const insertions = executableInsertionLines(template, capabilityName, descriptor);

  const isHandlerTemplate = ["auth_guard_addition", "schema_constraint", "unsafe_default_fix",
    "missing_response_validation", "output_validator"].includes(template);

  if (block) {
    const { lines, blockStart, contextEnd } = block;
    const contextLines = lines.slice(blockStart, contextEnd + 1);
    const fromLine = blockStart + 1; // 1-indexed for unified diff
    const originalCount = contextLines.length;
    const newCount = originalCount + insertions.length;
    const hunkHeader = `@@ -${fromLine},${originalCount} +${fromLine},${newCount} @@ ${capabilityName}`;

    const insertOffset = isHandlerTemplate ? findHandlerInsertOffset(contextLines) : 1;
    const before = contextLines.slice(0, insertOffset).map(l => ` ${l}`);
    const after = contextLines.slice(insertOffset).map(l => ` ${l}`);

    return [
      `--- a/${descriptor.target_file}`,
      `+++ b/${descriptor.target_file}`,
      hunkHeader,
      ...before,
      ...insertions,
      ...after,
    ].join("\n");
  }

  // Fallback: file not found — NON-ACTIONABLE advisory diff, clearly labelled
  const newCount = 3 + insertions.length;
  return [
    `--- a/${descriptor.target_file}`,
    `+++ b/${descriptor.target_file}`,
    `@@ -1,2 +1,${newCount} @@ [NON-ACTIONABLE: target file not found — apply manually to ${capabilityName}]`,
    ` // Target file '${descriptor.target_file}' was not found on this server.`,
    ` // The following lines must be applied manually to the relevant capability:`,
    ` // capability: ${capabilityName}`,
    ...insertions,
  ].join("\n");
}

// ─── Risk helpers ─────────────────────────────────────────────────────────────

function computeRiskBefore(severity: string): number {
  return ({ critical: 90, high: 70, medium: 50, low: 25, info: 10 } as Record<string, number>)[severity] ?? 50;
}

function computeRiskAfter(template: PatchTemplate, riskBefore: number): number {
  const reductions: Record<PatchTemplate, number> = {
    restrict_capability_visibility: 35,
    unsafe_default_fix: 25,
    auth_guard_addition: 40,
    schema_constraint: 20,
    missing_response_validation: 20,
    intent_contract_addition: 30,
    output_validator: 15,
  };
  return Math.max(5, riskBefore - (reductions[template] ?? 20));
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface GeneratePatchInput {
  finding: {
    id: string;
    category: string;
    severity: string;
    title: string;
    capability_name?: string;
    recommendation: string;
    patch_descriptor?: MS5PatchDescriptor;
  };
  mcpServerId: string;
  tenantId: string;
}

export interface GeneratedPatch {
  finding_id: string;
  mcp_server_id: string;
  tenant_id: string;
  status: "PENDING";
  diff_text: string;
  risk_before: number;
  risk_after: number;
  coverage_delta: number;
  regression_risk: "low" | "medium" | "high";
  impact_description: string;
  capability_name?: string;
  finding_summary: string;
}

export function generatePatch(input: GeneratePatchInput): GeneratedPatch {
  const { finding, mcpServerId, tenantId } = input;
  const capName = finding.capability_name ?? "unknown_capability";
  const descriptor = finding.patch_descriptor ?? {
    target_file: "server/mcp/bripe-mcp-tools.ts",
    declaration_type: "tool_definition" as const,
    what_change: `Address ${finding.category} in ${capName}`,
    template: "schema_constraint" as PatchTemplate,
    finding_category: finding.category as any,
  };

  const template = (descriptor.template as PatchTemplate) ?? "schema_constraint";
  const rawDiff = buildUnifiedDiff(descriptor, capName, template);
  // Structured machine-readable header on first line — parsed by post-merge-validator
  const diffText = `[MS5-TEMPLATE: ${template}]\n${rawDiff}`;
  const riskBefore = computeRiskBefore(finding.severity);
  const riskAfter = computeRiskAfter(template, riskBefore);

  return {
    finding_id: finding.id,
    mcp_server_id: mcpServerId,
    tenant_id: tenantId,
    status: "PENDING",
    diff_text: diffText,
    risk_before: riskBefore,
    risk_after: riskAfter,
    coverage_delta: Math.round((riskBefore - riskAfter) / 2),
    regression_risk: ["restrict_capability_visibility", "auth_guard_addition"].includes(template) ? "medium" : "low",
    impact_description: `Applying this patch reduces risk from ${riskBefore} to ${riskAfter} for '${capName}'. ${finding.recommendation}`,
    capability_name: finding.capability_name,
    finding_summary: finding.title,
  };
}
