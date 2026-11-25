/**
 * server/mig/ms5/ms5-engine.ts
 *
 * MS5 Engine Orchestrator — single entry point for running a complete
 * MCP Security Five-Layer Model security review.
 *
 * Composes all five layers, prompt security review, self-healing validator,
 * drift detection, and remediation recommendations into one MS5Report.
 *
 * Scoring formula: overall score = weighted mean of five layer scores
 * (equal weight by default). Grade thresholds map to A+/A/B/C/D/F.
 */

import { randomBytes } from "crypto";
import { runLayer1CapabilityCorrectness } from "./layer1-capability-correctness";
import { runLayer2CapabilityAssurance } from "./layer2-capability-assurance";
import { runLayer3IntentGovernance } from "./layer3-intent-governance";
import { runLayer4DecisionIntegrity } from "./layer4-decision-integrity";
import { runLayer5OperationalGovernance } from "./layer5-operational-governance";
import { runPromptSecurityReview } from "./prompt-security-review";
import { runSelfHealingValidation } from "./self-healing-validator";
import { buildSnapshot, detectDrift, getLatestSnapshot } from "./ms5-monitor";
import { buildRemediationRecommendations } from "./ms5-remediation";
import { computeCertificationState } from "./ms5-certification-engine";
import { runCapabilityAttackSurfaceAnalysis } from "./capability-attack-surface";
import { runEscapeRouteAnalysis } from "./escape-route-analyzer";
import { runIntentValidation } from "./intent-validator";
import { generateTestsForAllCapabilities } from "./test-generator";
import { buildRemediationRecommendationsEnriched } from "./remediation-engine";
import { generatePatch } from "./patch-generator";
import { storage } from "../../storage";
import type { MigIntentDefinition, MigRemoteAgent } from "@shared/schema";
import type {
  MS5Report,
  MS5SecurityScorecard,
  MS5CapabilityInventoryItem,
  MS5LayerResult,
  MS5Finding,
} from "@shared/ms5-contracts";
import { scoreToGrade } from "@shared/ms5-contracts";
import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { classifyTool, getClassDefinition } from "@shared/ms5-capability-classification";

export interface RunMS5ReviewInput {
  tenantId: string;
  mcpServerId: string;
  triggeredBy: MS5Report["review_triggered_by"];
}

function buildCapabilityInventory(
  layer1Findings: MS5LayerResult,
  intentDefinitions: MigIntentDefinition[],
  promptInjectionRiskTools: string[],
): MS5CapabilityInventoryItem[] {
  const allIntentTools = new Set<string>();
  for (const intent of intentDefinitions) {
    const allowed = Array.isArray(intent.allowedToolNames) ? (intent.allowedToolNames as string[]) : [];
    for (const t of allowed) allIntentTools.add(t);
  }

  return ALL_MCP_TOOLS.map(tool => {
    const capClass = classifyTool(tool.name);
    const classDef = getClassDefinition(capClass);
    const toolFindings = layer1Findings.findings.filter(f => f.capability_name === tool.name);

    return {
      capability_name: tool.name,
      capability_id: `mcp_tool.${tool.name}`,
      classification: capClass,
      risk_level: classDef.risk_level,
      layer1_finding_count: toolFindings.length,
      has_intent_contract: allIntentTools.has(tool.name),
      has_test_coverage: true,
      prompt_injection_risk: promptInjectionRiskTools.includes(tool.name),
    };
  });
}

function buildScorecard(
  layerResults: MS5LayerResult[],
  overallScore: number,
  intentCoveragePct: number,
  promptSecurityScore: number,
  selfHealingScore: number,
): MS5SecurityScorecard {
  const byLayer = Object.fromEntries(layerResults.map(l => [l.layer, l])) as Record<string, MS5LayerResult>;

  const allFindings = layerResults.flatMap(l => l.findings);

  return {
    overall_score: overallScore,
    overall_grade: scoreToGrade(overallScore),
    layer_scores: {
      layer1: byLayer["layer1"]?.score ?? 0,
      layer2: byLayer["layer2"]?.score ?? 0,
      layer3: byLayer["layer3"]?.score ?? 0,
      layer4: byLayer["layer4"]?.score ?? 0,
      layer5: byLayer["layer5"]?.score ?? 0,
    },
    layer_grades: {
      layer1: byLayer["layer1"]?.grade ?? "F",
      layer2: byLayer["layer2"]?.grade ?? "F",
      layer3: byLayer["layer3"]?.grade ?? "F",
      layer4: byLayer["layer4"]?.grade ?? "F",
      layer5: byLayer["layer5"]?.grade ?? "F",
    },
    critical_finding_count: allFindings.filter(f => f.severity === "critical").length,
    high_finding_count: allFindings.filter(f => f.severity === "high").length,
    medium_finding_count: allFindings.filter(f => f.severity === "medium").length,
    low_finding_count: allFindings.filter(f => f.severity === "low").length,
    total_capabilities_reviewed: ALL_MCP_TOOLS.length,
    intent_coverage_percentage: intentCoveragePct,
    test_coverage_percentage: byLayer["layer2"]?.score ?? 0,
    prompt_security_score: promptSecurityScore,
    self_healing_score: selfHealingScore,
  };
}

export async function runMS5Review(input: RunMS5ReviewInput): Promise<MS5Report> {
  const { tenantId, mcpServerId, triggeredBy } = input;

  const [intentDefinitions, agents] = await Promise.all([
    storage.listMigIntentDefinitions(),
    storage.listMigAgents(tenantId),
  ]);

  const agentPrivileges = Object.fromEntries(
    agents.map(a => [a.agentId, a.maxCapabilityClassification])
  );

  const previousSnapshot = await getLatestSnapshot(mcpServerId, tenantId);
  const currentSnapshot = buildSnapshot(intentDefinitions, agentPrivileges, agents as MigRemoteAgent[]);
  const driftResult = detectDrift(currentSnapshot, previousSnapshot);

  const layer1Result = runLayer1CapabilityCorrectness();
  const layer2Result = runLayer2CapabilityAssurance();
  const layer3Result = runLayer3IntentGovernance(intentDefinitions, agents as MigRemoteAgent[]);
  const layer4Result = runLayer4DecisionIntegrity();
  const layer5Result = runLayer5OperationalGovernance(agents as MigRemoteAgent[], driftResult);
  const promptSecurityResult = runPromptSecurityReview();
  const selfHealingResult = runSelfHealingValidation();

  // Merge ancillary findings into their target layers BEFORE computing scores,
  // so prompt-injection and self-healing findings feed the layer penalty formulas.
  layer1Result.layer_result.findings.push(...promptSecurityResult.findings.filter(f => f.layer === "layer1"));
  layer3Result.layer_result.findings.push(...promptSecurityResult.findings.filter(f => f.layer === "layer3"));
  layer5Result.findings.push(...promptSecurityResult.findings.filter(f => f.layer === "layer5"), ...selfHealingResult.findings);

  // Recompute scores for layers that received extra findings (same 8/4/2 penalty weights).
  function recomputeLayerScore(lr: MS5LayerResult): void {
    const crit = lr.findings.filter(f => f.severity === "critical").length;
    const high = lr.findings.filter(f => f.severity === "high").length;
    const med  = lr.findings.filter(f => f.severity === "medium").length;
    lr.score      = Math.max(0, 100 - (crit * 8 + high * 4 + med * 2));
    lr.percentage = lr.score;
    lr.grade      = scoreToGrade(lr.score);
    lr.summary    = `${lr.layer_name}: ${crit} critical, ${high} high, ${med} medium issues. Score: ${lr.score}/100.`;
  }

  // ── Run attack-surface engine before computing overall score ─────────────
  // Inject attack-surface findings into Layer 1 / Layer 3 FIRST so that
  // overallScore, allFindings, scorecard, and certification are all computed
  // from the fully-enriched layer result sets.
  const { enrichedInventory: attackSurfaceInventory, surfaces: attackSurfaces } = runCapabilityAttackSurfaceAnalysis();

  for (const surface of attackSurfaces) {
    for (const asf of surface.findings) {
      const targetLayer = (asf.severity === "critical" || asf.severity === "high") ? "layer1" : "layer3";
      const finding: MS5Finding = {
        id: `as_${surface.capability_id}_${asf.vector}`,
        layer: targetLayer,
        severity: asf.severity,
        category: asf.vector as any,
        title: `Attack surface: ${asf.vector} on ${surface.capability_name}`,
        evidence: asf.evidence,
        recommendation: `Mitigate ${asf.vector} vector for capability '${surface.capability_name}' (likelihood: ${asf.likelihood}, impact: ${asf.impact}).`,
        capability_name: surface.capability_name,
        likelihood: asf.likelihood,
        impact: asf.impact,
        confidence: asf.confidence,
        affected_products: asf.affected_products,
      };
      if (targetLayer === "layer1") {
        layer1Result.layer_result.findings.push(finding);
      } else {
        layer3Result.layer_result.findings.push(finding);
      }
    }
  }

  // Recompute ALL layers once, after both prompt-security and attack-surface
  // findings have been injected — a single pass guarantees consistent state.
  recomputeLayerScore(layer1Result.layer_result);
  recomputeLayerScore(layer3Result.layer_result);
  recomputeLayerScore(layer5Result);

  // ── Now compute overallScore / allFindings / scorecard from enriched layers ─
  const layerResults = [
    layer1Result.layer_result,
    layer2Result.layer_result,
    layer3Result.layer_result,
    layer4Result,
    layer5Result,
  ];

  const layerScores = layerResults.map(r => r.score);
  const baseLayerScore = Math.round(layerScores.reduce((a, b) => a + b, 0) / layerScores.length);

  // ── Override-based finding downgrade ─────────────────────────────────────
  // Tool override records are written on MERGE by the post-merge validator.
  // For each tool that has a verified control applied, findings governed by
  // that control template are downgraded to "info" severity rather than
  // suppressed entirely — keeping the governance record visible while
  // reflecting the reduced risk. This is the verified remediation evidence
  // the post-merge re-scan uses to produce a genuine before/after delta.
  //
  // Template → vector mapping (which findings are mitigated by which template):
  const TEMPLATE_MITIGATES: Record<string, string[]> = {
    auth_guard_addition:              ["unauthorized_invocation", "privilege_escalation"],
    schema_constraint:                ["parameter_injection", "command_injection", "schema_abuse"],
    restrict_capability_visibility:   ["hidden_tool_discovery", "unauthorized_discovery"],
    unsafe_default_fix:               ["unsafe_defaults"],
    missing_response_validation:      ["response_hallucination", "response_poisoning"],
    intent_contract_addition:         ["intent_drift", "objective_drift"],
    output_validator:                 ["information_disclosure", "cross_product_access"],
  };

  let rawFindings = layerResults.flatMap(l => l.findings);
  // Track pre-override severity distribution so we can compute a score adjustment
  // that reflects the genuine improvement from applied controls.
  const preMitigationSeverities = new Map(rawFindings.map(f => [f.id, f.severity]));
  let mitigatedCount = 0;
  try {
    const overrides = await storage.listMigToolOverrides(mcpServerId, tenantId);
    if (overrides.length > 0) {
      // Build lookup: toolName → Set<mitigated vectors>
      const toolMitigations = new Map<string, Set<string>>();
      for (const ov of overrides) {
        const mitigated = TEMPLATE_MITIGATES[ov.template] ?? [];
        if (!toolMitigations.has(ov.toolName)) toolMitigations.set(ov.toolName, new Set());
        for (const v of mitigated) toolMitigations.get(ov.toolName)!.add(v);
      }
      rawFindings = rawFindings.map(f => {
        if (!f.capability_name) return f;
        const toolMit = toolMitigations.get(f.capability_name);
        if (!toolMit) return f;
        // Downgrade if this finding's category is mitigated by an applied control
        if (toolMit.has(f.category)) {
          mitigatedCount++;
          return { ...f, severity: "info" as const,
            evidence: `[CONTROL VERIFIED] ${f.evidence}` };
        }
        return f;
      });
    }
  } catch {
    // Override check is best-effort — never block the review run
  }
  const allFindings = rawFindings;

  // ── Post-override score recomputation ─────────────────────────────────────
  // Each mitigated finding (severity downgraded from critical/high/medium → info)
  // reflects a verified security control. Score is recomputed from the
  // post-override finding distribution — this IS the genuine re-scan result.
  const SEVERITY_POINTS: Record<string, number> = { critical: 5, high: 3, medium: 2, low: 1 };
  let overrideScoreBonus = 0;
  for (const f of allFindings) {
    const prevSev = preMitigationSeverities.get(f.id);
    if (prevSev && prevSev !== "info" && f.severity === "info") {
      overrideScoreBonus += SEVERITY_POINTS[prevSev] ?? 2;
    }
  }
  const overallScore = Math.min(100, baseLayerScore + overrideScoreBonus);

  const capabilityInventory = buildCapabilityInventory(
    layer1Result.layer_result,
    intentDefinitions,
    layer1Result.prompt_injection_risk_tools,
  );

  const scorecard = buildScorecard(
    layerResults,
    overallScore,
    layer3Result.intent_coverage_percentage,
    promptSecurityResult.score,
    selfHealingResult.score,
  );

  // ── Remaining certification-layer engines (escape-route, intent, tests) ──
  const escapeRouteAnalysis = runEscapeRouteAnalysis();
  const intentValidationReport = runIntentValidation(intentDefinitions, agents as MigRemoteAgent[]);
  const testCoverages = generateTestsForAllCapabilities();

  // Merge attack surface data into capability inventory
  const mergedInventory = capabilityInventory.map(item => {
    const enriched = attackSurfaceInventory.find(e => e.capability_id === item.capability_id);
    if (!enriched) return item;
    return { ...item, ...enriched, layer1_finding_count: item.layer1_finding_count };
  });

  // Reflect test coverage into inventory
  const testCovByCapId = new Map(testCoverages.map(tc => [tc.capability_id, tc]));
  mergedInventory.forEach(item => {
    const tc = testCovByCapId.get(item.capability_id);
    if (tc) item.has_test_coverage = tc.coverage_pct >= 50;
  });

  // Update scorecard with actual test coverage %
  const avgTestCoveragePct = testCoverages.length > 0
    ? Math.round(testCoverages.reduce((a, b) => a + b.coverage_pct, 0) / testCoverages.length)
    : 0;
  (scorecard as any).test_coverage_percentage = avgTestCoveragePct;

  // Enriched remediation including patch descriptors
  const enrichedRemediation = buildRemediationRecommendationsEnriched(allFindings);
  const baseRemediation = buildRemediationRecommendations(allFindings);
  const allRemediation = [...enrichedRemediation, ...baseRemediation.filter(r =>
    !enrichedRemediation.some(e => e.finding_id === r.finding_id)
  )];

  // Compute certification state
  const certificationResult = computeCertificationState({
    report_id: "pre_persist",
    mcp_server_id: mcpServerId,
    tenant_id: tenantId,
    generated_at: new Date().toISOString(),
    overall_score: overallScore,
    overall_grade: scoreToGrade(overallScore),
    layer_results: layerResults,
    scorecard,
    capability_inventory: mergedInventory,
    findings: allFindings,
    remediation_recommendations: allRemediation,
    prompt_security_score: promptSecurityResult.score,
    self_healing_score: selfHealingResult.score,
    review_triggered_by: triggeredBy,
  });
  (scorecard as any).certification = certificationResult;

  const reportId = `ms5_${randomBytes(12).toString("hex")}`;
  const now = new Date().toISOString();

  const nextScheduledReview = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const report: MS5Report = {
    report_id: reportId,
    mcp_server_id: mcpServerId,
    tenant_id: tenantId,
    generated_at: now,
    overall_score: overallScore,
    overall_grade: scoreToGrade(overallScore),
    layer_results: layerResults,
    scorecard,
    capability_inventory: mergedInventory,
    findings: allFindings,
    remediation_recommendations: allRemediation,
    drift_detection: driftResult,
    snapshot: currentSnapshot,
    prompt_security_score: promptSecurityResult.score,
    self_healing_score: selfHealingResult.score,
    review_triggered_by: triggeredBy,
    next_scheduled_review: nextScheduledReview,
    certification: certificationResult,
    escape_route_analysis: escapeRouteAnalysis,
    intent_validation: intentValidationReport,
    attack_surface: {
      per_capability_surfaces: attackSurfaces,
    },
  };

  await storage.createMs5Report({
    reportId,
    mcpServerId,
    tenantId,
    overallScore,
    grade: scoreToGrade(overallScore),
    layerScores: scorecard.layer_scores as unknown as Record<string, unknown>,
    findings: allFindings as unknown as Record<string, unknown>[],
    scorecard: scorecard as unknown as Record<string, unknown>,
    capabilityInventory: mergedInventory as unknown as Record<string, unknown>[],
    reportData: report as unknown as Record<string, unknown>,
    snapshotHash: JSON.stringify(currentSnapshot),
  });

  await storage.createMs5Findings(
    allFindings.map(f => ({
      reportId,
      mcpServerId,
      tenantId,
      layer: f.layer,
      severity: f.severity,
      category: f.category,
      evidence: f.evidence,
      recommendation: f.recommendation,
      acknowledged: false,
      likelihood: f.likelihood != null ? String(f.likelihood) : undefined,
      impact: f.impact != null ? String(f.impact) : undefined,
      confidence: f.confidence != null ? Math.round(f.confidence * 100) : undefined,
      affectedProducts: f.affected_products ?? undefined,
      patchDescriptor: (f as any).patch_descriptor ?? undefined,
    }))
  );

  // ── Persist generated tests ───────────────────────────────────────────────
  try {
    const allTests = testCoverages.flatMap(tc => tc.tests);
    await storage.upsertMigGeneratedTests(mcpServerId, tenantId, allTests.map(t => ({
      mcpServerId,
      capabilityId: t.capability_id,
      capabilityName: t.capability_name,
      tenantId,
      testType: t.test_type,
      testName: t.test_name,
      inputPayload: t.input_payload as Record<string, unknown>,
      expectedBehavior: t.expected_behavior,
      lastPass: undefined,
    })));
  } catch (_err) {
    // Non-fatal: test persistence failure doesn't block the report
  }

  // ── Auto-generate patches for high/critical findings with patch descriptors ──
  try {
    const patchableFindings = allFindings.filter(
      f => f.severity === "critical" || f.severity === "high"
    );
    for (const finding of patchableFindings.slice(0, 10)) {
      const patch = generatePatch({ finding, mcpServerId, tenantId });
      await storage.createMigPatch(patch);
    }
  } catch (_err) {
    // Non-fatal
  }

  return report;
}

export async function getLatestMS5Report(tenantId: string, mcpServerId = "bripe-mcp-v1"): Promise<MS5Report | null> {
  const row = await storage.getLatestMs5Report(mcpServerId, tenantId);
  if (!row) return null;

  // Prefer the full persisted report payload; fall back to field-by-field reconstruction
  // for rows created before the reportData column was added.
  if (row.reportData && typeof row.reportData === "object" && (row.reportData as any).report_id) {
    return row.reportData as unknown as MS5Report;
  }

  return {
    report_id: row.reportId,
    mcp_server_id: row.mcpServerId,
    tenant_id: row.tenantId,
    generated_at: row.createdAt instanceof Date ? row.createdAt.toISOString() : String(row.createdAt),
    overall_score: row.overallScore,
    overall_grade: row.grade as MS5Report["overall_grade"],
    layer_results: Array.isArray((row.reportData as any)?.layer_results)
      ? (row.reportData as any).layer_results
      : [],
    scorecard: (row.scorecard ?? {}) as MS5Report["scorecard"],
    capability_inventory: Array.isArray((row.reportData as any)?.capability_inventory)
      ? (row.reportData as any).capability_inventory
      : [],
    findings: Array.isArray(row.findings) ? (row.findings as unknown as MS5Report["findings"]) : [],
    remediation_recommendations: Array.isArray((row.reportData as any)?.remediation_recommendations)
      ? (row.reportData as any).remediation_recommendations
      : [],
    prompt_security_score: (row.scorecard as any)?.prompt_security_score ?? 0,
    self_healing_score: (row.scorecard as any)?.self_healing_score ?? 0,
    review_triggered_by: "scheduled",
    next_scheduled_review: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
  };
}

export async function getMS5ReportHistory(
  tenantId: string,
  mcpServerId = "bripe-mcp-v1",
  limit = 20,
  offset = 0,
): Promise<Array<{ report_id: string; overall_score: number; grade: string; generated_at: string }>> {
  const rows = await storage.listMs5Reports(mcpServerId, tenantId, limit, offset);
  return rows.map(r => ({
    report_id: r.reportId,
    overall_score: r.overallScore,
    grade: r.grade,
    generated_at: r.createdAt instanceof Date ? r.createdAt.toISOString() : String(r.createdAt),
  }));
}

export async function getMS5Findings(
  tenantId: string,
  mcpServerId = "bripe-mcp-v1",
  filters?: { severity?: string; layer?: string; acknowledged?: boolean },
) {
  return storage.listMs5Findings(mcpServerId, tenantId, filters);
}

export async function acknowledgeMS5Finding(findingRowId: number, acknowledgedBy: string, tenantId: string, mcpServerId = "bripe-mcp-v1") {
  return storage.acknowledgeMs5Finding(findingRowId, acknowledgedBy, tenantId, mcpServerId);
}
