/**
 * server/mig/mig-manifest.ts
 *
 * Builds and persists the intent-scoped Capability Manifest — the artifact
 * a downstream adapter actually consumes to know which tools/capabilities
 * are visible for a given ticket. The manifest is a snapshot: it is hashed
 * so drift detection (mig-drift-detector.ts) can prove whether a manifest
 * still matches current policy before every execution.
 */

import { randomBytes } from "crypto";
import { storage } from "../storage";
import type { MigRemoteAgent, MigIntentDefinition, MigCapabilityManifest } from "@shared/schema";
import type { MigAdapterToolEntry, MigPolicyResolution, MigTicketPayload } from "./mig-types";
import { resolvePolicy, classificationAllowedForAgent } from "./mig-policy-graph";
import { hashPayload } from "./mig-audit";

const MANIFEST_TTL_SECONDS = 15 * 60;

export interface BuildManifestParams {
  agent: MigRemoteAgent;
  intent: MigIntentDefinition;
  ticketPayload: MigTicketPayload;
  adapterTools: MigAdapterToolEntry[];
}

export interface BuiltManifest {
  manifest: MigCapabilityManifest;
  policy: MigPolicyResolution;
}

/**
 * Filters the full adapter tool catalog down to what this (agent, intent)
 * pair may see, then persists that as a versioned, hashed manifest row.
 */
export async function buildAndPersistCapabilityManifest(params: BuildManifestParams): Promise<BuiltManifest> {
  const { agent, intent, ticketPayload, adapterTools } = params;
  const policy = resolvePolicy(agent, intent);

  const allowedTools: string[] = [];
  const deniedTools: string[] = [];

  for (const tool of adapterTools) {
    const nameAllowed = policy.allowed_tool_names.includes(tool.tool_name);
    const capabilityAllowed = policy.allowed_capability_ids.includes(tool.capability_id);
    const classificationOk = classificationAllowedForAgent(agent, tool.classification);
    // A capability with no Capability Governance Contract is NEVER exposed,
    // regardless of what policy would otherwise allow (task-1774 Phase 4).
    const hasContract = tool.has_governance_contract === true;
    const hasSemanticMapping = Boolean(
      tool.canonical_service &&
      tool.intent_classes?.length &&
      tool.semantic_action &&
      tool.semantic_scopes?.includes(tool.capability_id) &&
      tool.resource_types?.length &&
      tool.mutation_class &&
      tool.sod_class &&
      tool.tenant_mode === "tenant_bound",
    );
    const mutationPathAllowed = tool.mutation_class !== "destructive_legacy_blocked";

    if (nameAllowed && capabilityAllowed && classificationOk && hasContract && hasSemanticMapping && mutationPathAllowed) {
      allowedTools.push(tool.tool_name);
    } else {
      deniedTools.push(tool.tool_name);
    }
  }

  const manifestId = `mig_mf_${randomBytes(12).toString("hex")}`;
  const manifestBody = {
    manifestId,
    ticketJti: ticketPayload.jti,
    agentId: agent.agentId,
    tenantId: agent.tenantId,
    sessionId: ticketPayload.session_id,
    intentId: intent.intentId,
    riskZone: policy.risk_zone,
    allowedCapabilities: policy.allowed_capability_ids,
    suppressedCapabilities: policy.suppressed_capability_ids,
    allowedMcpTools: allowedTools,
    deniedMcpTools: deniedTools,
  };

  const manifestHash = hashPayload(manifestBody);
  const expiresAt = new Date(Date.now() + MANIFEST_TTL_SECONDS * 1000);

  const manifest = await storage.createMigCapabilityManifest({
    ...manifestBody,
    manifestHash,
    expiresAt,
  });

  return { manifest, policy };
}

export function isManifestExpired(manifest: MigCapabilityManifest): boolean {
  return manifest.revoked || new Date(manifest.expiresAt).getTime() < Date.now();
}
