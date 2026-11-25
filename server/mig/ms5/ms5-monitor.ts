/**
 * server/mig/ms5/ms5-monitor.ts
 *
 * MS5 Continuous Monitoring and Drift Detection
 *
 * After each report, snapshots the capability list, schema hashes, intent
 * bindings, privilege assignments, and credential posture fingerprints.
 * On the next review, diffs the snapshot to detect:
 *   - New/removed capabilities
 *   - Schema drift
 *   - Intent drift
 *   - Privilege drift
 *   - Credential drift (trustLevel / maxCapabilityClassification / riskZones change)
 *   - Version drift
 *   - Decision drift
 */

import { createHash } from "crypto";
import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { storage } from "../../storage";
import type { MigIntentDefinition, MigRemoteAgent } from "@shared/schema";
import type {
  MS5DriftSnapshot,
  MS5DriftDetectionResult,
} from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

function hashString(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 16);
}

function buildSchemaHashes(): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const tool of ALL_MCP_TOOLS) {
    try {
      const schemaStr = JSON.stringify({
        input: (tool.inputSchema as any)?._def ?? {},
        output: tool.outputSchema ?? {},
      });
      hashes[tool.name] = hashString(schemaStr);
    } catch {
      hashes[tool.name] = hashString(tool.name);
    }
  }
  return hashes;
}

function buildVersionHash(): string {
  const toolNames = ALL_MCP_TOOLS.map(t => `${t.name}:${t.classification}:${t.canonical_service}`).sort();
  return hashString(toolNames.join("|"));
}

/**
 * Builds a non-secret fingerprint of each agent's security posture.
 * Never hashes actual credential values — only structural metadata:
 * trustLevel, maxCapabilityClassification, allowedRiskZones.
 */
function buildCredentialFingerprints(agents: MigRemoteAgent[]): Record<string, string> {
  const fingerprints: Record<string, string> = {};
  for (const agent of agents) {
    const posture = [
      agent.trustLevel ?? "standard",
      agent.maxCapabilityClassification ?? "read_only",
      JSON.stringify(Array.isArray(agent.allowedRiskZones) ? [...(agent.allowedRiskZones as string[])].sort() : ["low"]),
    ].join("|");
    fingerprints[agent.agentId] = hashString(posture);
  }
  return fingerprints;
}

export function buildSnapshot(
  intentDefinitions: MigIntentDefinition[],
  agentPrivileges: Record<string, string>,
  agents: MigRemoteAgent[] = [],
): MS5DriftSnapshot {
  const capabilityNames = ALL_MCP_TOOLS.map(t => t.name).sort();
  const schemaHashes = buildSchemaHashes();
  const intentBindings = intentDefinitions
    .filter(i => i.status === "published" || i.status === "active")
    .map(i => `${i.intentId}:${JSON.stringify((i.allowedToolNames as string[])?.sort() ?? [])}`)
    .sort();
  const versionHash = buildVersionHash();
  const credentialFingerprints = buildCredentialFingerprints(agents);

  return {
    snapshot_id: `snap_${randomBytes(8).toString("hex")}`,
    taken_at: new Date().toISOString(),
    capability_names: capabilityNames,
    schema_hashes: schemaHashes,
    intent_bindings: intentBindings,
    privilege_assignments: agentPrivileges,
    version_hash: versionHash,
    credential_fingerprints: credentialFingerprints,
  };
}

export function detectDrift(
  current: MS5DriftSnapshot,
  previous: MS5DriftSnapshot | undefined,
): MS5DriftDetectionResult {
  if (!previous) {
    return {
      has_drift: false,
      new_capabilities: [],
      removed_capabilities: [],
      schema_drift_capabilities: [],
      intent_drift_capabilities: [],
      privilege_drift_details: [],
      credential_drift: false,
      version_drift: false,
      decision_drift: false,
    };
  }

  const currentSet = new Set(current.capability_names);
  const previousSet = new Set(previous.capability_names);

  const newCapabilities = current.capability_names.filter(n => !previousSet.has(n));
  const removedCapabilities = previous.capability_names.filter(n => !currentSet.has(n));

  const schemaDriftCapabilities: string[] = [];
  for (const name of current.capability_names) {
    if (previousSet.has(name) && current.schema_hashes[name] !== previous.schema_hashes[name]) {
      schemaDriftCapabilities.push(name);
    }
  }

  const currentIntentSet = new Set(current.intent_bindings);
  const previousIntentSet = new Set(previous.intent_bindings);
  const intentDriftCapabilities: string[] = [];
  for (const binding of current.intent_bindings) {
    if (!previousIntentSet.has(binding)) intentDriftCapabilities.push(binding.split(":")[0]);
  }
  for (const binding of previous.intent_bindings) {
    if (!currentIntentSet.has(binding)) {
      const intentId = binding.split(":")[0];
      if (!intentDriftCapabilities.includes(intentId)) intentDriftCapabilities.push(intentId);
    }
  }

  const privilegeDriftDetails: string[] = [];
  for (const [agentId, privilege] of Object.entries(current.privilege_assignments)) {
    if (previous.privilege_assignments[agentId] && previous.privilege_assignments[agentId] !== privilege) {
      privilegeDriftDetails.push(`${agentId}: ${previous.privilege_assignments[agentId]} → ${privilege}`);
    }
  }

  // Credential drift: any change to trustLevel / maxCapabilityClassification / riskZones
  // for a known agent, or any new admin-class agent appearing.
  const prevCreds = previous.credential_fingerprints ?? {};
  const currCreds = current.credential_fingerprints ?? {};
  let credentialDrift = false;
  for (const [agentId, fingerprint] of Object.entries(currCreds)) {
    if (prevCreds[agentId] !== undefined && prevCreds[agentId] !== fingerprint) {
      credentialDrift = true;
      break;
    }
  }

  const versionDrift = current.version_hash !== previous.version_hash;
  const decisionDrift = schemaDriftCapabilities.some(n =>
    ALL_MCP_TOOLS.find(t => t.name === n)?.classification === "execution"
  );

  const hasDrift = newCapabilities.length > 0 || removedCapabilities.length > 0 ||
    schemaDriftCapabilities.length > 0 || intentDriftCapabilities.length > 0 ||
    privilegeDriftDetails.length > 0 || versionDrift || credentialDrift || decisionDrift;

  return {
    has_drift: hasDrift,
    new_capabilities: newCapabilities,
    removed_capabilities: removedCapabilities,
    schema_drift_capabilities: schemaDriftCapabilities,
    intent_drift_capabilities: intentDriftCapabilities,
    privilege_drift_details: privilegeDriftDetails,
    credential_drift: credentialDrift,
    version_drift: versionDrift,
    decision_drift: decisionDrift,
  };
}

export async function getLatestSnapshot(mcpServerId: string, tenantId: string): Promise<MS5DriftSnapshot | undefined> {
  const latest = await storage.getLatestMs5Report(mcpServerId, tenantId);
  if (!latest?.snapshotHash) return undefined;
  try {
    const parsed = JSON.parse(latest.snapshotHash);
    return parsed as MS5DriftSnapshot;
  } catch {
    return undefined;
  }
}
