import { createHash } from "node:crypto";
import { and, desc, eq } from "drizzle-orm";
import { db } from "../db";
import { migMcpSchemaAccessAlerts, migMcpSchemaObservations, workflowNotifications } from "@shared/schema";
import type { CanonicalMCPKnowledgeBinding } from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";

export interface MigMcpSchemaObservationInput {
  observation_id: string;
  tenant_id: string; mcp_server_id: string; mcp_tool_name: string;
  schema_version: string; schema_fingerprint: string; observed_at: string; source_proof_ref: string;
}
export interface MigMcpSchemaObservationRepository {
  insert(observation: MigMcpSchemaObservationInput): Promise<void>;
  list(tenant_id: string, mcp_server_id: string, mcp_tool_name: string): Promise<readonly MigMcpSchemaObservationInput[]>;
}
export interface MigMcpSchemaAccessAlert {
  alert_id: string;
  tenant_id: string;
  mcp_server_id: string;
  mcp_tool_name: string;
  prior_binding_id: string;
  prior_schema_version: string;
  prior_schema_fingerprint: string;
  observed_schema_version: string;
  observed_schema_fingerprint: string;
  observation_id: string;
  detected_at: string;
}
export interface MigMcpSchemaAccessAlertRepository {
  insert(alert: MigMcpSchemaAccessAlert): Promise<void>;
  list(tenant_id: string): Promise<readonly MigMcpSchemaAccessAlert[]>;
}
export interface MigMcpSchemaAccessNotification {
  tenant_id: string;
  mcp_server_id: string;
  mcp_tool_name: string;
  prior_binding_id: string;
  observed_schema_fingerprint: string;
}
export interface MigMcpSchemaAccessNotificationChannel {
  deliver(notification: MigMcpSchemaAccessNotification): Promise<void>;
}
export const databaseMigMcpSchemaObservationRepository: MigMcpSchemaObservationRepository = {
  async insert(observation) {
    await db.insert(migMcpSchemaObservations).values({
      observationId: observation.observation_id, tenantId: observation.tenant_id,
      mcpServerId: observation.mcp_server_id, mcpToolName: observation.mcp_tool_name,
      schemaVersion: observation.schema_version, schemaFingerprint: observation.schema_fingerprint,
      observedAt: new Date(observation.observed_at), sourceProofRef: observation.source_proof_ref,
    }).onConflictDoNothing({ target: migMcpSchemaObservations.observationId });
  },
  async list(tenant_id, mcp_server_id, mcp_tool_name) {
    const rows = await db.select().from(migMcpSchemaObservations).where(and(
      eq(migMcpSchemaObservations.tenantId, tenant_id),
      eq(migMcpSchemaObservations.mcpServerId, mcp_server_id),
      eq(migMcpSchemaObservations.mcpToolName, mcp_tool_name),
    )).orderBy(desc(migMcpSchemaObservations.observedAt));
    return rows.map(row => ({
      observation_id: row.observationId, tenant_id: row.tenantId, mcp_server_id: row.mcpServerId,
      mcp_tool_name: row.mcpToolName, schema_version: row.schemaVersion,
      schema_fingerprint: row.schemaFingerprint, observed_at: row.observedAt.toISOString(),
      source_proof_ref: row.sourceProofRef,
    }));
  },
};
export const databaseMigMcpSchemaAccessAlertRepository: MigMcpSchemaAccessAlertRepository = {
  async insert(alert) {
    await db.insert(migMcpSchemaAccessAlerts).values({
      alertId: alert.alert_id,
      tenantId: alert.tenant_id,
      mcpServerId: alert.mcp_server_id,
      mcpToolName: alert.mcp_tool_name,
      priorBindingId: alert.prior_binding_id,
      priorSchemaVersion: alert.prior_schema_version,
      priorSchemaFingerprint: alert.prior_schema_fingerprint,
      observedSchemaVersion: alert.observed_schema_version,
      observedSchemaFingerprint: alert.observed_schema_fingerprint,
      observationId: alert.observation_id,
      detectedAt: new Date(alert.detected_at),
    }).onConflictDoNothing({ target: migMcpSchemaAccessAlerts.alertId });
  },
  async list(tenant_id) {
    const rows = await db.select().from(migMcpSchemaAccessAlerts)
      .where(eq(migMcpSchemaAccessAlerts.tenantId, tenant_id))
      .orderBy(desc(migMcpSchemaAccessAlerts.detectedAt));
    return rows.map(row => ({
      alert_id: row.alertId,
      tenant_id: row.tenantId,
      mcp_server_id: row.mcpServerId,
      mcp_tool_name: row.mcpToolName,
      prior_binding_id: row.priorBindingId,
      prior_schema_version: row.priorSchemaVersion,
      prior_schema_fingerprint: row.priorSchemaFingerprint,
      observed_schema_version: row.observedSchemaVersion,
      observed_schema_fingerprint: row.observedSchemaFingerprint,
      observation_id: row.observationId,
      detected_at: row.detectedAt.toISOString(),
    }));
  },
};
export function schemaAccessNotification(
  alert: MigMcpSchemaAccessAlert,
): MigMcpSchemaAccessNotification {
  return {
    tenant_id: alert.tenant_id,
    mcp_server_id: alert.mcp_server_id,
    mcp_tool_name: alert.mcp_tool_name,
    prior_binding_id: alert.prior_binding_id,
    observed_schema_fingerprint: alert.observed_schema_fingerprint,
  };
}
export const governedMigMcpSchemaAccessNotificationChannel: MigMcpSchemaAccessNotificationChannel = {
  async deliver(notification) {
    const message = JSON.stringify(notification);
    await db.insert(workflowNotifications).values({
      channel: "governed_operator",
      eventType: "mcp_schema_access_blocked",
      message,
      tenantId: notification.tenant_id,
    }).onConflictDoNothing();
  },
};
export function observationId(input: Omit<MigMcpSchemaObservationInput, "observation_id">): string {
  return `mig_schema_obs_${createHash("sha256").update(JSON.stringify([
    input.tenant_id, input.mcp_server_id, input.mcp_tool_name, input.schema_version, input.schema_fingerprint,
    input.observed_at, input.source_proof_ref,
  ])).digest("hex").slice(0, 32)}`;
}
export function latestSchemaObservation(rows: readonly MigMcpSchemaObservationInput[]) {
  if (!rows.length) return undefined;
  const latestTime = Math.max(...rows.map(row => Date.parse(row.observed_at)));
  const latest = rows.filter(row => Date.parse(row.observed_at) === latestTime);
  if (new Set(latest.map(row => `${row.schema_version}:${row.schema_fingerprint}`)).size !== 1) return undefined;
  return latest[0];
}

export function schemaAccessAlertId(prior_binding_id: string, observation_id: string): string {
  return `mig_schema_alert_${createHash("sha256").update(`${prior_binding_id}:${observation_id}`).digest("hex").slice(0, 32)}`;
}

/** Returns a payload-free alert only when the newest observation invalidates the active confirmed leaf. */
export function detectMcpSchemaAccessAlert(input: {
  observation: MigMcpSchemaObservationInput;
  bindings: readonly CanonicalMCPKnowledgeBinding[];
}): MigMcpSchemaAccessAlert | undefined {
  const relevant = input.bindings.filter(binding =>
    binding.tenant_id === input.observation.tenant_id
    && binding.mcp_server_id === input.observation.mcp_server_id
    && binding.mcp_tool_name === input.observation.mcp_tool_name);
  const predecessors = new Set(relevant.map(binding => binding.supersedes_binding_id).filter(Boolean));
  const active = relevant.filter(binding =>
    ["CONFIRMED", "OVERRIDDEN"].includes(binding.status)
    && !predecessors.has(binding.binding_id));
  if (active.length !== 1) return undefined;
  const prior = active[0];
  if (prior.mcp_schema_version === input.observation.schema_version
    && prior.schema_fingerprint === input.observation.schema_fingerprint) return undefined;
  return {
    alert_id: schemaAccessAlertId(prior.binding_id, input.observation.observation_id),
    tenant_id: input.observation.tenant_id,
    mcp_server_id: input.observation.mcp_server_id,
    mcp_tool_name: input.observation.mcp_tool_name,
    prior_binding_id: prior.binding_id,
    prior_schema_version: prior.mcp_schema_version,
    prior_schema_fingerprint: prior.schema_fingerprint,
    observed_schema_version: input.observation.schema_version,
    observed_schema_fingerprint: input.observation.schema_fingerprint,
    observation_id: input.observation.observation_id,
    detected_at: input.observation.observed_at,
  };
}
