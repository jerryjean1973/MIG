/**
 * Small provisioning extension of MIG's canonical principal/client/binding owners.
 * The marker is persisted by the administrator, never accepted as caller authority.
 * No policy bootstrap, external-provider projection, or new credential framework.
 */
import { randomUUID } from "crypto";
import { storage } from "../storage";
import { registerMigClient, revokeMigClient } from "./mig-client-lineage";
import { recordMigAuditEvent } from "./mig-audit";
import { buildBripeAuthorizationCatalog, bripeToolCatalog, DOMAIN_DISCOVERY_TOOL_NAMES } from "./mig-bripe-adapter";
import { MCP_ACCESS_PRESETS } from "@shared/mcp-access-presets";
import { buildRemoteMcpConfig, REMOTE_MCP_CLIENT_KINDS, type RemoteMcpClientKind, type RemoteMcpClientProjection } from "@shared/remote-mcp-config";
import type { MigClient, MigCredentialBinding } from "@shared/schema";

export const REMOTE_MCP_MARKER = "remote-mcp:read_only:v1";
export const REMOTE_MCP_INTENT = "domain_discovery";
// Existing Read Only preset, restricted further to the existing domain-discovery intent.
export const REMOTE_MCP_PRESETS = [{
  id: "read_only", label: "Read Only — domain discovery",
  description: "List and inspect published domain packages. No execution, approval, or administrator tools.",
}] as const;
export const REMOTE_MCP_TOOLS = DOMAIN_DISCOVERY_TOOL_NAMES;
export const remoteMcpResource = (tenantId: string) => `mcp:catalog:${tenantId}`;

export function remoteMcpKind(componentId: string): RemoteMcpClientKind | undefined {
  const parts = componentId.split(":");
  return parts.length === 3 && parts[0] === "remote-mcp" &&
    REMOTE_MCP_CLIENT_KINDS.includes(parts[1] as RemoteMcpClientKind)
    ? parts[1] as RemoteMcpClientKind : undefined;
}
export function isProvisionedRemoteMcpClient(client: MigClient, binding: MigCredentialBinding | undefined) {
  return client.clientClass === "MCP" && !!remoteMcpKind(client.componentId) &&
    !!binding && Array.isArray(binding.scopes) && binding.scopes.includes(REMOTE_MCP_MARKER) &&
    binding.tenantId === client.tenantId && binding.principalId === client.principalId;
}
export function remoteMcpEndpoint(): string {
  // Do not fall back to request Host, a guessed deployment domain, or loopback.
  const endpoint = process.env.MCP_RESOURCE_URL;
  if (!endpoint) throw new Error("Set MCP_RESOURCE_URL to this Docker application's externally reachable HTTPS /api/mcp address before creating remote clients.");
  buildRemoteMcpConfig("claude_code", endpoint, "validation-only");
  return new URL(endpoint).href;
}

/** Checks canonical availability without mutating policy or fabric configuration. */
export async function remoteMcpReadiness(tenantId: string) {
  const endpoint = remoteMcpEndpoint();
  const [config, policy, intent] = await Promise.all([
    storage.getMigTenantAuthorityConfig(tenantId),
    storage.getMigTenantAuthorizationPolicy(tenantId),
    storage.getMigIntentDefinition(REMOTE_MCP_INTENT),
  ]);
  if (config && (config.status !== "active" || config.authorityProvider !== "mig_native" ||
      config.deploymentMode !== "full_control_plane")) {
    throw new Error("Remote client quick config requires active MIG-native Full Control Plane authority. Enterprise-managed authority is unchanged; use its existing onboarding.");
  }
  if (!policy || policy.status !== "active") {
    throw new Error("An active canonical tenant authorization policy is required. Configure it in MIG before creating a client.");
  }
  if (!intent || intent.status !== "published") {
    throw new Error("The existing domain_discovery intent must be active in MIG before creating a client.");
  }
  const catalog = buildBripeAuthorizationCatalog([REMOTE_MCP_INTENT]);
  const domains = [...catalog.domains].filter(domain => domain !== "*");
  // A real canonical domain, never a wildcard invented by the UI.
  const allows = (values: unknown, value: string) =>
    Array.isArray(values) && (values.includes("*") || values.includes(value));
  const permittedDomains = domains.filter(domain => allows(policy.domainIds, domain));
  const domain = permittedDomains.sort()[0];
  const catalogTools = bripeToolCatalog();
  const tools = REMOTE_MCP_TOOLS.filter(name => {
    const entry = catalogTools.find(tool => tool.tool_name === name);
    return entry && entry.classification === "read_only" && entry.semantic_action === "read" &&
      allows(policy.capabilityIds, entry.capability_id) && allows(intent.allowedToolNames, name);
  });
  if (!domain || !tools.includes("list_domains") ||
      !allows(policy.intentIds, REMOTE_MCP_INTENT) ||
      !allows(policy.resourceScopes, remoteMcpResource(tenantId)) ||
      !Array.isArray(policy.allowedRiskZones) || !policy.allowedRiskZones.includes("low")) {
    throw new Error("Tenant policy must permit domain_discovery, a canonical domain, list_domains, low risk, and the tenant MCP catalog resource. Configure these bounded permissions in MIG.");
  }
  return { endpoint, domain, tools,
    capabilities: [...new Set(catalogTools.filter(tool => tools.includes(tool.tool_name)).map(tool => tool.capability_id))] };
}

export async function listRemoteMcpClients(tenantId: string): Promise<RemoteMcpClientProjection[]> {
  const clients = await storage.listMigClients(tenantId);
  return Promise.all(clients.filter(client => remoteMcpKind(client.componentId)).map(async client => ({
    id: client.componentId,
    name: (await storage.getMigPrincipal(tenantId, client.principalId))?.displayName ?? "Remote client",
    clientKind: remoteMcpKind(client.componentId)!,
    preset: "read_only" as const,
    status: client.status,
    createdAt: client.createdAt.toISOString(),
  })));
}

export async function provisionRemoteMcpClient(tenantId: string, actorId: string, body: unknown) {
  const input = body as Record<string, unknown> | undefined;
  if (!input || Object.keys(input).some(key => !["name", "clientKind", "preset"].includes(key)) ||
      typeof input.name !== "string" || !input.name.trim() || input.name.trim().length > 80 ||
      /[\x00-\x1f\x7f]/.test(input.name) ||
      !REMOTE_MCP_CLIENT_KINDS.includes(input.clientKind as RemoteMcpClientKind) || input.preset !== "read_only") {
    throw new Error("Supply a client name (1–80 characters), a supported client type, and the Read Only preset. Authority overrides are not accepted.");
  }
  const ready = await remoteMcpReadiness(tenantId);
  const componentId = `remote-mcp:${input.clientKind}:${randomUUID()}`;
  const principalId = `remote-mcp-principal:${randomUUID()}`;
  await storage.createMigPrincipal({ tenantId, principalId, principalType: "service",
    subjectRef: componentId, displayName: input.name.trim(), status: "active" });
  await storage.createMigPrincipalEntitlement({
    entitlementId: `mig_entitlement_${randomUUID()}`, tenantId, principalId,
    capabilityIds: ready.capabilities, domainIds: [ready.domain], intentIds: [REMOTE_MCP_INTENT],
    resourceScopes: [remoteMcpResource(tenantId)], assignedRoles: [], status: "active",
  });
  let client: MigClient | undefined;
  try {
    const issued = await registerMigClient({
      tenantId, componentId, principalId, clientClass: "MCP", originUserId: actorId,
      capabilityCeiling: ready.capabilities, allowedCapabilities: ready.capabilities,
      scopes: [...MCP_ACCESS_PRESETS.read_only, "mcp:invoke", "mcp:result", REMOTE_MCP_MARKER],
      allowedIntents: [REMOTE_MCP_INTENT], allowedDomains: [ready.domain],
      allowedMcpTargets: [componentId], resourceScopes: [remoteMcpResource(tenantId)], riskZoneCeiling: "low",
    });
    client = issued.client;
    // Validate actual policy/admission/dispatch before handing out a usable connection.
    const { establishRemoteMcpLineage } = await import("../mcp/remote-mcp-ingress");
    const { resolveTenantAuthority } = await import("./mig-authority-provider");
    const credential = await resolveTenantAuthority({ tenantId, credentialRef: `mig-key:${client.credentialHash}` });
    if (!credential) throw new Error("Canonical credential authority is unavailable.");
    await establishRemoteMcpLineage(client, credential, ready.tools);
    await recordMigAuditEvent({ tenantId, originUserId: actorId, authenticatedPrincipalId: principalId,
      agentId: componentId, eventType: "agent_registered", decision: "allow",
      policyDecision: "remote_mcp_read_only_provisioned", reason: "bounded_read_only_remote_client" });
    return {
      client: { id: componentId, name: input.name.trim(), clientKind: input.clientKind as RemoteMcpClientKind,
        preset: "read_only" as const, status: client.status, createdAt: client.createdAt.toISOString() },
      connection: buildRemoteMcpConfig(input.clientKind as RemoteMcpClientKind, ready.endpoint, issued.apiKey),
    };
  } catch (error) {
    // Never leave usable credentials behind when readiness/provisioning fails.
    await revokeMigClient(tenantId, componentId);
    throw error;
  }
}

export async function revokeRemoteMcpClient(tenantId: string, actorId: string, id: string) {
  const client = (await storage.listMigClients(tenantId)).find(row => row.componentId === id && remoteMcpKind(row.componentId));
  if (!client) return false;
  if (client.status !== "revoked") await revokeMigClient(tenantId, id);
  await recordMigAuditEvent({ tenantId, originUserId: actorId, agentId: id, eventType: "agent_status_changed",
    decision: "deny", policyDecision: "remote_mcp_client_revoked", reason: "administrator_revocation" });
  return true;
}
