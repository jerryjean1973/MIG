/**
 * Governance/UI adapter, layers 13/15. Reuses the bounded network probe and
 * canonical entitlements. No execution, credential issue or discovery admission
 * is performed by a connection test.
 */
import { storage } from "../storage";
import { probeMcpEndpoint } from "./mig-registry-network";
import type { MigSimpleConnectionTest, MigSimplePermissions, MigSimpleTool } from "@shared/mig-simple-connection";

export const stringValues = (value: unknown): string[] =>
  Array.isArray(value) ? [...new Set(value.filter((v): v is string => typeof v === "string"))] : [];

export function projectSimpleTools(value: unknown): MigSimpleTool[] {
  if (!Array.isArray(value)) return [];
  return value.filter(tool => tool && typeof tool.name === "string").map(tool => ({
    name: tool.name,
    ...(typeof tool.description === "string" ? { description: tool.description } : {}),
    ...(typeof (tool.capability_id ?? tool.capabilityId) === "string"
      ? { capability_id: tool.capability_id ?? tool.capabilityId } : {}),
  }));
}

export async function testMigConnection(endpoint: unknown): Promise<MigSimpleConnectionTest> {
  if (typeof endpoint !== "string" || !/^https:\/\//i.test(endpoint)) throw new Error("MIG_CONNECTION_HTTPS_ENDPOINT_REQUIRED");
  let url: URL;
  try { url = new URL(endpoint); } catch { throw new Error("MIG_CONNECTION_ENDPOINT_INVALID"); }
  if (url.username || url.password || url.hash) throw new Error("MIG_CONNECTION_ENDPOINT_INVALID");
  const probe = await probeMcpEndpoint(endpoint, [url.origin], "api");
  const tools = projectSimpleTools(probe.toolDeclarations);
  return {
    endpoint, identity: typeof probe.serverInfo?.name === "string" ? probe.serverInfo.name : null,
    protocol_version: probe.protocolVersion, handshake_status: "compatible",
    capabilities: [...new Set(tools.flatMap(tool => tool.capability_id ? [tool.capability_id] : []))],
    tools, supports_lineage: probe.mig?.lineage === true,
    supports_outcomes: probe.mig?.terminalOutcomes === true,
    secure_credential_delivery: typeof probe.mig?.credentialBindingMethod === "string",
    registered: false, authority_granted: false,
  };
}

export async function readSimpleMigPermissions(tenantId: string, candidateId: string): Promise<MigSimplePermissions> {
  const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
  if (!candidate || candidate.clientClass !== "MCP" || !candidate.principalId) throw new Error("MIG_CONNECTION_REGISTRATION_NOT_FOUND");
  const [entitlement, client, policy, authority, roles, principal, soleClient] = await Promise.all([
    storage.getActiveMigPrincipalEntitlement(tenantId, candidate.principalId),
    storage.getActiveMigClientByComponent(tenantId, candidate.componentId),
    storage.getMigTenantAuthorizationPolicy(tenantId),
    storage.getMigTenantAuthorityConfig(tenantId), storage.getMigConnectionRoles(tenantId),
    storage.getMigPrincipal(tenantId, candidate.principalId),
    storage.getActiveMigClientByPrincipal(tenantId, candidate.principalId),
  ]);
  const blockers: string[] = [];
  if (!["registered", "trusted"].includes(candidate.state) || client?.principalId !== candidate.principalId) blockers.push("ACTIVE_REGISTRATION_REQUIRED");
  if (!entitlement) blockers.push("ACTIVE_PRINCIPAL_ENTITLEMENT_REQUIRED");
  if (principal?.status !== "active" || principal.subjectRef?.startsWith("host-operator:")) blockers.push("ACTIVE_MCP_PRINCIPAL_REQUIRED");
  if (soleClient?.componentId !== candidate.componentId) blockers.push("SHARED_PRINCIPAL_NOT_EDITABLE");
  if (policy?.status !== "active") blockers.push("ACTIVE_TENANT_POLICY_REQUIRED");
  if (authority?.status !== "active" || authority.authorityProvider !== "mig_native" ||
      authority.executionFabric !== "mig_managed" || authority.deploymentMode !== "full_control_plane") {
    blockers.push("NATIVE_MANAGED_AUTHORITY_REQUIRED");
  }
  const binding = client ? await storage.getActiveMigCredentialBinding(`mig-key:${client.credentialHash}`) : undefined;
  if (!binding || binding.tenantId !== tenantId || binding.principalId !== candidate.principalId ||
      binding.expiresAt && binding.expiresAt <= new Date()) blockers.push("ACTIVE_SCOPED_CREDENTIAL_REQUIRED");
  const ceilings = [entitlement?.intentIds, binding?.allowedIntents, policy?.intentIds].map(stringValues);
  const requested = stringValues((candidate.target as any)?.credential_authority?.assigned?.allowed_intents);
  const allowed = requested.filter(id => ceilings.every(values => values.includes("*") || values.includes(id)));
  // Roles come from the tenant's existing catalog, never arbitrary browser input.
  return {
    candidate_id: candidateId, principal_id: candidate.principalId, entitlement_id: entitlement?.entitlementId ?? null,
    allowed_intents: stringValues(entitlement?.intentIds).includes("*") ? allowed : stringValues(entitlement?.intentIds),
    assigned_roles: stringValues(entitlement?.assignedRoles), intent_options: allowed,
    role_options: roles, editable: blockers.length === 0, blockers,
  };
}

export async function saveSimpleMigPermissions(tenantId: string, actorId: string, candidateId: string, body: any) {
  if (!body || Object.keys(body).some(key => !["entitlement_id", "allowed_intents", "assigned_roles"].includes(key)) ||
      typeof body.entitlement_id !== "string" ||
      ![body.allowed_intents, body.assigned_roles].every(values => Array.isArray(values) && values.length <= 100 &&
        values.every(value => typeof value === "string" && value.length > 0 && value.length <= 128))) {
    throw new Error("MIG_CONNECTION_PERMISSIONS_INVALID");
  }
  const current = await readSimpleMigPermissions(tenantId, candidateId);
  if (!current.editable) throw new Error("MIG_CONNECTION_PERMISSIONS_NOT_EDITABLE");
  if (body.entitlement_id !== current.entitlement_id) throw new Error("MIG_CONNECTION_PERMISSIONS_CONFLICT");
  const intents = stringValues(body.allowed_intents), roles = stringValues(body.assigned_roles);
  if (intents.some(id => !current.intent_options.includes(id)) ||
      roles.some(role => !current.role_options.some(option => option.key === role) && !current.assigned_roles.includes(role))) {
    throw new Error("MIG_CONNECTION_PERMISSIONS_OUTSIDE_CEILING");
  }
  await storage.replaceMigConnectionPermissions({
    tenantId, actorId, candidateId, expectedEntitlementId: body.entitlement_id, intentIds: intents, assignedRoles: roles,
  });
  return readSimpleMigPermissions(tenantId, candidateId);
}
