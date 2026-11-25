import { storage } from "../storage";
import { registerMigClient } from "./mig-client-lineage";

const COMPONENT_ID = "bcentrisk-session-facade";
const CAPABILITIES = ["shared/bripe/orchestrator.ts#BRIPeRuntimeOrchestrator.run"];
const INTENTS = ["decision_execution"];
const DOMAINS = ["bcentrisk"];
const LEGACY_POLICY_PREFIX = "legacy-mcp-compat-";

const allows = (values: string[], required: string) => values.includes("*") || values.includes(required);
const mergeAuthority = (current: string[], required: string[]): string[] =>
  [...new Set([...current, ...required])];

function policyAllowsFacade(policy: {
  capabilityIds: string[];
  domainIds: string[];
  intentIds: string[];
  allowedRiskZones: string[];
}): boolean {
  return CAPABILITIES.every(value => allows(policy.capabilityIds, value))
    && DOMAINS.every(value => allows(policy.domainIds, value))
    && INTENTS.every(value => allows(policy.intentIds, value))
    && policy.allowedRiskZones.includes("medium");
}

/**
 * Forward-only migration for the retired legacy MCP compatibility policy.
 * It does not edit the prior row and cannot reactivate or broaden a suspended
 * or administrator-authored policy.
 */
async function migrateActiveLegacyPolicy(
  tenantId: string,
  policy: NonNullable<Awaited<ReturnType<typeof storage.getLatestMigTenantAuthorizationPolicy>>>,
) {
  if (policy.status !== "active" || !policy.version.startsWith(LEGACY_POLICY_PREFIX)) {
    return policy;
  }
  const version = `bcentrisk-facade-from-${policy.id}-v1`;
  try {
    return await storage.createMigTenantAuthorizationPolicy({
      tenantId,
      version,
      status: "active",
      capabilityIds: mergeAuthority(policy.capabilityIds, CAPABILITIES),
      domainIds: mergeAuthority(policy.domainIds, DOMAINS),
      intentIds: mergeAuthority(policy.intentIds, INTENTS),
      resourceScopes: [...policy.resourceScopes],
      allowedRiskZones: mergeAuthority(policy.allowedRiskZones, ["medium"]),
      allowedResourceStates: [...policy.allowedResourceStates],
      staticSodConflicts: [...policy.staticSodConflicts],
    });
  } catch {
    return await storage.getLatestMigTenantAuthorizationPolicy(tenantId) ?? policy;
  }
}

export async function resolveBcentriskSessionFacade(tenantId: string) {
  const principalId = `service:bcentrisk-session-facade:${tenantId}`;
  const principal = await storage.getMigPrincipal(tenantId, principalId);
  const client = await storage.getActiveMigClientByComponent(tenantId, COMPONENT_ID);
  const policy = await storage.getLatestMigTenantAuthorizationPolicy(tenantId);
  const entitlement = await storage.getActiveMigPrincipalEntitlement(tenantId, principalId);
  if (!principal || principal.status !== "active" || !client || !policy || policy.status !== "active" || !entitlement) {
    return undefined;
  }
  if (!policyAllowsFacade(policy) ||
      !CAPABILITIES.every(value => allows(entitlement.capabilityIds, value)) ||
      !DOMAINS.every(value => allows(policy.domainIds, value) && allows(entitlement.domainIds, value)) ||
      !INTENTS.every(value => allows(entitlement.intentIds, value))) {
    return undefined;
  }
  return client;
}

/** Administrative tenant provisioning only; never called from request authentication. */
export async function provisionBcentriskSessionFacade(tenantId: string) {
  let policy = await storage.getLatestMigTenantAuthorizationPolicy(tenantId);
  if (!policy) {
    try {
      policy = await storage.createMigTenantAuthorizationPolicy({
        tenantId, version: "bcentrisk-session-facade-v1", status: "active",
        capabilityIds: CAPABILITIES, domainIds: DOMAINS, intentIds: INTENTS,
        resourceScopes: ["*"], allowedRiskZones: ["low", "medium", "high"],
        allowedResourceStates: [], staticSodConflicts: [],
      });
    } catch {
      policy = await storage.getLatestMigTenantAuthorizationPolicy(tenantId);
    }
  }
  if (policy && !policyAllowsFacade(policy)) {
    policy = await migrateActiveLegacyPolicy(tenantId, policy);
  }
  if (!policy || policy.status !== "active" || !policyAllowsFacade(policy)) {
    throw new Error("BCENTRISK_MIG_POLICY_UNAVAILABLE");
  }

  const principalId = `service:bcentrisk-session-facade:${tenantId}`;
  let principal = await storage.getMigPrincipal(tenantId, principalId);
  if (!principal) {
    try {
      principal = await storage.createMigPrincipal({
        tenantId, principalId, principalType: "service",
        subjectRef: principalId, displayName: "BCentrisk session façade", status: "active",
      });
    } catch {
      principal = await storage.getMigPrincipal(tenantId, principalId);
    }
  }
  if (!principal || principal.status !== "active") throw new Error("BCENTRISK_MIG_PRINCIPAL_UNAVAILABLE");

  let client = await storage.getActiveMigClientByComponent(tenantId, COMPONENT_ID);
  if (!client) {
    try {
      client = (await registerMigClient({
        tenantId, componentId: COMPONENT_ID, principalId, clientClass: "MCP",
        capabilityCeiling: CAPABILITIES, allowedCapabilities: CAPABILITIES,
        allowedIntents: INTENTS, allowedDomains: DOMAINS,
        allowedMcpTargets: [COMPONENT_ID],
        resourceScopes: ["*"], riskZoneCeiling: "high",
      })).client;
    } catch {
      client = await storage.getActiveMigClientByComponent(tenantId, COMPONENT_ID);
    }
  }
  if (!client) throw new Error("BCENTRISK_MIG_CLIENT_UNAVAILABLE");

  if (!await storage.getActiveMigPrincipalEntitlement(tenantId, principalId)) {
    try {
      await storage.createMigPrincipalEntitlement({
        entitlementId: `bcentrisk-session-facade:${tenantId}:v1`,
        tenantId, principalId, capabilityIds: CAPABILITIES, domainIds: DOMAINS,
        intentIds: INTENTS, resourceScopes: ["*"],
        assignedRoles: ["decision_consumer"], status: "active",
      });
    } catch {
      if (!await storage.getActiveMigPrincipalEntitlement(tenantId, principalId)) throw new Error("BCENTRISK_MIG_ENTITLEMENT_UNAVAILABLE");
    }
  }
  return resolveBcentriskSessionFacade(tenantId);
}