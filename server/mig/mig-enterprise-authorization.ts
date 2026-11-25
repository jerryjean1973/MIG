/**
 * Enterprise authorization entry point. Authentication adapters resolve a
 * VerifiedCredentialIdentity first; this entry point is the final common MIG
 * evaluator for every credential type. It intentionally does not authenticate
 * credentials or invoke downstream MCP tools.
 */
import { storage } from "../storage";
import { normalizeAuthorizationContext, type MigAuthorizationRequest, type VerifiedCredentialIdentity } from "./mig-authorization-context";
import { evaluateAuthorization, type MigAuthorizationDecision, type MigEffectiveEntitlement, type MigTenantAuthorizationPolicy } from "./mig-authorization-policy";
import type { MigAuthorizationCatalog } from "./mig-authorization-catalog";
import { persistAuthorizationManifest, persistRejectedAuthorizationManifest } from "./mig-audit";
import type { MigCapabilityManifest, MigIntentDefinition, MigRemoteAgent, MigTicket } from "@shared/schema";
import { resolveTenantAuthority, type AuthorityProviderInput } from "./mig-authority-provider";
import {
  resolveTrustedCanonicalKnowledgeResource,
  isCanonicalKnowledgeResourceRef,
  type CanonicalKnowledgeAuthorityDecision,
  type CanonicalKnowledgeResource,
  type CBAuthorityOperation,
} from "@shared/corporate-brain/canonical-knowledge-authority";

export type MigCanonicalKnowledgeResolver = (input: {
  tenantId: string;
  principalId: string;
  intentId: string;
  resource: CanonicalKnowledgeResource;
  operation: import("../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority").CBAuthorityOperation;
  serviceId: string;
  accessPath: string;
  capabilityIds: string[];
  evaluatedAt?: string;
}) => Promise<CanonicalKnowledgeAuthorityDecision | undefined>;

/** Protected knowledge aliases cannot use the ordinary MIG resource path. */
export function isProtectedCanonicalKnowledgeAlias(resourceRef: string): boolean {
  return /^(?:cb:|knowledge:|corporate[-_:]?brain:|vendor[-_:]?risk[-_:]?score:)/i.test(resourceRef);
}

export function canonicalKnowledgeResolutionMatches(
  requested: CanonicalKnowledgeResource,
  resolved: CanonicalKnowledgeAuthorityDecision | undefined,
  operation: CBAuthorityOperation,
): boolean {
  return Boolean(
    resolved
    && resolved.resource.tenant_id === requested.tenant_id
    && resolved.resource.partition === requested.partition
    && resolved.resource.canonical_object_id === requested.canonical_object_id
    && resolved.resource.knowledge_id === requested.knowledge_id
    && resolved.resource.version === requested.version
    && resolved.operation === operation,
  );
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}
function credentialCeilings(binding: import("@shared/schema").MigCredentialBinding) {
  return {
    credentialCapabilityCeiling: asStrings(binding.capabilityCeiling),
    credentialScopes: asStrings(binding.scopes),
    credentialIntentCeiling: asStrings(binding.allowedIntents),
    credentialDomainCeiling: asStrings(binding.allowedDomains),
    credentialMcpTargetCeiling: asStrings(binding.allowedMcpTargets),
    credentialResourceCeiling: asStrings(binding.resourceScopes),
    credentialRiskZoneCeiling: ["low", "medium", "high", "critical"].includes(binding.riskZoneCeiling ?? "")
      ? binding.riskZoneCeiling as "low" | "medium" | "high" | "critical" : undefined,
  };
}

function denied(reason: string): MigAuthorizationDecision {
  return {
    decision: "deny",
    reason,
    effectivePermissions: [],
    sodResult: { static: "pass", dynamic: "pass" },
  };
}

/** Resolves only an opaque credential reference after its authenticator succeeds. */
export async function resolveVerifiedCredential(credentialRef: string): Promise<VerifiedCredentialIdentity | undefined> {
  if (!credentialRef) return undefined;
  const binding = await storage.getActiveMigCredentialBinding(credentialRef);
  if (!binding || (binding.expiresAt && binding.expiresAt.getTime() <= Date.now())) return undefined;
  const principal = await storage.getMigPrincipal(binding.tenantId, binding.principalId);
  if (!principal || principal.tenantId !== binding.tenantId || principal.principalId !== binding.principalId) return undefined;
  return {
    credentialRef: binding.credentialRef,
    credentialType: binding.credentialType as VerifiedCredentialIdentity["credentialType"],
    principalId: principal.principalId,
    tenantId: principal.tenantId,
    principalType: principal.principalType as VerifiedCredentialIdentity["principalType"],
    principalStatus: principal.status as VerifiedCredentialIdentity["principalStatus"],
    credentialStatus: binding.status as VerifiedCredentialIdentity["credentialStatus"],
    ...credentialCeilings(binding),
  };
}

export async function authorizeEnterpriseRequest(
  verifiedCredential: VerifiedCredentialIdentity | undefined,
  request: MigAuthorizationRequest,
  catalog: MigAuthorizationCatalog,
  canonicalKnowledgeResolver?: MigCanonicalKnowledgeResolver,
): Promise<{ decision: MigAuthorizationDecision; authorizationManifestId?: string; policyVersion: string }> {
  const normalized = normalizeAuthorizationContext(verifiedCredential, request);
  if (!normalized.context) {
    const decision = denied(normalized.reason ?? "authorization_context_invalid");
    const manifest = await persistRejectedAuthorizationManifest(decision.reason, catalog.version, request);
    return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion: catalog.version };
  }
  const identityRefs = [
    normalized.context.actorPrincipalId,
    normalized.context.clientPrincipalId,
    normalized.context.executorPrincipalId,
  ].filter((value): value is string => Boolean(value));
  for (const principalId of new Set(identityRefs)) {
    const principal = await storage.getMigPrincipal(normalized.context.tenantId, principalId);
    if (!principal || principal.status !== "active") {
      const decision = denied("related_principal_unknown_or_inactive");
      const manifest = await persistAuthorizationManifest(normalized.context, decision, catalog.version);
      return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion: catalog.version };
    }
  }
  if (normalized.context.canonicalKnowledge) {
    const candidate = normalized.context.canonicalKnowledge;
    try {
      resolveTrustedCanonicalKnowledgeResource({
        authenticated_tenant_id: normalized.context.tenantId,
        requested_tenant_id: normalized.context.tenantId,
        resource_ref: normalized.context.resourceRef,
        resource: candidate.resource,
      });
    } catch (error) {
      const decision = denied(error instanceof Error ? error.message : "canonical_knowledge_resource_unresolved");
      const manifest = await persistAuthorizationManifest(normalized.context, decision, catalog.version);
      return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion: catalog.version };
    }
    // Preliminary MIG authorization is intentionally not a second CB
    // evaluation. Protected MCP dispatch performs the exact server-owned CB
    // ALLOW check after MIG policy has allowed the request. Direct callers
    // without a binding remain fail-closed below.
    if (!canonicalKnowledgeResolver && !normalized.context.canonicalKnowledgeBinding) {
      const decision = denied("canonical_knowledge_authority_unresolved");
      const manifest = await persistAuthorizationManifest(normalized.context, decision, catalog.version);
      return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion: catalog.version };
    }
    if (canonicalKnowledgeResolver) normalized.context.canonicalKnowledge = {
      ...candidate,
      authority: await canonicalKnowledgeResolver({
        tenantId: normalized.context.tenantId,
        principalId: normalized.context.credential.principalId,
        intentId: normalized.context.intentId,
        resource: candidate.resource,
        operation: candidate.operation,
        serviceId: "mig",
        accessPath: "enterprise_authorization",
        capabilityIds: [normalized.context.capabilityId],
        evaluatedAt: undefined,
      }),
    };
    else normalized.context.canonicalKnowledge = { ...candidate, authority_state: "DEFERRED_TO_PROTECTED_DISPATCH" };
    if (canonicalKnowledgeResolver && !canonicalKnowledgeResolutionMatches(
      candidate.resource,
      normalized.context.canonicalKnowledge.authority,
      candidate.operation,
    )) {
      const decision = denied("canonical_knowledge_resolver_target_mismatch");
      const manifest = await persistAuthorizationManifest(normalized.context, decision, catalog.version);
      return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion: catalog.version };
    }
  }
  if (
    (isCanonicalKnowledgeResourceRef(normalized.context.resourceRef)
      || isProtectedCanonicalKnowledgeAlias(normalized.context.resourceRef))
    && (!normalized.context.canonicalKnowledge || !normalized.context.canonicalKnowledgeBinding)
  ) {
    const decision = denied("canonical_knowledge_authority_unresolved");
    const manifest = await persistAuthorizationManifest(normalized.context, decision, catalog.version);
    return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion: catalog.version };
  }
  const intent = await storage.getMigIntentDefinition(normalized.context.intentId);
  if (!intent || intent.status !== "published") {
    const decision = denied("unknown_intent");
    const manifest = await persistAuthorizationManifest(normalized.context, decision, catalog.version);
    return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion: catalog.version };
  }
  const intentAllowedCapabilities = asStrings(intent.allowedCapabilityIds);
  const intentDeniedCapabilities = asStrings(intent.deniedCapabilityIds);
  const intentDomains = asStrings(intent.domainScope);
  const catalogEntry = catalog.entries.get(normalized.context.capabilityId);
  const riskRank = { low: 0, medium: 1, high: 2, critical: 3 } as const;
  const intentRisk = intent.riskZone as keyof typeof riskRank;
  const intentDenial =
    intentDeniedCapabilities.includes(normalized.context.capabilityId) ? "intent_capability_explicitly_denied" :
    intentAllowedCapabilities.length > 0 && !intentAllowedCapabilities.includes(normalized.context.capabilityId) ? "intent_capability_not_allowed" :
    intentDomains.length > 0 && !intentDomains.includes("*") && !intentDomains.includes(normalized.context.domainId) ? "intent_domain_not_allowed" :
    catalogEntry && (!intentRisk || riskRank[catalogEntry.riskZone] > riskRank[intentRisk]) ? "intent_risk_zone_exceeded" :
    undefined;
  if (intentDenial) {
    const decision = denied(intentDenial);
    const manifest = await persistAuthorizationManifest(normalized.context, decision, catalog.version);
    return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion: catalog.version };
  }
  const row = await storage.getActiveMigPrincipalEntitlement(normalized.context.tenantId, normalized.context.credential.principalId);
  const entitlement: MigEffectiveEntitlement | undefined = row ? {
    capabilityIds: asStrings(row.capabilityIds),
    domainIds: asStrings(row.domainIds),
    intentIds: asStrings(row.intentIds),
    resourceScopes: asStrings(row.resourceScopes),
    // Static SoD evaluates the full local assignment. External projection may
    // reduce executable authority, but can never erase a local conflict.
    assignedRoles: asStrings(row.assignedRoles),
  } : undefined;
  const tenantRow = await storage.getMigTenantAuthorizationPolicy(normalized.context.tenantId);
  const tenantPolicy: MigTenantAuthorizationPolicy | undefined = tenantRow ? {
    status: tenantRow.status === "active" ? "active" : "suspended",
    capabilityIds: asStrings(tenantRow.capabilityIds),
    domainIds: asStrings(tenantRow.domainIds),
    intentIds: asStrings(tenantRow.intentIds),
    resourceScopes: asStrings(tenantRow.resourceScopes),
    allowedRiskZones: asStrings(tenantRow.allowedRiskZones).filter(
      (zone): zone is MigTenantAuthorizationPolicy["allowedRiskZones"][number] =>
        zone === "low" || zone === "medium" || zone === "high" || zone === "critical",
    ),
    allowedResourceStates: asStrings(tenantRow.allowedResourceStates),
    staticSodConflicts: Array.isArray(tenantRow.staticSodConflicts)
      ? tenantRow.staticSodConflicts.filter(
          (pair): pair is [string, string] =>
            Array.isArray(pair) && pair.length === 2 && pair.every(value => typeof value === "string"),
        )
      : [],
  } : undefined;
  const decision = evaluateAuthorization(normalized.context, entitlement, catalog, tenantPolicy);
  const policyVersion = tenantRow?.version ?? catalog.version;
  const manifest = await persistAuthorizationManifest(normalized.context, decision, policyVersion);
  return { decision, authorizationManifestId: manifest.authorizationManifestId, policyVersion };
}

export async function authorizeEnterpriseCredentialReference(
  credentialRef: string,
  request: MigAuthorizationRequest,
  catalog: MigAuthorizationCatalog,
  canonicalKnowledgeResolver?: MigCanonicalKnowledgeResolver,
): Promise<{ decision: MigAuthorizationDecision; authorizationManifestId?: string }> {
  const binding = await storage.getActiveMigCredentialBinding(credentialRef);
  const verifiedCredential = binding
    ? await resolveTenantAuthority({ tenantId: binding.tenantId, credentialRef })
    : undefined;
  if (!verifiedCredential) {
    const decision = denied("unknown_credential");
    const manifest = await persistRejectedAuthorizationManifest(
      decision.reason,
      catalog.version,
      request,
      credentialRef,
    );
    return { decision, authorizationManifestId: manifest.authorizationManifestId };
  }
  return authorizeEnterpriseRequest(verifiedCredential, request, catalog, canonicalKnowledgeResolver);
}

export async function authorizeDualModeRequest(
  authority: AuthorityProviderInput,
  request: MigAuthorizationRequest,
  catalog: MigAuthorizationCatalog,
  canonicalKnowledgeResolver?: MigCanonicalKnowledgeResolver,
): Promise<{ decision: MigAuthorizationDecision; authorizationManifestId?: string; policyVersion: string }> {
  const verified = await resolveTenantAuthority(authority);
  return authorizeEnterpriseRequest(verified, request, catalog, canonicalKnowledgeResolver);
}

export async function authorizeLegacyMigTicketRequest(input: {
  agent: MigRemoteAgent;
  ticket: MigTicket;
  intent: MigIntentDefinition;
  manifest: MigCapabilityManifest;
  request: MigAuthorizationRequest;
  catalog: MigAuthorizationCatalog;
}): Promise<{ decision: MigAuthorizationDecision; authorizationManifestId?: string }> {
  const { agent, ticket, manifest, request, catalog } = input;
  const principalId = agent.principalId ?? `mig-agent:${agent.agentId}`;
  const persistKnownTicketDenial = async (reason: string, principalStatus: VerifiedCredentialIdentity["principalStatus"]) => {
    const decision = denied(reason);
    const context = {
      ...request,
      tenantId: ticket.tenantId,
      actorPrincipalId: principalId,
      clientPrincipalId: principalId,
      executorPrincipalId: principalId,
      delegationRef: manifest.manifestId,
      requestCorrelationId: request.requestCorrelationId ?? ticket.jti,
      credential: {
        credentialRef: `mig-ticket:${ticket.jti}`,
        credentialType: "mig_agent" as const,
        principalId,
        tenantId: ticket.tenantId,
        principalType: "agent" as const,
        principalStatus,
        credentialStatus: "active" as const,
        credentialCapabilityCeiling: asStrings(manifest.allowedCapabilities),
        credentialScopes: [],
        credentialIntentCeiling: [],
        credentialDomainCeiling: [],
        credentialMcpTargetCeiling: [],
        credentialResourceCeiling: [],
        actorPrincipalId: principalId,
        clientPrincipalId: principalId,
        executorPrincipalId: principalId,
      },
    };
    const proof = await persistAuthorizationManifest(context, decision, catalog.version);
    return { decision, authorizationManifestId: proof.authorizationManifestId };
  };
  const principal = await storage.getMigPrincipal(agent.tenantId, principalId);
  if (!principal) {
    return persistKnownTicketDenial("agent_principal_unknown", "suspended");
  }
  if (principal.status !== "active") {
    return persistKnownTicketDenial(
      "principal_not_active",
      principal.status as VerifiedCredentialIdentity["principalStatus"],
    );
  }

  const allowedCapabilities = asStrings(manifest.allowedCapabilities);
  const credentialRef = `mig-ticket:${ticket.jti}`;
  let ticketBinding = await storage.getActiveMigCredentialBinding(credentialRef);
  if (!ticketBinding) {
    ticketBinding = await storage.createMigCredentialBinding({
      credentialRef,
      tenantId: ticket.tenantId,
      principalId,
      credentialType: "mig_agent",
      providerKind: "mcp",
      status: "active",
        capabilityCeiling: allowedCapabilities,
        allowedCapabilities,
        // A historic ticket never silently receives scope authority.
        scopes: [],
        allowedIntents: [],
        allowedDomains: [],
        allowedMcpTargets: [],
        resourceScopes: [],
      expiresAt: ticket.expiresAt,
    });
  }
  if (ticketBinding.tenantId !== ticket.tenantId || ticketBinding.principalId !== principalId) {
    return persistKnownTicketDenial("ticket_credential_binding_mismatch", "suspended");
  }
  const verifiedCredential: VerifiedCredentialIdentity = {
    credentialRef,
    credentialType: "mig_agent",
    principalId,
    tenantId: ticket.tenantId,
    principalType: "agent",
    principalStatus: "active",
    credentialStatus: "active",
    ...credentialCeilings(ticketBinding),
    actorPrincipalId: principalId,
    clientPrincipalId: principalId,
    executorPrincipalId: principalId,
  };
  // Legacy tickets authenticate an already-registered principal and contribute
  // only a credential capability ceiling. Persisted principal entitlements and
  // tenant policy remain the sole authority for domain, intent, resource, role,
  // risk, and SoD decisions. Request targets are checked, never merged.
  return authorizeEnterpriseRequest(verifiedCredential, {
    ...request,
    intentId: ticket.intentId,
    delegationRef: manifest.manifestId,
    requestCorrelationId: request.requestCorrelationId ?? ticket.jti,
  }, catalog);
}