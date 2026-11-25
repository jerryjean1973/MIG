import { createHash, randomUUID } from "crypto";
import { storage } from "../storage";
import type { MigTenantAuthorityConfig } from "@shared/schema";
import type { VerifiedCredentialIdentity } from "./mig-authorization-context";
import { resolveEntraToken } from "../auth/entra-authority-verifier";

interface VerifiedExternalAuthorityClaims {
  provider: "microsoft_entra";
  tenantId: string;
  providerTenantRef: string;
  stableSubjectRef: string;
  scopes: string[];
  roles: string[];
  groups: string[];
  issuedAt: Date;
  expiresAt: Date;
}

export interface AuthorityProviderInput {
  tenantId: string;
  credentialRef?: string;
  entraJwt?: string;
}

export interface AuthorityProvider {
  readonly provider: "mig_native" | "microsoft_entra";
  resolve(config: MigTenantAuthorityConfig, input: AuthorityProviderInput): Promise<VerifiedCredentialIdentity | undefined>;
}

const strings = (value: unknown) => Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];

type EntraProjectionDimension = "capability" | "intent" | "domain" | "resource" | "target" | "role";
type EntraClaimKind = "scope" | "role" | "group";
const PROJECTION_DIMENSIONS: EntraProjectionDimension[] =
  ["capability", "intent", "domain", "resource", "target", "role"];

/**
 * Governed local mapping declarations use:
 * entra-map|<scope|role|group>|<verified-claim>|<dimension>|<value>
 * Claims select declarations; they never become authority by themselves.
 */
function projectEntraClaims(claims: VerifiedExternalAuthorityClaims, declarations: string[]) {
  const active: Record<EntraClaimKind, Set<string>> = {
    scope: new Set(claims.scopes), role: new Set(claims.roles), group: new Set(claims.groups),
  };
  const result = Object.fromEntries(PROJECTION_DIMENSIONS.map(d => [d, [] as string[]])) as
    Record<EntraProjectionDimension, string[]>;
  for (const declaration of declarations) {
    if (!declaration.startsWith("entra-map")) continue;
    const [prefix, kind, claim, dimension, ...valueParts] = declaration.split("|");
    const value = valueParts.join("|");
    if (prefix !== "entra-map" || valueParts.length !== 1 ||
        !["scope", "role", "group"].includes(kind) || !claim ||
        !PROJECTION_DIMENSIONS.includes(dimension as EntraProjectionDimension) || !value) {
      return { valid: false as const, projection: result };
    }
    if (!active[kind as EntraClaimKind].has(claim)) continue;
    result[dimension as EntraProjectionDimension].push(value);
  }
  for (const dimension of PROJECTION_DIMENSIONS) result[dimension] = [...new Set(result[dimension])];
  return { valid: true as const, projection: result };
}

function intersectAuthority(local: string[], external: string[]): string[] {
  if (local.includes("*")) return [...new Set(external)];
  if (external.includes("*")) return [...new Set(local)];
  const permitted = new Set(external);
  return local.filter(value => permitted.has(value));
}

const migNativeAuthorityProvider: AuthorityProvider = {
  provider: "mig_native",
  async resolve(config, input) {
    if (config.deploymentMode !== "full_control_plane" || config.tenantId !== input.tenantId || !input.credentialRef) return undefined;
    const binding = await storage.getActiveMigCredentialBinding(input.credentialRef);
    if (!binding || binding.tenantId !== input.tenantId || binding.expiresAt && binding.expiresAt <= new Date()) return undefined;
    const principal = await storage.getMigPrincipal(input.tenantId, binding.principalId);
    if (!principal) return undefined;
    return {
      credentialRef: binding.credentialRef,
      credentialType: binding.credentialType as VerifiedCredentialIdentity["credentialType"],
      principalId: principal.principalId, tenantId: principal.tenantId,
      principalType: principal.principalType as VerifiedCredentialIdentity["principalType"],
      principalStatus: principal.status as VerifiedCredentialIdentity["principalStatus"],
      credentialStatus: binding.status as VerifiedCredentialIdentity["credentialStatus"],
      credentialCapabilityCeiling: strings(binding.capabilityCeiling),
      credentialScopes: strings(binding.scopes), credentialIntentCeiling: strings(binding.allowedIntents),
      credentialDomainCeiling: strings(binding.allowedDomains), credentialMcpTargetCeiling: strings(binding.allowedMcpTargets),
      credentialResourceCeiling: strings(binding.resourceScopes),
      credentialRiskZoneCeiling: binding.riskZoneCeiling as VerifiedCredentialIdentity["credentialRiskZoneCeiling"],
      authorityProvider: "mig_native", authorityRef: binding.credentialRef,
      authoritySourceEvidence: ["mig_credential_binding", "mig_principal"],
      agentId: principal.principalType === "agent" ? principal.subjectRef : undefined,
    };
  },
};

const microsoftEntraAuthorityProvider: AuthorityProvider = {
  provider: "microsoft_entra",
  async resolve(config, input) {
    if (!input.entraJwt) return undefined;
    const verified = await resolveEntraToken(input.entraJwt);
    if (!verified.ok) return undefined;
    const claims: VerifiedExternalAuthorityClaims = {
      provider: "microsoft_entra", tenantId: verified.tenantId,
      providerTenantRef: verified.entraTenantId, stableSubjectRef: verified.entraObjectId,
      scopes: verified.scopes, roles: verified.roles, groups: verified.groups,
      issuedAt: verified.issuedAt, expiresAt: verified.expiresAt,
    };
    if (config.deploymentMode !== "enterprise_intelligence_plane" || !claims ||
        claims.provider !== "microsoft_entra" || config.tenantId !== input.tenantId ||
        claims.tenantId !== input.tenantId || config.providerTenantRef !== claims.providerTenantRef ||
        claims.expiresAt <= new Date() || claims.issuedAt > new Date()) return undefined;
    const subjectHash = createHash("sha256").update(`${claims.providerTenantRef}:${claims.stableSubjectRef}`).digest("hex");
    const credentialRef = `entra-subject:${subjectHash}`;
    const binding = await storage.getActiveMigCredentialBinding(credentialRef);
    if (!binding || binding.tenantId !== input.tenantId || binding.credentialType !== "oauth_subject" ||
        binding.expiresAt && binding.expiresAt <= new Date()) return undefined;
    const principal = await storage.getMigPrincipal(input.tenantId, binding.principalId);
    const entitlement = principal && await storage.getActiveMigPrincipalEntitlement(input.tenantId, principal.principalId);
    if (!principal || principal.status !== "active" || !entitlement) return undefined;
    if (!binding.riskZoneCeiling) return undefined;
    const mapped = projectEntraClaims(claims, strings(binding.scopes));
    if (!mapped.valid) return undefined;
    const projection = mapped.projection;
    const capabilities = intersectAuthority(strings(binding.capabilityCeiling), projection.capability);
    const intents = intersectAuthority(strings(binding.allowedIntents), projection.intent);
    const domains = intersectAuthority(strings(binding.allowedDomains), projection.domain);
    const resources = intersectAuthority(strings(binding.resourceScopes), projection.resource);
    const targets = intersectAuthority(strings(binding.allowedMcpTargets), projection.target);
    const roles = intersectAuthority(strings(entitlement.assignedRoles), projection.role);
    const observedAt = new Date();
    const maxExpiry = new Date(observedAt.getTime() + config.maximumSnapshotAgeSeconds * 1000);
    const expiresAt = claims.expiresAt < maxExpiry ? claims.expiresAt : maxExpiry;
    if (expiresAt <= observedAt) return undefined;
    const snapshot = await storage.createMigAuthoritySnapshot({
      snapshotId: `mig_authority_${randomUUID()}`, tenantId: input.tenantId, provider: "microsoft_entra",
      authorityRef: credentialRef, providerTenantRef: claims.providerTenantRef,
      providerSubjectRef: `sha256:${subjectHash}`, principalId: principal.principalId,
      targetIds: targets, capabilityIds: capabilities,
      domainIds: domains, resourceScopes: resources,
      assignedRoles: roles,
      sourceEvidence: [
        "verified_entra_jwt", "entra_tenant_mapping", "mig_principal_binding", "mig_entitlement",
        ...claims.scopes.map(scope => `entra_scope:${scope}`),
        ...claims.roles.map(role => `entra_role:${role}`),
        ...claims.groups.map(group => `entra_group:sha256:${createHash("sha256").update(group).digest("hex")}`),
        ...intents.map(intent => `entra_projected_intent:${intent}`),
      ],
      riskZoneCeiling: binding.riskZoneCeiling!, observedAt, expiresAt, syncState: "verified",
    });
    return {
      credentialRef, credentialType: "oauth_subject", principalId: principal.principalId,
      tenantId: input.tenantId, principalType: principal.principalType as VerifiedCredentialIdentity["principalType"],
      principalStatus: "active", credentialStatus: "active",
      credentialCapabilityCeiling: capabilities, credentialScopes: claims.scopes,
      credentialIntentCeiling: intents, credentialDomainCeiling: domains,
      credentialMcpTargetCeiling: targets, credentialResourceCeiling: resources,
      credentialRiskZoneCeiling: binding.riskZoneCeiling as VerifiedCredentialIdentity["credentialRiskZoneCeiling"],
      credentialActionCeiling: verified.classification === "read_only" ? "read" : "execute",
      authorityProvider: "microsoft_entra", authorityRef: credentialRef, authoritySnapshotId: snapshot.snapshotId,
      authoritySourceEvidence: strings(snapshot.sourceEvidence), authorityObservedAt: observedAt, authorityExpiresAt: expiresAt,
      authorityAssignedRoles: roles,
      agentId: principal.principalType === "agent" ? principal.subjectRef : undefined,
    };
  },
};

export async function resolveTenantAuthority(input: AuthorityProviderInput): Promise<VerifiedCredentialIdentity | undefined> {
  const config = await storage.getMigTenantAuthorityConfig(input.tenantId);
  const effective = config ?? {
    tenantId: input.tenantId, deploymentMode: "full_control_plane", authorityProvider: "mig_native",
    executionFabric: "mig_managed", maximumSnapshotAgeSeconds: 300,
  } as MigTenantAuthorityConfig;
  const provider = effective.authorityProvider === "mig_native" ? migNativeAuthorityProvider :
    effective.authorityProvider === "microsoft_entra" ? microsoftEntraAuthorityProvider : undefined;
  return provider?.resolve(effective, input);
}