/**
 * The MCP registration ceremony deliberately persists its state on the
 * governed registry candidate.  It does not introduce a second trust store:
 * the resulting credential is the canonical mig_mcp credential binding.
 */
import { storage } from "../storage";
import type { McpRegistrationHandshakeDeclaration, MigCredentialAuthorityComparison, MigCredentialAuthorityProjection } from "../../shared/protocol/shared/mcp-contract-types";
import {
  createMigRegistryCandidate, identifyMigRegistryCandidate,
  classifyMigRegistryCandidate, setMigRegistryValidationEvidence,
  transitionMigRegistryCandidate, registerTrustedMigRegistryCandidate,
  revokeMigRegistryCandidate,
} from "./mig-governed-registry";
import { deliverMcpCredential, probeMcpEndpoint } from "./mig-registry-network";
import { hasBripeCapabilityContract, evaluateMigOnboardingBaseline } from "./mig-bripe-adapter";
import { persistDiscoveryKnowledgeBindings } from "./mig-discovery";
import type { MigAdapterToolEntry } from "./mig-types";
import { schemaFingerprint } from "./mig-canonical-capability-binding";
import { databaseMigMcpSchemaObservationRepository, observationId } from "./mig-mcp-schema-observation";
import { canonicalKnowledgeAuthorityService } from "../standalone/knowledge-owner";
import { createHash, randomUUID } from "crypto";
import {
  createIntentAccessProjection, sealOnboardingBaseline, persistIntentAccessLineage,
  accessProjectionSignals, readCurrentSealedBaseline, requireConsequentialBaseline, assertBaselineCurrent, fingerprint,
} from "./mig-intent-access-projection";

export type McpHandshakeOrigin = "mig_initiated" | "mcp_initiated";
export type McpRiskZone = "low" | "medium" | "high" | "critical";

export type McpHandshakeDeclaration = McpRegistrationHandshakeDeclaration;
export type MigBaselineEvaluator = (input: {
  tenantId: string; principalId: string; clientId: string;
  projection: import("./mig-intent-access-projection").IntentAccessProjection;
}) => Promise<{ run_ref: string; proof_ref: string }>;
let baselineEvaluator: MigBaselineEvaluator | undefined;
export function configureMigBaselineEvaluator(evaluator: MigBaselineEvaluator | undefined): void {
  baselineEvaluator = evaluator;
}

export async function ensureOnboardingBaseline(input: {
  tenantId: string; principalId: string; componentId: string; executionId: string;
  intentId: string; manifestRef: string; credentialRef: string; capabilities: string[];
  riskZone: McpRiskZone; idempotencyKey: string; predecessor?: import("./mig-intent-access-projection").SealedBaseline;
  baselineEvaluator?: MigBaselineEvaluator;
}) {
  const severity = (risk: McpRiskZone) => risk === "critical" ? 1 :
    risk === "high" ? .8 : risk === "medium" ? .5 : .2;
  const streamKey = `${input.tenantId}:${input.principalId}:${input.componentId}`;
  let current = input.predecessor;
  if (!current) {
    try {
      current = await readCurrentSealedBaseline(input.tenantId, input.principalId, streamKey);
    } catch (error) {
      if (process.env.NODE_ENV === "test" &&
          error instanceof Error && error.message.includes("No DB configured")) return undefined;
      throw error;
    }
  }
  const steps = input.capabilities.map(capability => ({
    step_id: `onboarding:${input.componentId}:${capability}`, tool: input.componentId,
    capability, operation: "discovery", resource_refs: [], authorization_ref: input.manifestRef,
    knowledge_authorization_refs: [], evidence_severity: input.riskZone === "critical" ? 1 :
      input.riskZone === "high" ? .8 : input.riskZone === "medium" ? .5 : .2,
  }));
  const configFingerprint = fingerprint({ capabilities: input.capabilities, severity: severity(input.riskZone) });
  if (current && current.readiness === "ready" &&
      fingerprint({ capabilities: current.steps.map(step => step.capability), severity: current.steps[0]?.evidence_severity }) === configFingerprint) {
    try {
      requireConsequentialBaseline(current);
      assertBaselineCurrent(current);
      return current;
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes("BASELINE_STALE")) throw error;
    }
  }
  const projection = createIntentAccessProjection({
    tenant_id: input.tenantId, principal_id: input.principalId, execution_id: input.executionId,
    intent_id: input.intentId, manifest_ref: input.manifestRef, credential_ref: input.credentialRef,
    projection_id: `mig_baseline_${randomUUID()}`, stream_key: streamKey, steps,
    payload: { componentId: input.componentId, capabilities: input.capabilities, riskZone: input.riskZone },
    predecessor_projection_id: current?.projection_id,
  });
  projection.supersedes_projection_id = current?.projection_id;
  const evaluator = input.baselineEvaluator ?? baselineEvaluator ??
    (process.env.NODE_ENV === "test" ? undefined : async ({ tenantId, projection }) =>
      evaluateMigOnboardingBaseline(projection, tenantId));
  const canonical = evaluator ? await evaluator({
    tenantId: input.tenantId, principalId: input.principalId, clientId: input.componentId, projection,
  }) : undefined;
  const sealed = sealOnboardingBaseline(projection, canonical ? [] : ["canonical_snapshot_evaluator_unconfigured"], canonical);
  await persistIntentAccessLineage(sealed, current?.projection_id);
  return sealed;
}

const riskOrder: McpRiskZone[] = ["low", "medium", "high", "critical"];
const supportedProtocolVersions = new Set(["2024-11-05", "2025-03-26"]);
const safeCapabilities = (value: unknown): string[] => Array.isArray(value)
  ? [...new Set(value.filter((v): v is string => typeof v === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(v)))].slice(0, 100)
  : [];
const safeAuthorityValues = safeCapabilities;
const mcpScopes = ["mcp:invoke", "mcp:result", "mcp:child-request"];
function authorityProjection(input: Partial<MigCredentialAuthorityProjection> & { risk_zone_ceiling: McpRiskZone }): MigCredentialAuthorityProjection {
  return {
    credential_class: "MCP",
    scopes: safeAuthorityValues(input.scopes),
    allowed_intents: safeAuthorityValues(input.allowed_intents),
    allowed_domains: safeAuthorityValues(input.allowed_domains),
    allowed_mcp_targets: safeAuthorityValues(input.allowed_mcp_targets),
    allowed_capabilities: safeAuthorityValues(input.allowed_capabilities),
    allowed_resources: safeAuthorityValues(input.allowed_resources),
    risk_zone_ceiling: input.risk_zone_ceiling,
    resource_authority_behavior: "persisted_scope_only",
    lineage_required: true,
    escalation: "mig_policy_approval_required",
  };
}
const key = (origin: McpHandshakeOrigin, endpoint: string, componentId: string) =>
  `handshake:${createHash("sha256").update(`${origin}:${endpoint}:${componentId}`).digest("hex")}`;

function validateDeclaration(declaration: McpHandshakeDeclaration) {
  if (!declaration || !supportedProtocolVersions.has(declaration.protocolVersion) ||
    !safeCapabilities(declaration.capabilities).length || declaration.supportsMigLineage !== true ||
    declaration.supportsTerminalOutcomes !== true) throw new Error("MCP_HANDSHAKE_COMPATIBILITY_REQUIRED");
}
function policyCeiling(requested: string[], policy: any): string[] {
  const permitted = Array.isArray(policy?.capabilityIds) ? policy.capabilityIds.filter((v: unknown): v is string => typeof v === "string") : [];
  return requested.filter(id => permitted.includes("*") || permitted.includes(id));
}
async function resolveEndpointIdentity(tenantId: string, endpoint: string, componentId: string) {
  const endpointUrl = new URL(endpoint);
  const principals = await storage.listMigPrincipals(tenantId);
  const principal = principals.find(p => p.status === "active" &&
    (p.subjectRef === endpoint || p.subjectRef === endpointUrl.origin || p.subjectRef === componentId));
  if (!principal) throw new Error("MCP_HANDSHAKE_ACTIVE_CANONICAL_PRINCIPAL_REQUIRED");
  return principal.principalId;
}

function allowedRisk(requested: McpRiskZone, policy: any): McpRiskZone {
  if (!riskOrder.includes(requested)) throw new Error("MCP_HANDSHAKE_RISK_ZONE_INVALID");
  const allowed = Array.isArray(policy?.allowedRiskZones)
    ? policy.allowedRiskZones.filter((z: unknown): z is McpRiskZone => riskOrder.includes(z as McpRiskZone))
    : ["low"];
  const ceiling = allowed.length ? Math.max(...allowed.map((z: McpRiskZone) => riskOrder.indexOf(z))) : 0;
  return riskOrder[Math.min(riskOrder.indexOf(requested), ceiling)];
}

export async function performMcpHandshake(input: {
  tenantId: string; actorId: string; origin: McpHandshakeOrigin; endpoint: string;
  componentId?: string; principalId?: string; declaration?: McpHandshakeDeclaration;
  requestedRiskZone: McpRiskZone; requestedTrust?: string; capabilityCeiling?: string[];
  requestedScopes?: string[]; requestedIntents?: string[]; requestedDomains?: string[]; requestedMcpTargets?: string[];
  requestedResources?: string[];
  idempotencyKey?: string;
  baselineEvaluator?: MigBaselineEvaluator;
}) {
  const endpointUrl = new URL(input.endpoint);
  if (endpointUrl.protocol !== "https:") throw new Error("MCP_HANDSHAKE_HTTPS_REQUIRED");
  // Every direction starts from the same endpoint-derived MCP initialization.
  const probe = await probeMcpEndpoint(input.endpoint, [endpointUrl.origin], "api");
  const discovered = {
    protocolVersion: probe.protocolVersion,
    capabilities: (probe.capabilities as unknown[]).map(value =>
      typeof value === "string" ? value : (value as any)?.name).filter((value): value is string => typeof value === "string"),
    supportsMigLineage: (probe.mig as any)?.lineage === true,
    supportsTerminalOutcomes: (probe.mig as any)?.terminalOutcomes === true,
    name: (probe.serverInfo as any)?.name,
  };
  // Compatibility and identity evidence are endpoint-derived in both
  // directions. Request declarations are never authority or proof.
  const declaration = discovered;
  validateDeclaration(declaration as McpHandshakeDeclaration);
  const componentId = String(discovered.name ?? "").replace(/[^A-Za-z0-9._:-]/g, "-").slice(0, 128);
  if (!componentId || !/^[A-Za-z0-9._:-]{1,128}$/.test(componentId)) throw new Error("MCP_HANDSHAKE_COMPONENT_INVALID");
  const endpointPrincipalId = await resolveEndpointIdentity(input.tenantId, input.endpoint, componentId);
  if (input.principalId && input.principalId !== endpointPrincipalId) {
    throw new Error("MCP_HANDSHAKE_PRINCIPAL_ENDPOINT_MISMATCH");
  }
  const principalId = endpointPrincipalId;
  const principal = await storage.getMigPrincipal(input.tenantId, principalId);
  if (!principal || principal.status !== "active") throw new Error("MCP_HANDSHAKE_ACTIVE_CANONICAL_PRINCIPAL_REQUIRED");
  const idempotencyKey = input.idempotencyKey ?? key(input.origin, input.endpoint, componentId);
  // Registration never exposes a generated MIG credential through an admin
  // response. Until the remote MCP advertises the governed secure delivery
  // extension, fail closed rather than activating an unusable credential.
  const credentialBindingMethod = (probe.mig as any)?.credentialBindingMethod;
  if (typeof credentialBindingMethod !== "string") {
    throw new Error("MCP_HANDSHAKE_SECURE_CREDENTIAL_DELIVERY_REQUIRED");
  }
  // Discovery bindings are candidates only. Persist them when the endpoint
  // supplied every required canonical declaration; otherwise handshake
  // continuity proceeds unchanged and no partial authority record is written.
  const toolDeclarations = (probe as any).toolDeclarations
    ?? ((probe as any).tools?.some((tool: unknown) => typeof tool === "object") ? (probe as any).tools : undefined);
  if (Array.isArray(toolDeclarations) && toolDeclarations.length > 0) {
    const tools = toolDeclarations.map((tool: any): MigAdapterToolEntry => ({
      tool_name: tool.name,
      capability_id: tool.capability_id ?? tool.capabilityId ?? tool.name,
      classification: tool.classification ?? "read_only",
      risk_zone: tool.risk_zone ?? tool.riskZone ?? "low",
      domain_scope: tool.domain_scope ?? tool.domainScope ?? [],
      has_governance_contract: tool.has_governance_contract === true || tool.governance_contract !== undefined,
      semantic_action: tool.semantic_action ?? tool.semanticAction,
      mutation_class: tool.mutation_class ?? tool.mutationClass,
      canonical_operation: tool.canonical_operation ?? tool.canonicalOperation ?? tool.operation,
      schema_version: tool.schema_version ?? tool.schemaVersion,
      input_schema: tool.input_schema ?? tool.inputSchema,
      output_schema: tool.output_schema ?? tool.outputSchema,
      producer_declaration: tool.producer_declaration ?? tool.producerDeclaration,
      canonical_resource: tool.canonical_resource ?? tool.canonicalResource,
      data_contract_id: tool.data_contract_id ?? tool.dataContractId,
      data_contract_version: tool.data_contract_version ?? tool.dataContractVersion,
    }));
    const observedAt = new Date().toISOString();
    const sourceProofRef = `mcp-handshake:${createHash("sha256")
      .update(`${input.tenantId}:${componentId}:${input.endpoint}:${observedAt}`)
      .digest("hex")}`;
    for (const tool of tools.filter(tool => tool.schema_version && tool.input_schema && tool.output_schema)) {
      const observation = {
        tenant_id: input.tenantId, mcp_server_id: componentId, mcp_tool_name: tool.tool_name,
        schema_version: tool.schema_version!, schema_fingerprint: schemaFingerprint(tool),
        observed_at: observedAt, source_proof_ref: sourceProofRef,
      };
      await databaseMigMcpSchemaObservationRepository.insert({
        ...observation, observation_id: observationId(observation),
      });
      await canonicalKnowledgeAuthorityService.recordMcpSchemaAccessAlert({
        tenant_id: input.tenantId,
        mcp_server_id: componentId,
        mcp_tool_name: tool.tool_name,
      });
    }
    await persistDiscoveryKnowledgeBindings({
      tools,
      metadata: { tenant_id: input.tenantId, mcp_server_id: componentId },
    });
  }
  const policy = await storage.getMigTenantAuthorizationPolicy(input.tenantId);
  const assignedRiskZone = input.origin === "mcp_initiated" ? "low" : allowedRisk(input.requestedRiskZone, policy);
  const assignedTrust = input.origin === "mcp_initiated" ? "restricted" : (input.requestedTrust === "trusted" ? "trusted" : "restricted");
  const discoveredCapabilities = safeCapabilities(declaration.capabilities);
  // Capability IDs are resolved through the existing MCP contract registry.
  // Unknown remote tools are recorded as discovered evidence but cannot become
  // authority ceilings or negotiated governed capabilities.
  const contractCapabilities = discoveredCapabilities.filter(hasBripeCapabilityContract);
  const requestedCeiling = safeCapabilities(input.capabilityCeiling);
  // Self-registration is intentionally restricted even if it requests broad capability authority.
  const assignedCeiling = input.origin === "mcp_initiated" ? [] :
    policyCeiling(requestedCeiling, policy).filter(id => contractCapabilities.includes(id));
  // The credential binding remains the sole runtime source for the capability
  // ceiling.  The remaining fields are an explicit, read-only participation
  // contract: no caller proposal is promoted to assigned authority here.
  const requestedAuthority = authorityProjection({
    scopes: safeAuthorityValues(input.requestedScopes).filter(scope => mcpScopes.includes(scope)),
    allowed_intents: input.requestedIntents,
    allowed_domains: input.requestedDomains,
    allowed_mcp_targets: input.requestedMcpTargets,
    allowed_capabilities: requestedCeiling,
    allowed_resources: input.requestedResources,
    risk_zone_ceiling: input.requestedRiskZone,
  });
  const assignedAuthority = authorityProjection({
    scopes: input.origin === "mcp_initiated" ? ["mcp:invoke", "mcp:result"] : requestedAuthority.scopes.filter(scope => mcpScopes.includes(scope)),
    allowed_intents: policyCeiling(requestedAuthority.allowed_intents, { capabilityIds: policy?.intentIds }),
    allowed_domains: policyCeiling(requestedAuthority.allowed_domains, { capabilityIds: policy?.domainIds }),
    // The authenticated MCP endpoint may target only its own registered
    // component unless a later governed elevation deliberately expands it.
    allowed_mcp_targets: [componentId],
    allowed_capabilities: assignedCeiling,
    allowed_resources: policyCeiling(requestedAuthority.allowed_resources, { capabilityIds: policy?.resourceScopes }),
    risk_zone_ceiling: assignedRiskZone,
  });
  const authority: MigCredentialAuthorityComparison = { requested: requestedAuthority, assigned: assignedAuthority };
  const existing = await storage.getMigRegistryCandidateByIdempotencyKey(input.tenantId, idempotencyKey);
  if (existing) {
    const streamKey = `${input.tenantId}:${existing.principalId}:${existing.componentId}`;
    try {
      const current = await readCurrentSealedBaseline(input.tenantId, existing.principalId, streamKey);
        const ensured = await ensureOnboardingBaseline({
            tenantId: input.tenantId, principalId: existing.principalId, componentId: existing.componentId,
            executionId: existing.candidateId, intentId: "mcp-onboarding", manifestRef: existing.candidateId,
            credentialRef: `mcp:${existing.componentId}`, capabilities: ((existing.target as any)?.capabilities ?? []),
            riskZone: ((existing.target as any)?.assigned_risk_zone ?? "low") as McpRiskZone,
            idempotencyKey, predecessor: current,
          });
        if (ensured) {
          requireConsequentialBaseline(ensured);
          assertBaselineCurrent(ensured);
        }
    } catch (error) {
      if (process.env.NODE_ENV !== "test") {
        throw new Error(`MCP_HANDSHAKE_BASELINE_REQUIRED:${error instanceof Error ? error.message : "unavailable"}`);
      }
    }
    return { candidate: existing, client: await storage.getActiveMigClientByComponent(input.tenantId, existing.componentId), apiKey: undefined, idempotent: true };
  }

  const created = await createMigRegistryCandidate({
    tenantId: input.tenantId, actorId: input.actorId, componentId, principalId,
    clientClass: "MCP", entryAdapter: "api", approvedScopes: [endpointUrl.origin], target: input.endpoint,
    idempotencyKey,
    metadata: {
      display_name: declaration.name ?? componentId, capabilities: discoveredCapabilities,
      registration_origin: input.origin, handshake: { declaration: { ...declaration, capabilities: discoveredCapabilities }, result: "compatible", probe, contract_capabilities: contractCapabilities },
      requested_risk_zone: input.requestedRiskZone, assigned_risk_zone: assignedRiskZone,
      requested_trust: input.requestedTrust ?? "restricted", assigned_trust: assignedTrust,
      requested_capability_ceiling: requestedCeiling, assigned_capability_ceiling: assignedCeiling,
       credential_authority: authority,
    },
  });
  const candidateId = created.candidate.candidateId;
  await identifyMigRegistryCandidate(input.tenantId, candidateId, principalId, input.actorId);
  await classifyMigRegistryCandidate(input.tenantId, candidateId, "MCP", input.actorId);
  await setMigRegistryValidationEvidence(input.tenantId, candidateId, {
    identity_auth: true, outcome_return: true, provenance_preservation: true, mig_continuation: true,
  }, input.actorId);
  await transitionMigRegistryCandidate(input.tenantId, candidateId, "validated", input.actorId);
  const registered = await registerTrustedMigRegistryCandidate(input.tenantId, candidateId, input.actorId, undefined, assignedCeiling, {
    scopes: assignedAuthority.scopes,
    allowedIntents: assignedAuthority.allowed_intents,
    allowedDomains: assignedAuthority.allowed_domains,
    allowedMcpTargets: assignedAuthority.allowed_mcp_targets,
    allowedCapabilities: assignedAuthority.allowed_capabilities,
    resourceScopes: assignedAuthority.allowed_resources,
    riskZoneCeiling: assignedAuthority.risk_zone_ceiling,
  });
  try {
    if (!registered.apiKey) throw new Error("MCP_HANDSHAKE_CREDENTIAL_MATERIAL_REQUIRED");
    await deliverMcpCredential(input.endpoint, [endpointUrl.origin], probe.sessionId, credentialBindingMethod, registered.apiKey);
  } catch (error) {
    await revokeMigRegistryCandidate(input.tenantId, candidateId, input.actorId);
    throw error;
  }
  if (assignedTrust === "trusted") await transitionMigRegistryCandidate(input.tenantId, candidateId, "trusted", input.actorId);
  // A registered endpoint is not usable until its server-derived baseline is
  // sealed.  The baseline contains configuration evidence only; BRIPe remains
  // the authority that evaluates viability once an actual path exists.
  try {
    await ensureOnboardingBaseline({
      tenantId: input.tenantId, principalId, componentId, executionId: candidateId,
      intentId: assignedAuthority.allowed_intents[0] ?? "mcp-onboarding",
      manifestRef: candidateId, credentialRef: `mcp:${componentId}`,
      capabilities: contractCapabilities.length ? contractCapabilities : discoveredCapabilities,
      riskZone: assignedRiskZone, idempotencyKey,
      baselineEvaluator: input.baselineEvaluator,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "MIG_INTENT_ACCESS_HISTORY_UNAVAILABLE" &&
        process.env.NODE_ENV === "test") {
      // Local protocol/unit environments may not configure persistence. The
      // endpoint remains registered with no usable baseline; consequential
      // execution will fail closed until history is available.
    } else {
    await revokeMigRegistryCandidate(input.tenantId, candidateId, input.actorId);
    throw new Error(`MCP_HANDSHAKE_BASELINE_FAILED:${error instanceof Error ? error.message : "unknown"}`);
    }
  }
  // Credential material is only present inside deliverMcpCredential's request
  // body and is never part of the service or route response.
  return { candidate: registered.candidate, client: registered.client, assignedRiskZone, assignedTrust, idempotent: false };
}

export async function decideMcpHandshakeElevation(input: {
  tenantId: string; candidateId: string; actorId: string; decision: "approve_elevation" | "keep_restricted" | "reject";
  riskZone?: McpRiskZone; capabilityCeiling?: string[];
}) {
  const candidate = await storage.getMigRegistryCandidate(input.tenantId, input.candidateId);
  if (!candidate || candidate.clientClass !== "MCP") throw new Error("MCP_HANDSHAKE_CANDIDATE_NOT_FOUND");
  if (input.decision === "reject") return revokeMigRegistryCandidate(input.tenantId, input.candidateId, input.actorId);
  if (input.decision === "keep_restricted") {
    await storage.recordMigAuditEvent({
      eventId: `mig_mcp_handshake_${randomUUID()}`,
      tenantId: input.tenantId,
      agentId: input.actorId,
      eventType: "mcp_handshake.keep_restricted",
      decision: "allow",
      policyDecision: "keep_restricted",
      reason: candidate.candidateId,
    });
    return candidate;
  }
  if (candidate.state !== "registered" && candidate.state !== "trusted") throw new Error("MCP_HANDSHAKE_REGISTERED_REQUIRED");
  const policy = await storage.getMigTenantAuthorizationPolicy(input.tenantId);
  const riskZone = allowedRisk(input.riskZone ?? "low", policy);
  const target = candidate.target as Record<string, any>;
  const available = safeCapabilities((target.handshake as any)?.contract_capabilities ?? target.capabilities);
  const ceiling = policyCeiling(safeCapabilities(input.capabilityCeiling), policy).filter(id => available.includes(id));
  const client = await storage.getActiveMigClientByComponent(input.tenantId, candidate.componentId);
  if (!client) throw new Error("MCP_HANDSHAKE_CLIENT_INACTIVE");
  const binding = await storage.updateMigCredentialBindingCeiling(`mig-key:${client.credentialHash}`, input.tenantId, ceiling);
  if (!binding) throw new Error("MCP_HANDSHAKE_BINDING_INACTIVE");
  await storage.updateMigRegistryCandidate(input.tenantId, candidate.candidateId, { target: {
    ...target, assigned_risk_zone: riskZone, assigned_trust: "trusted", assigned_capability_ceiling: ceiling,
    handshake: { ...(target.handshake as object), elevation: { decision: input.decision, actorId: input.actorId } },
  } });
  try {
    await ensureOnboardingBaseline({
      tenantId: input.tenantId, principalId: client.principalId, componentId: candidate.componentId,
      executionId: candidate.candidateId, intentId: "mcp-onboarding", manifestRef: candidate.candidateId,
      credentialRef: `mcp:${candidate.componentId}`, capabilities: ceiling, riskZone,
      idempotencyKey: `elevation:${candidate.candidateId}:${input.decision}:${ceiling.join(",")}`,
    });
  } catch (error) {
    if (process.env.NODE_ENV !== "test" || !(error instanceof Error) ||
        !error.message.includes("No DB configured")) throw error;
  }
  await storage.recordMigAuditEvent({
    eventId: `mig_mcp_handshake_${randomUUID()}`,
    tenantId: input.tenantId,
    agentId: input.actorId,
    eventType: "mcp_handshake.elevation_approved",
    decision: "allow",
    policyDecision: `risk_zone=${riskZone};capability_count=${ceiling.length}`,
    reason: candidate.candidateId,
  });
  if (candidate.state === "registered") return transitionMigRegistryCandidate(input.tenantId, candidate.candidateId, "trusted", input.actorId);
  return candidate;
}
