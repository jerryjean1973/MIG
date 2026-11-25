/** Remote adapter only. Native policy, validation, admission, snapshots and
 * BRIPe computation execute at their existing authenticated canonical owner. */
import { readOwnerCatalog } from "../standalone/catalog";
import { ownerCall } from "../standalone/owner-client";
import { buildAuthorizationCatalog } from "./mig-authorization-catalog";
import type { MigAdapterToolEntry, MigDownstreamAdapter } from "./mig-types";
import type { IntentAccessProjection } from "./mig-intent-access-projection";

export function bripeToolCatalog(): MigAdapterToolEntry[] {
  return readOwnerCatalog().tools;
}
export function getBripeToolAuthorizationEntry(name: string) {
  return bripeToolCatalog().find(tool => tool.tool_name === name);
}
export function hasBripeCapabilityContract(capabilityId: string): boolean {
  return readOwnerCatalog().capability_contract_ids.includes(capabilityId);
}
export function buildBripeAuthorizationCatalog(additionalIntentIds: readonly string[] = []) {
  const catalog = readOwnerCatalog();
  return buildAuthorizationCatalog("bripe-mcp-catalog-v1", catalog.tools, catalog.domains,
    [...catalog.intents, ...additionalIntentIds]);
}
export const bripeMcpAdapter: MigDownstreamAdapter = {
  adapter_id: "bripe-mcp-v1",
  listTools: bripeToolCatalog,
  authorityAssertionInput: (toolName, input) =>
    ownerCall("tool.authorityAssertionInput", [toolName, input]),
  executeTool: async (toolName, input, context) => {
    if (!getBripeToolAuthorizationEntry(toolName)) throw new Error("MIG_UNKNOWN_DOWNSTREAM_TOOL");
    return ownerCall("tool.execute", [toolName, input, context], context.tenantId);
  },
};
export const evaluateMigOnboardingBaseline = (projection: IntentAccessProjection, tenantId: string) =>
  ownerCall<{run_ref: string; proof_ref: string}>("onboarding.evaluate", [projection, tenantId], tenantId);

// The export preparer appends the existing read-only baseline validator,
// mapping validator and intent-library seeder, without copying the native
// adapter or any BRIPe/product implementation.

import { ALL_MCP_TOOLS } from "../mcp/bripe-mcp-tools";


import { createIntentLibrary, upsertIntentDefinition, publishIntentLibrary } from "./mig-intent-library";
import type { VerifiedCredentialIdentity } from "./mig-authorization-context";
import { authorizeEnterpriseRequest } from "./mig-enterprise-authorization";
import type { MigCanonicalKnowledgeResolver } from "./mig-enterprise-authorization";
import { isCanonicalKnowledgeResourceRef, type CanonicalMCPKnowledgeBinding } from "@shared/corporate-brain/canonical-knowledge-authority";
import type { CanonicalKnowledgeResource, CBAuthorityOperation } from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";
import { issueMigDelegation } from "./mig-delegation";
import { authorizeProtectedMcpDispatch } from "./mig-protected-mcp-dispatch";
import { storage } from "../storage";
import { isByolabDomainCaller, isByolabDomainTool } from "../mcp/byolab-domain-access";
const BRIPE_CORE_LIBRARY_ID = "bripe-core-v1";

export const BYOLAB_REACQUISITION_INTENT_ID = "byolab_reacquisition";

export function isValidBripeToolAuthorizationMapping(entry: MigAdapterToolEntry): boolean {
  return Boolean(
    entry.tool_name &&
    entry.capability_id &&
    entry.has_governance_contract &&
    entry.canonical_service &&
    entry.intent_classes?.length &&
    entry.semantic_action &&
    entry.semantic_scopes?.includes(entry.capability_id) &&
    entry.resource_types?.length &&
    entry.mutation_class &&
    entry.sod_class &&
    entry.tenant_mode === "tenant_bound",
  );
}

const CLASSIFICATION_RANK = { read_only: 0, execution: 1, admin: 2 } as const;

const isProtectedKnowledgeAlias = (value: string) =>
  /^(?:cb:|knowledge:|corporate[-_:]?brain:|vendor[-_:]?risk[-_:]?score:)/i.test(value);

export async function authorizeBripeMcpProtocolRequest(input: {
  verifiedCredential: VerifiedCredentialIdentity;
  classification: "read_only" | "execution" | "admin";
  allowedTools?: string[] | null;
  allowedIntents?: string[] | null;
  method: "tools/list" | "tools/call";
  toolName?: string;
  intentId: string;
  domainId: string;
  resourceRef: string;
  resourceVersion?: string;
  requestId: string;
  clientId: string;
  canonicalKnowledge?: { resource: CanonicalKnowledgeResource; operation: CBAuthorityOperation };
  /** Server-resolved exact persisted binding; never accepted from MCP input. */
  canonicalKnowledgeBinding?: CanonicalMCPKnowledgeBinding;
  canonicalKnowledgeResolver?: MigCanonicalKnowledgeResolver;
}): Promise<
  | { allowed: true; delegationToken: string; allowedToolNames: string[]; authorizationManifestIds: string[] }
  | { allowed: false; reason: string; authorizationManifestIds: string[] }
> {
  const catalogEntries = bripeToolCatalog();
  const byName = new Map(catalogEntries.map(entry => [entry.tool_name, entry]));
  const byolab = isByolabDomainCaller({
    tenantId: input.verifiedCredential.tenantId,
    principalId: input.verifiedCredential.principalId, clientId: input.clientId,
  });
  if (input.method === "tools/call" && input.toolName && isByolabDomainTool(input.toolName) && !byolab)
    return { allowed: false, reason: "byolab_domain_access_denied", authorizationManifestIds: [] };
  const requested = input.method === "tools/call"
    ? (input.toolName ? [input.toolName] : [])
    : ALL_MCP_TOOLS
      .filter(tool => !isByolabDomainTool(tool.name) || byolab)
      .filter(tool => CLASSIFICATION_RANK[tool.classification] <= CLASSIFICATION_RANK[input.classification])
      .filter(tool => !input.allowedTools?.length || input.allowedTools.includes(tool.name))
      .map(tool => tool.name);
  if (requested.length === 0) return { allowed: false, reason: "mig_tool_binding_missing", authorizationManifestIds: [] };
  if (input.allowedIntents?.length && !input.allowedIntents.includes(input.intentId)) {
    return { allowed: false, reason: "mig_intent_not_credential_allowlisted", authorizationManifestIds: [] };
  }

  const authorizationCatalog = buildBripeAuthorizationCatalog([input.intentId]);
  const allowedBindings: import("./mig-delegation").MigDelegatedToolBinding[] = [];
  const authorizationManifestIds: string[] = [];
  const effectiveScopes = new Set<string>();
  let lastReason = "mig_authorization_denied";

  for (const toolName of requested) {
    const mapping = byName.get(toolName);
    if (!mapping || !isValidBripeToolAuthorizationMapping(mapping)) {
      lastReason = "mig_tool_authorization_mapping_invalid";
      continue;
    }
    if (mapping.mutation_class === "destructive_legacy_blocked") {
      lastReason = "mig_destructive_legacy_path_blocked";
      continue;
    }
    if (CLASSIFICATION_RANK[mapping.classification] > CLASSIFICATION_RANK[input.classification]) {
      lastReason = "mig_credential_classification_exceeded";
      continue;
    }
    if (input.allowedTools?.length && !input.allowedTools.includes(toolName)) {
      lastReason = "mig_tool_not_credential_allowlisted";
      continue;
    }
    const semanticAction = mapping.semantic_action!;
    if (isCanonicalKnowledgeResourceRef(input.resourceRef) && !input.canonicalKnowledgeBinding) {
      lastReason = "canonical_knowledge_binding_required";
      continue;
    }
    if (isProtectedKnowledgeAlias(input.resourceRef) && !input.canonicalKnowledgeBinding) {
      lastReason = "canonical_knowledge_authority_unresolved";
      continue;
    }
    const authorization = await authorizeEnterpriseRequest(input.verifiedCredential, {
      intentId: input.intentId,
      capabilityId: mapping.capability_id,
      semanticAction: mapping.semantic_action!,
      domainId: input.domainId,
      resourceRef: input.resourceRef,
      resourceVersion: input.resourceVersion,
      mcpTargetId: input.clientId,
      requestCorrelationId: requested.length === 1 ? input.requestId : `${input.requestId}:${toolName}`,
      canonicalKnowledge: input.canonicalKnowledge,
      canonicalKnowledgeBinding: input.canonicalKnowledgeBinding,
    }, authorizationCatalog, input.canonicalKnowledgeResolver);
    if (authorization.authorizationManifestId) authorizationManifestIds.push(authorization.authorizationManifestId);
    if (authorization.decision.decision !== "allow" || !authorization.authorizationManifestId) {
      lastReason = authorization.decision.reason;
      continue;
    }
    if (isCanonicalKnowledgeResourceRef(input.resourceRef) || isProtectedKnowledgeAlias(input.resourceRef)) {
      const binding = input.canonicalKnowledgeBinding;
      if (!binding || binding.tenant_id !== input.verifiedCredential.tenantId
        || binding.capability_id !== mapping.capability_id
        || binding.mcp_server_id !== input.clientId
        || binding.intent_constraints.length > 0 && !binding.intent_constraints.includes(input.intentId)) {
        lastReason = "canonical_knowledge_binding_unresolved";
        continue;
      }
      try {
        const receipt = await authorizeProtectedMcpDispatch({
          lookup: {
            tenant_id: binding.tenant_id, mcp_server_id: binding.mcp_server_id,
            mcp_tool_name: binding.mcp_tool_name, mcp_schema_version: binding.mcp_schema_version,
            schema_fingerprint: binding.schema_fingerprint,
            capability_id: binding.capability_id, binding_id: binding.binding_id,
          },
          principal: {
            principal_id: input.verifiedCredential.principalId,
            tenant_id: input.verifiedCredential.tenantId,
            service_id: binding.service_id,
            access_path: "mig-bripe-mcp",
            intent_id: input.intentId,
            capability_ids: [mapping.capability_id],
          },
          trustedResults: {
            capability_exists: { allowed: true, version: mapping.capability_id },
            route: { allowed: true, version: authorization.policyVersion },
            mig: { allowed: true, version: authorization.policyVersion },
          },
        });
        if (receipt.decision !== "ALLOW") {
          lastReason = receipt.reason;
          continue;
        }
      } catch (error) {
        lastReason = error instanceof Error ? error.message : "canonical_knowledge_binding_unresolved";
        continue;
      }
    }
    authorization.decision.effectivePermissions.forEach(scope => effectiveScopes.add(scope));
    allowedBindings.push({
      toolName,
      capabilityId: mapping.capability_id,
      semanticAction: mapping.semantic_action!,
      domainId: input.domainId,
      resourceType: mapping.resource_types![0],
      mutationClass: mapping.mutation_class as "none" | "append_only" | "governed_transition",
      canonicalService: mapping.canonical_service!,
      authorizationManifestId: authorization.authorizationManifestId,
      authorizationDecisionId: authorization.authorizationManifestId,
      policyVersion: authorization.policyVersion,
    });
  }

  if (input.method === "tools/call" && allowedBindings.length !== 1) {
    return { allowed: false, reason: lastReason, authorizationManifestIds };
  }
  if (input.method === "tools/list" && allowedBindings.length === 0) {
    return { allowed: false, reason: lastReason, authorizationManifestIds };
  }
  const { token } = issueMigDelegation({
    tenantId: input.verifiedCredential.tenantId,
    actorPrincipalId: input.verifiedCredential.actorPrincipalId ?? input.verifiedCredential.principalId,
    clientPrincipalId: input.verifiedCredential.clientPrincipalId ?? input.clientId,
    executorPrincipalId: input.verifiedCredential.executorPrincipalId ?? input.verifiedCredential.principalId,
    intentId: input.intentId,
    requestId: input.requestId,
    mcpMethod: input.method,
    resourceRef: input.resourceRef,
    resourceVersion: input.resourceVersion,
    effectiveScopes: [...effectiveScopes],
    tools: allowedBindings,
  });
  return {
    allowed: true,
    delegationToken: token,
    allowedToolNames: allowedBindings.map(binding => binding.toolName),
    authorizationManifestIds,
  };
}

export async function evaluateMigReadOnlyOnboardingBaseline(
  projection: IntentAccessProjection,
  tenantId: string,
): Promise<{ run_ref: string; proof_ref: string }> {
  if (projection.tenant_id !== tenantId || !projection.manifest_ref) {
    throw new Error("MIG_READ_BASELINE_IDENTITY_MISMATCH");
  }
  const capabilities = [...new Set(projection.steps.map(step => step.capability))];
  if (!capabilities.length || capabilities.some(capability => {
    const mapping = bripeToolCatalog().find(entry => entry.capability_id === capability);
    return !mapping || mapping.classification !== "read_only" || !mapping.has_governance_contract;
  })) {
    throw new Error("MIG_READ_BASELINE_CAPABILITY_INVALID");
  }
  const entitlement = await storage.getActiveMigPrincipalEntitlement(
    tenantId,
    projection.principal_id,
  );
  const entitled = new Set(Array.isArray(entitlement?.capabilityIds) ? entitlement.capabilityIds : []);
  if (!entitlement || !capabilities.every(capability => entitled.has(capability) || entitled.has("*"))) {
    throw new Error("MIG_READ_BASELINE_ENTITLEMENT_MISSING");
  }
  return {
    run_ref: projection.manifest_ref,
    proof_ref: entitlement.entitlementId,
  };
}

export const DOMAIN_DISCOVERY_TOOL_NAMES = [
  "list_domains", "get_domain_package", "list_active_odps",
  "get_odp_registry_status", "check_odp_activation",
];

const DISCOVERY_TOOL_NAMES = [
  "list_domains", "get_domain_package", "list_capabilities", "search_capabilities",
  "get_capability_contract", "list_bripe_layers", "get_required_layers",
  "list_doctrines", "get_doctrine", "get_doctrines_by_layer", "list_active_odps",
  "get_odp_registry_status", "validate_domain_package", "list_adam_phases",
  "get_governance_contract", "check_odp_activation", "validate_decision_manifest",
  "retrieve_adaptation_memories",
];

const EXECUTION_TOOL_NAMES = [
  "start_autopilot_objective", "run_bripe_decision", "ingest_replay_record", "ingest_calibra_record",
];

function capabilityIdsFor(toolNames: string[]): string[] {
  const catalog = bripeToolCatalog();
  return catalog.filter(t => toolNames.includes(t.tool_name)).map(t => t.capability_id);
}

export async function seedByolabDomainUniverseIntent(): Promise<void> {
  await upsertIntentDefinition({
    intentId: "byolab_domain_universe", libraryId: BRIPE_CORE_LIBRARY_ID,
    name: "Byolab Domain Universe",
    description: "Byolab-only whole-domain candidate creation, immutable successor updates from contributed ontology/UI snapshots, and lossless historical retrieval. No canonical admission or activation.",
    allowedCapabilityIds: capabilityIdsFor(["create_domain_universe", "update_domain_universe", "get_domain_universe"]),
    deniedCapabilityIds: [], allowedToolNames: ["create_domain_universe", "update_domain_universe", "get_domain_universe"],
    deniedToolNames: [], domainScope: ["*"], packageScope: ["*"], riskZone: "medium",
    payloadClasses: ["metadata"], requiresHumanApproval: false,
    requiresEvidence: false, requiresManifest: true, status: "published",
  });
}

export async function seedByolabHistoricalEventsIntent(): Promise<void> {
  const tools = ["get_historical_event_contract", "submit_historical_events", "get_historical_event_receipt"];
  await upsertIntentDefinition({
    intentId: "byolab_historical_events", libraryId: BRIPE_CORE_LIBRARY_ID,
    name: "Byolab Historical Source Events",
    description: "Byolab-only atomic append-only historical source capture and exact receipt retrieval; no canonical admission, learning or action execution.",
    allowedCapabilityIds: capabilityIdsFor(tools), deniedCapabilityIds: [],
    allowedToolNames: tools, deniedToolNames: [], domainScope: ["*"], packageScope: ["*"],
    riskZone: "medium", payloadClasses: ["metadata"], requiresHumanApproval: false,
    requiresEvidence: false, requiresManifest: true, status: "published",
  });
}

export async function seedDefaultBripeIntentLibrary(): Promise<void> {
  await createIntentLibrary({
    libraryId: BRIPE_CORE_LIBRARY_ID,
    name: "BRIPe Core MCP Intent Library",
    version: "1.0.0",
    status: "draft",
  });
  await publishIntentLibrary(BRIPE_CORE_LIBRARY_ID);

  await seedByolabDomainUniverseIntent();
  await seedByolabHistoricalEventsIntent();

  await upsertIntentDefinition({
    intentId: "domain_discovery",
    libraryId: BRIPE_CORE_LIBRARY_ID,
    name: "Domain Discovery",
    description: "Narrow read-only access to BRIPe domain/ODP registry listing only (list domains, get domain packages, ODP registry status). No capability introspection, doctrine exploration, or execution.",
    allowedCapabilityIds: capabilityIdsFor(DOMAIN_DISCOVERY_TOOL_NAMES),
    deniedCapabilityIds: [],
    allowedToolNames: DOMAIN_DISCOVERY_TOOL_NAMES,
    deniedToolNames: EXECUTION_TOOL_NAMES,
    domainScope: ["*"],
    packageScope: ["*"],
    riskZone: "low",
    payloadClasses: ["metadata"],
    requiresHumanApproval: false,
    requiresEvidence: false,
    requiresManifest: true,
    status: "published",
  });

  await upsertIntentDefinition({
    intentId: "decision_execution",
    libraryId: BRIPE_CORE_LIBRARY_ID,
    name: "Decision Execution",
    description: "Authorizes BRIPe decision execution and autopilot objectives in the bcentrisk execution domain. Business ODP selection remains independently governed.",
    allowedCapabilityIds: capabilityIdsFor(EXECUTION_TOOL_NAMES),
    deniedCapabilityIds: [],
    allowedToolNames: EXECUTION_TOOL_NAMES,
    deniedToolNames: [],
    domainScope: ["bcentrisk"],
    packageScope: ["*"],
    riskZone: "medium",
    payloadClasses: ["decision_output"],
    requiresHumanApproval: true,
    requiresEvidence: true,
    requiresManifest: true,
    status: "published",
  });

  // ── Byolab Evidence Re-acquisition intent ─────────────────────────────────
  // Narrower than decision_execution: only run_bripe_decision is authorized.
  // requiresHumanApproval=false because the confidence gate (≥0.70, ≥2 families)
  // is the automated evidence-based approval equivalent.
  const BYOLAB_REACQUISITION_TOOL_NAMES = ["run_bripe_decision"];
  await upsertIntentDefinition({
    intentId: BYOLAB_REACQUISITION_INTENT_ID,
    libraryId: BRIPE_CORE_LIBRARY_ID,
    name: "Byolab Evidence Re-acquisition",
    description: "Authorizes internal Byolab discovery agents to trigger BRIPe structural re-analysis after evidence confidence gate is met (confidence ≥0.70, ≥2 independent families). Narrower than decision_execution — run_bripe_decision only.",
    allowedCapabilityIds: capabilityIdsFor(BYOLAB_REACQUISITION_TOOL_NAMES),
    deniedCapabilityIds: [],
    allowedToolNames: BYOLAB_REACQUISITION_TOOL_NAMES,
    deniedToolNames: [],
    domainScope: ["*"],
    packageScope: ["*"],
    riskZone: "medium",
    payloadClasses: ["decision_output"],
    requiresHumanApproval: false,
    requiresEvidence: true,
    requiresManifest: true,
    status: "published",
  });

  // Deprecate stale intents from previous seeding runs so existing deployments converge.
  const { storage } = await import("../storage");
  for (const staleId of [
    "healthcare_visibility", "audit_provider_visibility",
    "structural_risk_analysis", "intelligence_read_access", "bal_signal_ingestion",
  ]) {
    const existing = await storage.getMigIntentDefinition(staleId);
    if (existing && existing.status !== "deprecated") {
      await storage.updateMigIntentDefinition(staleId, { status: "deprecated" });
    }
  }
}

export const BRIPE_CORE_INTENT_LIBRARY_ID = BRIPE_CORE_LIBRARY_ID;

export const BRIPE_DOMAIN_DISCOVERY_TOOL_NAMES = DOMAIN_DISCOVERY_TOOL_NAMES;

export const BRIPE_DISCOVERY_TOOL_NAMES = DISCOVERY_TOOL_NAMES;

export const BRIPE_EXECUTION_TOOL_NAMES = EXECUTION_TOOL_NAMES;