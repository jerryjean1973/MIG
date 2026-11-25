import type { Request } from "express";

import type { McpKeyClassification } from "@shared/schema";

import type { VerifiedCredentialIdentity } from "../mig/mig-authorization-context";

import { storage } from "../storage";

import { hashMcpApiKey, resolveMcpApiKey } from "./bripe-mcp-auth";

import { resolveEntraToken } from "./entra-jwt-middleware";

import { getActiveMcpTools } from "./bripe-mcp-tools";

import { authenticateMigClient } from "../mig/mig-client-lineage";

import { resolveTenantAuthority } from "../mig/mig-authority-provider";

import { sealMigCallOutcome } from "../mig/mig-client-lineage";

import { authorizeBripeMcpProtocolRequest } from "../mig/mig-bripe-adapter";

import { createHash, randomUUID, timingSafeEqual } from "crypto";

import { resolveBcentriskSessionFacade } from "../mig/bcentrisk-session-facade";

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function intersectCeiling(canonical: string[], legacy: string[] | null | undefined): string[] {
  if (!legacy?.length) return canonical;
  if (canonical.includes("*")) return [...new Set(legacy)];
  if (legacy.includes("*")) return canonical;
  const legacySet = new Set(legacy);
  return canonical.filter(value => legacySet.has(value));
}

export interface McpCallingClient {
  name?: string;
  version?: string;
  userAgent?: string;
}

export interface McpMigLineageContext {
  journeyId: string;
  parentCallId: string;
  originUserId: string;
  originAgentId: string;
  rootIntentId: string;
  rootIntent: string;
  compoundedIntentIds: string[];
  graphCallIds: string[];
}

export type McpCredentialResult =
  | {
      ok: true;
      adapter: "mig_proxy" | "entra_oidc";
      tenantId: string;
      classification: McpKeyClassification;
      allowedTools: string[] | null;
      allowedIntents: string[] | null;
      apiKeyId?: number;
      migAgentId?: string;
      migPrincipalId?: string;
      legacyCompatibility?: boolean;
      remoteContext?: import("./remote-mcp-ingress").RemoteMcpRequestContext;
      migLineage?: McpMigLineageContext;
      credential: VerifiedCredentialIdentity;
      callingClient: McpCallingClient;
    }
  | {
      ok: false;
      status: number;
      error: string;
      adapter: "mig_proxy" | "entra_oidc" | "none";
      stage: "discovery" | "token_verification" | "canonical_mapping" | "credential_binding" | "lineage";
    };

function callingClient(req: Request): McpCallingClient {
  const params = req.body && typeof req.body === "object" ? req.body.params : undefined;
  const info = params && typeof params === "object" ? params.clientInfo : undefined;
  return {
    name: typeof info?.name === "string" ? info.name : undefined,
    version: typeof info?.version === "string" ? info.version : undefined,
    userAgent: req.header("user-agent") ?? undefined,
  };
}

function stringsAt(value: unknown, paths: string[][]): string[] {
  const values = new Set<string>();
  for (const path of paths) {
    let current: any = value;
    for (const segment of path) current = current && typeof current === "object" ? current[segment] : undefined;
    if (typeof current === "string" && current.trim()) values.add(current.trim());
  }
  return [...values];
}

export function canonicalToolTarget(req: Request): { resourceRefs: string[]; domainIds: string[]; environments: string[] } | undefined {
  if (req.body?.method !== "tools/call" || typeof req.body?.params?.name !== "string") return undefined;
  const tool = getActiveMcpTools().find(candidate => candidate.name === req.body.params.name);
  if (!tool) return undefined;
  const parsed = tool.inputSchema.safeParse(req.body?.params?.arguments ?? {});
  if (!parsed.success) return undefined;
  const input = parsed.data;
  // These source-only tools share one server-owned compatibility resource.
  // Otherwise write calls have no target and reads select tool-specific targets,
  // making an accepted receipt impossible to retrieve through the same client.
  // This mapping grants nothing: exact Byolab identity and all MIG ceilings
  // remain enforced independently at discovery, authorization and the handler.
  if (["get_historical_event_contract", "submit_historical_events", "get_historical_event_receipt"].includes(tool.name)) {
    return { resourceRefs: ["byolab:historical-events"], domainIds: [], environments: [] };
  }
  if (["create_domain_universe", "update_domain_universe", "get_domain_universe"].includes(tool.name)) {
    return { resourceRefs: ["byolab:domain-universe"], domainIds: [], environments: [] };
  }
  // Handshake mode only reads the nested source account. Unrelated assessment
  // subjects must not authorize a lookup against a different account.
  const isSourceJson = tool.name === "run_bripe_decision" && (
    input.source_json !== undefined || input.source_upload_ref
    || input.source_json_binding_ref || input.source_json_request_ref
  );
  const resourceInput = tool.name === "run_bripe_decision" && input.organization_handshake
    ? { organization_handshake: input.organization_handshake }
    // JSON intake and continuation operate on the confirmed organization.
    // A source subject is a different namespace and cannot stand in for it.
    : isSourceJson && input.canonical_organization_id
      ? { canonical_organization_id: input.canonical_organization_id }
    : input;
  return {
    resourceRefs: stringsAt(resourceInput, [
      ["entity_id"], ["entityId"], ["subject_id"], ["subjectId"], ["vendor_id"], ["vendorId"], ["assessment_id"], ["assessmentId"],
      ["vendorname"], ["session_id"],
      ["source_graph", "source_subject", "id"],
      ["organization_handshake", "source_account_id"],
      ["canonical_organization_id"],
      ["operational_assessment", "canonical_subject_id"],
      ["decision_context", "entity_id"], ["decision_context", "entityId"], ["decision_context", "subject_id"], ["decision_context", "vendor_id"],
      ["canonical_envelope", "entity_id"], ["canonical_envelope", "entityId"],
      ["canonical_envelope", "enterprise_context", "enterprise_id"], ["canonical_envelope", "enterprise_context", "entity_id"],
      ["canonical_envelope", "entity", "entity_id"], ["canonical_envelope", "entity", "id"],
      ["canonical_envelope", "decision_context", "entity_id"], ["canonical_envelope", "decision_context", "subject_id"],
    ]),
    domainIds: stringsAt(input, [
      ["domain_id"], ["domainId"], ["scope_context", "domain"],
      ["decision_context", "domain_id"], ["decision_context", "domainId"],
      ["canonical_envelope", "domain_id"], ["canonical_envelope", "domainId"],
      ["canonical_envelope", "domain_profile", "domain_id"], ["canonical_envelope", "domain_profile", "domainId"],
      ["canonical_envelope", "decision_context", "domain_id"], ["canonical_envelope", "enterprise_context", "domain_id"],
    ]),
    environments: stringsAt(input, [
      ["environment"], ["decision_context", "environment"], ["canonical_envelope", "enterprise_context", "environment"],
    ]),
  };
}

export async function authenticateMcpRequest(req: Request): Promise<McpCredentialResult> {
  // Loopback-only server façade authentication. This is a server-to-server
  // proof using the existing session secret; the browser never sees it.
  const internalProof = req.header("x-internal-session-proof");
  const internalTenant = req.header("x-mig-session-tenant");
  const internalUser = req.header("x-mig-session-user");
  const configuredSecret = process.env.SESSION_SECRET ?? "";
  const proofMatches = internalProof && configuredSecret &&
    internalProof.length === configuredSecret.length &&
    timingSafeEqual(Buffer.from(internalProof), Buffer.from(configuredSecret));
  if (proofMatches && internalTenant &&
      (req.ip === "127.0.0.1" || req.ip === "::1" || req.ip === "::ffff:127.0.0.1" ||
        req.socket.remoteAddress === "127.0.0.1" || req.socket.remoteAddress === "::1")) {
    const client = await resolveBcentriskSessionFacade(internalTenant).catch(() => undefined);
    if (!client || client.clientClass !== "MCP" || client.tenantId !== internalTenant || !client.credentialHash) {
      return { ok: false, status: 503, error: "Server-owned MCP participant is not configured", adapter: "none", stage: "canonical_mapping" };
    }
    const authority = await resolveTenantAuthority({ tenantId: internalTenant, credentialRef: `mig-key:${client.credentialHash}` });
    if (!authority) return { ok: false, status: 503, error: "Server-owned tenant authority is unavailable", adapter: "none", stage: "credential_binding" };
    const principal = await storage.getMigPrincipal(internalTenant, client.principalId);
    if (!principal || principal.status !== "active") {
      return { ok: false, status: 403, error: "Server-owned MCP participant is not active", adapter: "none", stage: "canonical_mapping" };
    }
    const intent = req.header("x-mig-intent-id");
    const domainId = req.header("x-mig-domain-id");
    const resourceRef = req.header("x-mig-resource-ref");
    if (intent !== "decision_execution" || domainId !== "bcentrisk" || !resourceRef?.startsWith(`bripe:${internalTenant}:`)) {
      return { ok: false, status: 403, error: "Server-owned MCP authorization context is invalid", adapter: "none", stage: "lineage" };
    }
    const journey = await storage.createMigJourney({
      journeyId: `mig_journey_${randomUUID()}`, tenantId: internalTenant,
      originUserId: internalUser ? `session:${internalUser}` : `session:${principal.principalId}`, originAgentId: client.componentId,
      rootIntentId: intent, rootIntent: intent,
    });
    const callId = `mig_call_${randomUUID()}`;
    const parent = await storage.createMigJourneyCall({
      callId, journeyId: journey.journeyId, tenantId: internalTenant, sequence: 0,
      currentIntentId: intent, currentIntent: intent, callerComponentId: "bcentrisk-session-facade",
      callerClass: "MCP", targetComponentId: client.componentId,
      inputHash: createHash("sha256").update("bcentrisk-session-facade").digest("hex"),
    });
    const credential = authority;
    const authorization = await authorizeBripeMcpProtocolRequest({
      verifiedCredential: credential, classification: "execution",
      allowedTools: ["run_bripe_decision"], allowedIntents: [intent],
      method: "tools/call", toolName: "run_bripe_decision", intentId: intent,
      domainId, resourceRef,
      requestId: callId, clientId: client.componentId,
    });
    if (!authorization.allowed || !authorization.delegationToken) {
      return { ok: false, status: 403, error: `Server-owned MIG authorization denied: ${authorization.reason}`, adapter: "none", stage: "lineage" };
    }
    await sealMigCallOutcome({ tenantId: internalTenant, journeyId: journey.journeyId, callId, outcome: "allowed", reason: "server_owned_session_facade", authorizationManifestId: authorization.authorizationManifestIds[0] });
    return {
      ok: true, adapter: "mig_proxy", tenantId: internalTenant, classification: "execution",
      allowedTools: ["run_bripe_decision"], allowedIntents: [intent],
      migAgentId: client.componentId, migPrincipalId: principal.principalId, credential,
      callingClient: { name: "BCentrisk session façade", version: "1" },
      migLineage: {
        journeyId: journey.journeyId, parentCallId: parent.callId,
        originUserId: journey.originUserId, originAgentId: journey.originAgentId,
        rootIntentId: intent, rootIntent: intent, compoundedIntentIds: [intent], graphCallIds: [parent.callId],
      },
    };
  }
  const authorization = req.header("authorization");
  const legacyApiKey = req.header("x-api-key");
  const migApiKey = req.header("x-mig-api-key");
  // A legacy credential is only a compatibility selector.  It may never be
  // combined with caller-supplied MIG identity or lineage (which would make
  // the old credential an oracle for choosing a different tenant/agent).
  if (legacyApiKey) {
    if (authorization || migApiKey ||
        req.header("x-mig-parent-call-id") || req.header("x-mig-intent-id") ||
        req.header("x-mig-domain-id") || req.header("x-mig-resource-ref")) {
      return { ok: false, status: 403, error: "Legacy MCP credentials cannot supply MIG identity overrides", adapter: "none", stage: "canonical_mapping" };
    }
    const key = await resolveMcpApiKey(legacyApiKey);
    if (!key.ok) return { ...key, adapter: "none", stage: "token_verification" };
    storage.touchMcpApiKeyLastUsed(key.apiKeyId).catch(() => undefined);
    if (!key.principalId || !key.migAgentId) {
      return { ok: false, status: 403, error: "Legacy MCP credential has no canonical MIG participant mapping", adapter: "none", stage: "canonical_mapping" };
    }
    const agent = await storage.getMigAgentByAgentId(key.migAgentId);
    if (!agent || agent.status !== "active" || agent.tenantId !== key.tenantId ||
        agent.principalId !== key.principalId) {
      return { ok: false, status: 403, error: "Legacy MCP credential is not mapped to an active MIG participant", adapter: "none", stage: "canonical_mapping" };
    }
    const principal = await storage.getMigPrincipal(key.tenantId, key.principalId);
    if (!principal || principal.status !== "active") {
      return { ok: false, status: 403, error: "MIG participant identity is not active", adapter: "none", stage: "credential_binding" };
    }
    const tenantAuthority = await storage.getMigTenantAuthorityConfig(key.tenantId);
    if (tenantAuthority && tenantAuthority.authorityProvider !== "mig_native") {
      return { ok: false, status: 403, error: "Tenant authority configuration does not permit legacy MCP compatibility", adapter: "none", stage: "credential_binding" };
    }
    const legacyResources = Array.isArray(key.resourceConstraints.resources)
      ? key.resourceConstraints.resources.filter((value): value is string => typeof value === "string")
      : [];
    const narrowedIntents = intersectCeiling(asStrings(agent.allowedIntents), key.allowedIntents);
    const narrowedDomains = intersectCeiling(asStrings(agent.allowedDomains), key.allowedDomains);
    const credentialRef = `mcp-key:${hashMcpApiKey(legacyApiKey)}`;
    const narrowedCredential: VerifiedCredentialIdentity = {
      credentialRef,
      credentialType: "api_key",
      principalId: principal.principalId,
      tenantId: principal.tenantId,
      principalType: principal.principalType as VerifiedCredentialIdentity["principalType"],
      principalStatus: "active",
      credentialStatus: "active",
      credentialCapabilityCeiling: key.effectiveScopes,
      credentialScopes: key.effectiveScopes,
      credentialIntentCeiling: narrowedIntents,
      credentialDomainCeiling: narrowedDomains,
      credentialMcpTargetCeiling: [agent.agentId],
      credentialResourceCeiling: legacyResources,
      credentialRiskZoneCeiling: asStrings(agent.allowedRiskZones).includes("critical") ? "critical"
        : asStrings(agent.allowedRiskZones).includes("high") ? "high"
        : asStrings(agent.allowedRiskZones).includes("medium") ? "medium" : "low",
      credentialActionCeiling: key.classification === "read_only" ? "read" : "execute",
      authorityProvider: "mig_native",
      authorityRef: credentialRef,
      authoritySourceEvidence: ["active_mcp_api_key", "canonical_principal_binding", "active_mig_agent_binding"],
      actorPrincipalId: principal.principalId,
      executorPrincipalId: principal.principalId,
    };
    const intent = narrowedCredential.credentialIntentCeiling[0];
    if (!intent) return { ok: false, status: 403, error: "Legacy MCP credential has no canonical intent ceiling", adapter: "none", stage: "lineage" };
    const journey = await storage.createMigJourney({
      journeyId: `mig_journey_${randomUUID()}`, tenantId: key.tenantId,
      originUserId: `mcp-compatibility:${key.apiKeyId}`,
      originAgentId: agent.agentId, rootIntentId: intent, rootIntent: intent,
    });
    const parentRequestId = `mig_call_${randomUUID()}`;
    const parent = await storage.createMigJourneyCall({
      callId: `${parentRequestId}:list_domains`, journeyId: journey.journeyId, tenantId: key.tenantId,
      parentCallId: undefined, sequence: 0, currentIntentId: intent, currentIntent: intent,
      callerComponentId: agent.agentId, callerClass: "MCP",
      targetComponentId: agent.agentId, inputHash: createHash("sha256").update("mcp-legacy-compatibility").digest("hex"),
    });
    const anchorAuthorization = await authorizeBripeMcpProtocolRequest({
      verifiedCredential: narrowedCredential,
      classification: key.classification,
      allowedTools: key.allowedTools,
      allowedIntents: narrowedIntents,
      method: "tools/call",
      toolName: "list_domains",
      intentId: intent,
      domainId: "*",
      resourceRef: `mcp:compatibility:${key.apiKeyId}`,
      // Authorization manifests and outcomes must bind to the exact admitted
      // journey call identity. Using the pre-admission request id here creates
      // a manifest that createMigJourneyOutcome correctly rejects.
      requestId: parent.callId,
      clientId: agent.agentId,
    });
    if (!anchorAuthorization.allowed) {
      await sealMigCallOutcome({
        tenantId: key.tenantId, journeyId: journey.journeyId, callId: parent.callId,
        outcome: "denied", reason: `server_owned_legacy_mcp_compatibility_anchor:${anchorAuthorization.reason}`,
        authorizationManifestId: anchorAuthorization.authorizationManifestIds[0],
      });
      return {
        ok: false, status: 403,
        error: `Legacy MCP compatibility lineage denied: ${anchorAuthorization.reason}`,
        adapter: "none", stage: "lineage",
      };
    }
    const anchorManifestId = anchorAuthorization.authorizationManifestIds[0];
    if (!anchorManifestId) {
      return { ok: false, status: 500, error: "Legacy MCP compatibility authorization manifest missing", adapter: "none", stage: "lineage" };
    }
    await sealMigCallOutcome({
      tenantId: key.tenantId, journeyId: journey.journeyId, callId: parent.callId,
      outcome: "allowed", reason: "server_owned_legacy_mcp_compatibility_anchor_authorized",
      authorizationManifestId: anchorManifestId,
    });
    await sealMigCallOutcome({
      tenantId: key.tenantId, journeyId: journey.journeyId, callId: parent.callId,
      outcome: "succeeded", reason: "server_owned_legacy_mcp_compatibility_anchor",
      authorizationManifestId: anchorManifestId,
    });
    return {
      ok: true, adapter: "mig_proxy", tenantId: key.tenantId, apiKeyId: key.apiKeyId,
      classification: key.classification, allowedTools: key.allowedTools,
      allowedIntents: narrowedIntents, migAgentId: agent.agentId,
      migPrincipalId: principal.principalId, credential: narrowedCredential, callingClient: callingClient(req),
      legacyCompatibility: true,
      migLineage: {
        journeyId: journey.journeyId, parentCallId: parent.callId,
        originUserId: journey.originUserId, originAgentId: journey.originAgentId,
        rootIntentId: journey.rootIntentId, rootIntent: journey.rootIntent,
        compoundedIntentIds: [intent], graphCallIds: [parent.callId],
      },
    };
  }
  let adapter: "mig_proxy" | "entra_oidc" = "mig_proxy";
  let classification: McpKeyClassification = "admin";
  let credential: VerifiedCredentialIdentity | undefined;
  let client: import("@shared/schema").MigClient | undefined;
  if (authorization) {
    adapter = "entra_oidc";
    const rawJwt = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
    if (!rawJwt) return { ok: false, status: 401, error: "Valid Entra Bearer token required", adapter, stage: "token_verification" };
    const verifiedToken = await resolveEntraToken(rawJwt);
    if (!verifiedToken.ok) return {
      ok: false,
      status: verifiedToken.status,
      error: verifiedToken.error,
      adapter,
      stage: verifiedToken.status === 401 ? "token_verification" : "canonical_mapping",
    };
    classification = verifiedToken.classification;
    credential = await resolveTenantAuthority({ tenantId: verifiedToken.tenantId, entraJwt: rawJwt });
    if (!credential) return { ok: false, status: 403, error: "Enterprise authority is not active", adapter, stage: "credential_binding" };
    client = await storage.getActiveMigClientByPrincipal(verifiedToken.tenantId, credential.principalId);
    if (!client) return { ok: false, status: 403, error: "Enterprise principal has no unique MIG participant binding", adapter, stage: "canonical_mapping" };
  } else {
    const rawMigKey = migApiKey;
    if (!rawMigKey) {
      return { ok: false, status: 401, error: "Valid OAuth Bearer token or full MIG MCP client key required", adapter, stage: "discovery" };
    }
    client = await authenticateMigClient(rawMigKey);
    if (!client || client.clientClass !== "MCP") {
      return { ok: false, status: 401, error: "Valid full MIG MCP client key required", adapter, stage: "token_verification" };
    }
  }
  if (client.clientClass !== "MCP") {
    return { ok: false, status: 403, error: "MCP ingress requires an active MCP-class participant binding", adapter, stage: "canonical_mapping" };
  }
  const [principal, nativeBinding] = await Promise.all([
    storage.getMigPrincipal(client.tenantId, client.principalId),
    adapter === "mig_proxy" ? storage.getActiveMigCredentialBinding(`mig-key:${client.credentialHash}`) : undefined,
  ]);
  if (!principal || principal.status !== "active" || principal.tenantId !== client.tenantId ||
      principal.principalId !== client.principalId ||
      adapter === "mig_proxy" && (!nativeBinding || nativeBinding.tenantId !== client.tenantId ||
        nativeBinding.principalId !== client.principalId || nativeBinding.credentialType !== "mig_mcp" ||
        nativeBinding.expiresAt && nativeBinding.expiresAt <= new Date())) {
    return { ok: false, status: 403, error: "MIG participant identity is not active", adapter, stage: "credential_binding" };
  }
  if (adapter === "mig_proxy") {
    credential = await resolveTenantAuthority({
      tenantId: client.tenantId,
      credentialRef: nativeBinding!.credentialRef,
    });
    if (!credential || credential.authorityProvider !== "mig_native") {
      return { ok: false, status: 403, error: "Tenant authority configuration does not permit native MCP credentials", adapter, stage: "credential_binding" };
    }
  }
  // Only explicitly admin-provisioned ordinary clients get server-owned root
  // lineage. Native continuation, OAuth and the internal façade stay unchanged.
  if (adapter === "mig_proxy" && Array.isArray(nativeBinding?.scopes) && nativeBinding.scopes.includes("remote-mcp:read_only:v1")) {
    try {
      const { isProvisionedRemoteMcpClient } = await import("../mig/mig-remote-mcp-clients");
      if (!isProvisionedRemoteMcpClient(client, nativeBinding)) throw new Error("Remote MCP participant binding is invalid.");
      const { assertRemoteMcpRequest, remoteMcpContext, remoteMcpAllowedTools, establishRemoteMcpLineage } = await import("./remote-mcp-ingress");
      assertRemoteMcpRequest(req, client.tenantId);
      const remoteContext = remoteMcpContext(credential!, client.tenantId);
      const allowedTools = remoteMcpAllowedTools(credential!);
      if (req.body?.method === "tools/call" && !allowedTools.includes(req.body?.params?.name)) {
        throw new Error("Remote MCP tool is outside the selected preset.");
      }
      const migLineage = await establishRemoteMcpLineage(client, credential!, allowedTools);
      return {
        ok: true, adapter, tenantId: client.tenantId, classification: "read_only",
        allowedTools, allowedIntents: [remoteContext.intentId],
        migAgentId: client.componentId, migPrincipalId: client.principalId,
        credential: { ...credential!, credentialActionCeiling: "read" },
        callingClient: callingClient(req), migLineage, remoteContext,
      };
    } catch (error) {
      return { ok: false, status: 403, error: error instanceof Error ? error.message : "Remote MCP admission failed", adapter, stage: "lineage" };
    }
  }
  const parentCallId = req.header("x-mig-parent-call-id");
  if (!parentCallId) {
    // OAuth establishes canonical identity for protocol initialization without
    // inventing lineage. Tool disclosure/execution remains fail-closed below
    // until a server-owned successful MIG parent is present.
    if (adapter === "entra_oidc") {
      return {
        ok: true,
        adapter,
        tenantId: client.tenantId,
        classification,
        allowedTools: null,
        allowedIntents: null,
        migAgentId: client.componentId,
        migPrincipalId: client.principalId,
        credential: credential!,
        callingClient: callingClient(req),
      };
    }
    return { ok: false, status: 403, error: "MIG proxy lineage anchor is required", adapter, stage: "lineage" };
  }
  const parent = await storage.getMigJourneyCall(client.tenantId, parentCallId);
  const parentOutcome = parent
    ? await storage.getMigJourneyOutcome(client.tenantId, parent.callId)
    : undefined;
  if (!parent || parent.targetComponentId !== client.componentId ||
      !parentOutcome || parentOutcome.outcome !== "succeeded") {
    return { ok: false, status: 403, error: "MIG proxy lineage is not authorized", adapter, stage: "lineage" };
  }
  const [journey, calls] = await Promise.all([
    storage.getMigJourney(client.tenantId, parent.journeyId),
    storage.listMigJourneyCalls(client.tenantId, parent.journeyId),
  ]);
  if (!journey) {
    return { ok: false, status: 403, error: "MIG proxy journey is not available", adapter, stage: "lineage" };
  }
  if (credential) {
    const targetCeiling = credential.credentialMcpTargetCeiling ?? [];
    if (credential.authorityProvider === "microsoft_entra" &&
        (!targetCeiling.length || !targetCeiling.includes("*") && !targetCeiling.includes(client.componentId))) {
      return { ok: false, status: 403, error: "Enterprise authority does not permit this MIG participant", adapter, stage: "credential_binding" };
    }
    const intentCeiling = credential.credentialIntentCeiling ?? [];
    if (credential.authorityProvider === "microsoft_entra" &&
        (!intentCeiling.length || !intentCeiling.includes("*") &&
          !intentCeiling.includes(journey.rootIntentId) && !intentCeiling.includes(journey.rootIntent))) {
      return { ok: false, status: 403, error: "Enterprise authority does not permit this journey intent", adapter, stage: "lineage" };
    }
  }
  return {
    ok: true,
    adapter,
    tenantId: client.tenantId,
    classification,
    allowedTools: null,
    allowedIntents: null,
    migAgentId: client.componentId,
    migPrincipalId: client.principalId,
    migLineage: {
      journeyId: journey.journeyId,
      parentCallId: parent.callId,
      originUserId: journey.originUserId,
      originAgentId: journey.originAgentId,
      rootIntentId: journey.rootIntentId,
      rootIntent: journey.rootIntent,
      compoundedIntentIds: [...new Set(calls.map(call => call.currentIntentId))],
      graphCallIds: calls.map(call => call.callId),
    },
    credential: credential!,
    callingClient: callingClient(req),
  };
}
