import { randomUUID } from "crypto";
import type { Request } from "express";
import type { MigClient } from "@shared/schema";
import type { VerifiedCredentialIdentity } from "../mig/mig-authorization-context";
import { storage } from "../storage";
import { hashPayload } from "../mig/mig-audit";
import { sealMigCallOutcome } from "../mig/mig-client-lineage";
import { authorizeBripeMcpProtocolRequest, getBripeToolAuthorizationEntry } from "../mig/mig-bripe-adapter";
import { REMOTE_MCP_INTENT, REMOTE_MCP_TOOLS, remoteMcpResource } from "../mig/mig-remote-mcp-clients";
import { assertContractValid, recordFailedGateInvocation, ContractGateError, type ContractGateRepository } from "./contract-invocation-gate";
import { getCapabilityContract } from "./bripe-mcp-registry-adapter";
import type { McpMigLineageContext } from "../../shared/protocol/server/mcp/mcp-auth-adapters";
import type { InsertMigJourney, MigJourney, InsertMigJourneyCall, MigJourneyCall } from "@shared/schema";

// Existing lineage storage methods are not all declared on the broad IStorage
// interface. Keep the same narrow typed repository boundary here rather than
// changing unrelated consumers' interface/diagnostic contracts.
const lineageStorage = storage as typeof storage & {
  createMigJourney(data: InsertMigJourney): Promise<MigJourney>;
  createMigJourneyCall(data: InsertMigJourneyCall): Promise<MigJourneyCall>;
};

export interface RemoteMcpRequestContext { intentId: string; domainId: string; resourceRef: string }

/** Reject authority supplied by ordinary clients instead of silently overwriting it. */
export function assertRemoteMcpRequest(req: Request, tenantId: string) {
  for (const header of Object.keys(req.headers ?? {})) {
    if ((header.startsWith("x-mig-") && header !== "x-mig-api-key") ||
        ["x-tenant-id", "x-user-id", "x-api-key", "authorization", "x-internal-session-proof"].includes(header)) {
      throw new Error("Remote MCP clients cannot supply authority or lineage overrides.");
    }
  }
  if (req.query && Object.keys(req.query).length) throw new Error("Remote MCP query parameters are not supported.");
  const body = req.body;
  if (Array.isArray(body)) throw new Error("Remote MCP batch requests are not supported.");
  if (!body || typeof body !== "object") return; // GET probes return 405 at transport boundary.
  for (const key of Object.keys(body)) {
    if (!["jsonrpc", "id", "method", "params", "contractEnvelope"].includes(key)) {
      throw new Error("Remote MCP request contains an unsupported authority field.");
    }
  }
  const allowed = ["initialize", "notifications/initialized", "notifications/cancelled", "ping", "tools/list", "tools/call"];
  if (!allowed.includes(body.method)) throw new Error("Remote MCP method is outside the selected preset.");
  // Unknown keys must be rejected before SDK/Zod can strip them.
  const authorityKeys = new Set(["tenant", "tenant_id", "tenantId", "principal", "principal_id", "principalId",
    "actor", "actor_id", "actorPrincipalId", "roles", "role", "groups", "group", "scopes", "scope",
    "authorization", "authorization_state", "policy_decision", "intent", "intent_id", "intentId",
    "journey_id", "journeyId", "parent_call_id", "parentCallId", "resource_ref", "resourceRef"]);
  const inspect = (value: unknown, depth: number) => {
    if (depth > 12) throw new Error("Remote MCP arguments are too deeply nested.");
    if (!value || typeof value !== "object") return;
    for (const [key, nested] of Object.entries(value)) {
      if (authorityKeys.has(key)) throw new Error("Remote MCP arguments cannot override server-owned authority.");
      inspect(nested, depth + 1);
    }
  };
  inspect(body.params, 0);
  void tenantId;
}

export function remoteMcpContext(credential: VerifiedCredentialIdentity, tenantId: string): RemoteMcpRequestContext {
  const domains = credential.credentialDomainCeiling ?? [];
  if (domains.length !== 1 || domains[0] === "*" ||
      !credential.credentialIntentCeiling?.includes(REMOTE_MCP_INTENT) ||
      !credential.credentialResourceCeiling?.includes(remoteMcpResource(tenantId)) ||
      credential.credentialRiskZoneCeiling !== "low") throw new Error("Remote MCP preset binding is invalid.");
  return { intentId: REMOTE_MCP_INTENT, domainId: domains[0], resourceRef: remoteMcpResource(tenantId) };
}
export function remoteMcpAllowedTools(credential: VerifiedCredentialIdentity) {
  return REMOTE_MCP_TOOLS.filter(name => {
    const entry = getBripeToolAuthorizationEntry(name);
    return entry?.classification === "read_only" && entry.semantic_action === "read" &&
      credential.credentialCapabilityCeiling.includes(entry.capability_id);
  });
}

/**
 * The anchor is an actual authorized list_domains dispatch through the existing
 * MCP server, with its one-shot delegation and invocation audit. Never stamp
 * "succeeded" merely because authorization passed.
 */
export async function establishRemoteMcpLineage(client: MigClient, credential: VerifiedCredentialIdentity,
  tools = remoteMcpAllowedTools(credential)): Promise<McpMigLineageContext> {
  const config = await storage.getMigTenantAuthorityConfig(client.tenantId);
  if (config && (config.status !== "active" || config.authorityProvider !== "mig_native" ||
      config.deploymentMode !== "full_control_plane")) throw new Error("Remote MCP tenant authority is not active.");
  const context = remoteMcpContext(credential, client.tenantId);
  if (!tools.includes("list_domains")) throw new Error("Remote MCP domain discovery anchor is unavailable.");
  const journey = await lineageStorage.createMigJourney({
    journeyId: `mig_journey_${randomUUID()}`, tenantId: client.tenantId,
    originUserId: client.originUserId ?? `remote-client:${client.principalId}`,
    originAgentId: client.componentId, rootIntentId: context.intentId, rootIntent: context.intentId,
  });
  const parent = await lineageStorage.createMigJourneyCall({
    callId: `mig_call_${randomUUID()}`, journeyId: journey.journeyId, tenantId: client.tenantId,
    sequence: 0, currentIntentId: context.intentId, currentIntent: context.intentId,
    callerComponentId: client.componentId, callerClass: "MCP", targetComponentId: client.componentId,
    inputHash: hashPayload({ tool: "list_domains", arguments: {} }),
  });
  const outcomeBase = { tenantId: client.tenantId, journeyId: journey.journeyId, callId: parent.callId };
  let admitted = false;
  let terminalRecorded = false;
  let manifestId: string | undefined;
  try {
    const authorization = await authorizeBripeMcpProtocolRequest({
      verifiedCredential: { ...credential, credentialActionCeiling: "read" },
      classification: "read_only", allowedTools: tools, allowedIntents: [context.intentId],
      method: "tools/call", toolName: "list_domains", ...context, requestId: parent.callId, clientId: client.componentId,
    });
    manifestId = authorization.authorizationManifestIds[0];
    if (!authorization.allowed) {
      await sealMigCallOutcome({ ...outcomeBase, outcome: "denied", reason: authorization.reason,
        authorizationManifestId: manifestId });
      terminalRecorded = true;
      throw new Error(`Remote MCP anchor denied: ${authorization.reason}`);
    }
    if (!manifestId || !authorization.delegationToken) throw new Error("Remote MCP anchor admission proof is incomplete.");
    const gateContext = {
      tenantId: client.tenantId, clientId: client.componentId, toolName: "list_domains", capabilityId: "list_domains",
    };
    try {
      await assertContractValid(undefined, storage as unknown as ContractGateRepository, gateContext, getCapabilityContract);
    } catch (error) {
      if (error instanceof ContractGateError) {
        await recordFailedGateInvocation(undefined, storage as unknown as ContractGateRepository, gateContext, error.code);
      }
      throw error;
    }
    await sealMigCallOutcome({ ...outcomeBase, outcome: "allowed", reason: "remote_mcp_anchor_admitted",
      authorizationManifestId: manifestId });
    admitted = true;
    const [{ Client }, { InMemoryTransport }, { createBripeMcpServer }] = await Promise.all([
      import("@modelcontextprotocol/sdk/client/index.js"),
      import("@modelcontextprotocol/sdk/inMemory.js"),
      import("./bripe-mcp-server"),
    ]);
    const server = createBripeMcpServer({
      tenantId: client.tenantId, principalId: client.principalId, classification: "read_only",
      allowedTools: ["list_domains"], migAllowedTools: ["list_domains"],
      delegationToken: authorization.delegationToken,
      delegationExpectation: { requestId: parent.callId, mcpMethod: "tools/call",
        resourceRef: context.resourceRef, toolName: "list_domains" },
      migAudit: { migClientId: client.componentId, migPrincipalId: client.principalId,
        journeyId: journey.journeyId, originUserId: journey.originUserId, originAgentId: client.componentId,
        rootIntentId: context.intentId,
        compoundedIntentIds: [context.intentId], graphCallIds: [parent.callId], resourceRef: context.resourceRef },
    });
    const caller = new Client({ name: "MIG remote-client anchor", version: "1" });
    const [callerTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    let result: Awaited<ReturnType<typeof caller.callTool>>;
    try {
      await server.connect(serverTransport);
      await caller.connect(callerTransport);
      result = await caller.callTool({ name: "list_domains", arguments: {} });
      if (result.isError) throw new Error("Canonical domain discovery anchor dispatch failed.");
    } finally {
      await caller.close().catch(() => undefined);
      await server.close().catch(() => undefined);
    }
    // Check the same active binding again after dispatch, before promoting success.
    const active = await storage.getActiveMigClientByComponent(client.tenantId, client.componentId);
    const binding = await storage.getActiveMigCredentialBinding(credential.credentialRef);
    if (!active || active.credentialHash !== client.credentialHash || !binding ||
        binding.tenantId !== client.tenantId || binding.principalId !== client.principalId) {
      throw new Error("Remote MCP credential was revoked during admission.");
    }
    await sealMigCallOutcome({ ...outcomeBase, outcome: "succeeded", reason: "remote_mcp_anchor_completed",
      authorizationManifestId: manifestId, result });
  } catch (error) {
    if (admitted) await sealMigCallOutcome({ ...outcomeBase, outcome: "failed", reason: "remote_mcp_anchor_failed",
      authorizationManifestId: manifestId });
    else if (!terminalRecorded) await sealMigCallOutcome({ ...outcomeBase, outcome: "denied", reason: "remote_mcp_anchor_not_admitted",
      authorizationManifestId: manifestId });
    throw error;
  }
  return {
    journeyId: journey.journeyId, parentCallId: parent.callId,
    originUserId: journey.originUserId, originAgentId: journey.originAgentId,
    rootIntentId: context.intentId, rootIntent: context.intentId,
    compoundedIntentIds: [context.intentId], graphCallIds: [parent.callId],
  };
}
