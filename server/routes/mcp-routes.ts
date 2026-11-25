/**
 * server/routes/mcp-routes.ts
 *
 * Mounts the BRIPe MCP interface at POST /api/mcp using the SDK's
 * StreamableHTTPServerTransport in stateless mode: each request gets a
 * fresh McpServer bound to the caller's tenant/classification context,
 * then the server/transport pair is torn down. This avoids any
 * cross-tenant session bleed and keeps the interface horizontally
 * scalable without shared session state.
 *
 * Registered from server/index.ts AFTER registerRoutes() per the
 * engine-snapshot-route-registration convention (routes.ts is >32k lines
 * and causes cold-start truncation if new route files are folded into it).
 *
 * Admin endpoints for MCP key management live here too, gated by the
 * existing in-app tenant-header auth (not the MCP API key itself —
 * you cannot mint MCP keys using an MCP key).
 */

import type { Express, Request, Response, NextFunction } from "express";
import { randomBytes, createHash } from "crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { hashMcpApiKey } from "../mcp/bripe-mcp-auth";
import { createBripeMcpServer, refreshBripeMcpServerTools, type McpServerContext } from "../mcp/bripe-mcp-server";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { getActiveMcpTools, MCP_CAPABILITY_GROUPS } from "../mcp/bripe-mcp-tools";
import { MCP_CLASSIFICATION_RANK } from "../mcp/bripe-mcp-schemas";
import { storage } from "../storage";
import type { ContractGateRepository } from "../../shared/protocol/server/mcp/contract-invocation-gate";
import { databaseKnowledgeAuthorityRepository } from "../standalone/knowledge-owner";
import { canonicalKnowledgeResourceRef, isCanonicalKnowledgeResourceRef, type CanonicalMCPKnowledgeBinding, type CanonicalKnowledgeResource } from "@shared/corporate-brain/canonical-knowledge-authority";
import { isProtectedCanonicalKnowledgeAlias } from "../mig/mig-enterprise-authorization";
import { getBripeToolAuthorizationEntry } from "../mig/mig-bripe-adapter";
import type { CanonicalKnowledgeAuthorityRepository } from "../standalone/knowledge-owner";
import { databaseMigMcpSchemaObservationRepository, latestSchemaObservation, type MigMcpSchemaObservationRepository } from "../mig/mig-mcp-schema-observation";

export async function resolveProtectedMcpBinding(input: {
  repository?: CanonicalKnowledgeAuthorityRepository;
  observationRepository?: MigMcpSchemaObservationRepository;
  tenant_id: string;
  mcp_server_id: string;
  mcp_tool_name: string;
  resource_ref: string;
  resource_version?: string;
  evaluated_at?: string;
}): Promise<{ binding: CanonicalMCPKnowledgeBinding; resource: CanonicalKnowledgeResource } | undefined> {
  const repository = input.repository ?? databaseKnowledgeAuthorityRepository;
  const observationRepository = input.observationRepository ?? databaseMigMcpSchemaObservationRepository;
  const observed = latestSchemaObservation(await observationRepository.list(
    input.tenant_id, input.mcp_server_id, input.mcp_tool_name,
  ));
  const rows = repository.listMcpBindings ? await repository.listMcpBindings(input.tenant_id) : [];
  const asOf = Date.parse(input.evaluated_at ?? new Date().toISOString());
  if (!Number.isFinite(asOf)) return undefined;
  const candidates = rows.filter(binding => binding.mcp_server_id === input.mcp_server_id && binding.mcp_tool_name === input.mcp_tool_name
    && Date.parse(binding.effective_from) <= asOf
    && (!binding.effective_to || Date.parse(binding.effective_to) > asOf));
  const successorMap = new Map<string, CanonicalMCPKnowledgeBinding[]>();
  for (const row of candidates) if (row.supersedes_binding_id) {
    const list = successorMap.get(row.supersedes_binding_id) ?? [];
    list.push(row); successorMap.set(row.supersedes_binding_id, list);
  }
  if ([...successorMap.values()].some(list => list.length > 1)) return undefined;
  const leaves = candidates.filter(row => !(successorMap.get(row.binding_id)?.length));
  if (new Set(leaves.map(row => row.binding_id)).size !== leaves.length) return undefined;
  const alias = /^vendor[-_:]?risk[-_:]?score:(v[^:]+|\d+(?:\.\d+)*)$/i.exec(input.resource_ref);
  const matches = leaves.filter(binding => {
    if (!["CONFIRMED", "OVERRIDDEN"].includes(binding.status)
      || binding.mcp_server_id !== input.mcp_server_id
      || binding.mcp_tool_name !== input.mcp_tool_name
      || !observed
      || observed.schema_version !== binding.mcp_schema_version
      || observed.schema_fingerprint !== binding.schema_fingerprint
      || (input.resource_version && binding.resource_version !== input.resource_version)
      || !binding.operation) return false;
    const resource: CanonicalKnowledgeResource = {
      tenant_id: binding.tenant_id, partition: binding.partition,
      canonical_object_id: binding.canonical_object_id, knowledge_id: binding.knowledge_id,
      version: binding.resource_version, knowledge_class: binding.knowledge_class,
      domain_id: binding.domain_id, producer_domain: binding.producer_domain,
    };
    return isCanonicalKnowledgeResourceRef(input.resource_ref)
      ? canonicalKnowledgeResourceRef(resource) === input.resource_ref
      : !!alias && binding.canonical_object_id === "vendor-risk-score"
        && binding.resource_version === alias[1].replace(/^v/i, "");
  });
  if (matches.length !== 1) return undefined;
  const binding = matches[0];
  return {
    binding,
    resource: {
      tenant_id: binding.tenant_id, partition: binding.partition,
      canonical_object_id: binding.canonical_object_id, knowledge_id: binding.knowledge_id,
      version: binding.resource_version, knowledge_class: binding.knowledge_class,
      domain_id: binding.domain_id, producer_domain: binding.producer_domain,
    },
  };
}
import { type McpKeyClassification } from "@shared/schema";
import { readMcpCallLog } from "../mcp/mcp-call-logger";
import { readTsFindings } from "../mcp/troubleshooting-findings-store";
import { logConnectionAttempt, readConnectionLog } from "../mcp/mcp-connection-log";
import { assertContractValid, recordFailedGateInvocation, ContractGateError, type ContractGateContext } from "../mcp/contract-invocation-gate";
import { runAdamAuditColumnsMigration } from "../mcp/mcp-adam-audit-migration";
import { invalidateEntraTenantMappingCache } from "../mcp/entra-jwt-middleware";
import { authenticateMcpRequest, canonicalToolTarget } from "../mcp/mcp-auth-adapters";
import { authorizeBripeMcpProtocolRequest, buildBripeAuthorizationCatalog } from "../mig/mig-bripe-adapter";
import { evaluateAuthorization, type MigEffectiveEntitlement, type MigTenantAuthorizationPolicy } from "../mig/mig-authorization-policy";
import { consumeMigDelegation } from "../mig/mig-delegation";
import { requireEnterpriseAdminContext } from "../routes-shared";
import { registerMigAgent } from "../mig/mig-agent-registry";
import { requireEnterpriseSchemaReady } from "../migrations/enterprise-schema-readiness";
import { recordMigAuditEvent } from "../mig/mig-audit";
import { buildMcpBearerChallenge } from "../mcp/mcp-oauth-metadata";
import { getCapabilityContract } from "../mcp/bripe-mcp-registry-adapter";
import { MCP_ACCESS_PRESETS } from "@shared/mcp-access-presets";

/**
 * MIG-only auth middleware for POST /api/mcp.
 *
 * Only a full tenant-scoped MIG MCP credential is accepted. Direct Entra and
 * legacy MCP API-key authentication are retained for audit history only.
 *
 * After successful auth, standard req.mcpTenantId / req.mcpKeyClassification /
 * req.mcpAllowedTools are set so the downstream handler is auth-path-agnostic.
 */
export async function requireMcpAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const result = await authenticateMcpRequest(req);
  if (!result.ok) {
    const ip = (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim()
      ?? req.socket?.remoteAddress ?? "unknown";
    logConnectionAttempt({
      ts: new Date().toISOString(), ip,
      key_prefix_hint: req.header("x-mig-api-key")?.startsWith("mig_mcp_") ? "mig_mcp_" : "(none)",
      auth_ok: false, auth_error: result.error, http_status: result.status,
      auth_mechanism: result.adapter === "entra_oidc" ? "bearer" : result.adapter === "mig_proxy" ? "mig_proxy" : req.header("x-api-key") ? "legacy_api_key" : "none",
      auth_stage: result.stage,
    });
    if (result.status === 401) {
      res.setHeader("WWW-Authenticate", buildMcpBearerChallenge());
    }
    res.status(result.status).json({ error: result.error });
    return;
  }
  req.mcpTenantId = result.tenantId;
  req.mcpApiKeyId = result.apiKeyId;
  req.mcpKeyClassification = result.classification;
  req.mcpAllowedTools = result.allowedTools;
  req.mcpVerifiedCredential = result.credential;
  req.mcpAuthAdapter = result.adapter;
  req.mcpCallingClient = result.callingClient;
  req.mcpAllowedIntents = result.allowedIntents;
  req.mcpMigAgentId = result.migAgentId;
  req.mcpMigPrincipalId = result.migPrincipalId;
  req.mcpMigLineage = result.migLineage;
  req.mcpLegacyCompatibility = result.legacyCompatibility;
  req.mcpRemoteContext = result.remoteContext;
  next();
}

export function normalizeMcpResponseChunk(chunk: unknown): Buffer | null {
  if (chunk == null) return null;
  if (Buffer.isBuffer(chunk)) return chunk;
  if (typeof chunk === "string") return Buffer.from(chunk);
  if (ArrayBuffer.isView(chunk)) {
    return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  if (chunk instanceof ArrayBuffer) return Buffer.from(chunk);
  return Buffer.from(JSON.stringify(chunk));
}

const LEGACY_MCP_SESSION_TTL_MS = Math.min(
  5 * 60_000,
  Math.max(process.env.NODE_ENV === "test" ? 20 : 5_000, Number(process.env.MCP_LEGACY_SESSION_TTL_MS) || 60_000),
);

interface LegacyMcpSession {
  transport: SSEServerTransport;
  server: McpServer;
  context: McpServerContext;
  tenantId: string;
  principalId: string;
  agentId: string;
  credentialRef: string;
  journeyId: string;
  parentCallId: string;
  expiresAt: number;
  timer: NodeJS.Timeout;
  closing: boolean;
  messageInFlight: boolean;
  inFlightRequestId?: string | number;
}

const legacyMcpSessions = new Map<string, LegacyMcpSession>();

async function closeLegacyMcpSession(sessionId: string): Promise<void> {
  const session = legacyMcpSessions.get(sessionId);
  if (!session || session.closing) return;
  session.closing = true;
  legacyMcpSessions.delete(sessionId);
  clearTimeout(session.timer);
  await session.server.close().catch(() => undefined);
}

function legacySessionMatches(req: Request, session: LegacyMcpSession): boolean {
  return req.mcpTenantId === session.tenantId
    && req.mcpMigPrincipalId === session.principalId
    && req.mcpMigAgentId === session.agentId
    && req.mcpVerifiedCredential?.credentialRef === session.credentialRef
    && (req.mcpLegacyCompatibility ||
      req.mcpMigLineage?.journeyId === session.journeyId &&
      req.mcpMigLineage?.parentCallId === session.parentCallId);
}

export function registerMcpRoutes(app: Express): void {
  const activeMcpTools = getActiveMcpTools();
  const mcpAuditSchemaReady = runAdamAuditColumnsMigration();
  // ── Startup migration: ensure ADAM audit columns exist ───────────────────

  // ── MCP protocol endpoint ────────────────────────────────────────────────
  // MCP is reachable only through an authenticated MIG MCP client.
  // Business webhook is a transport alias, not a second ingestion pipeline.
  // It speaks MCP JSON-RPC and inherits credential provisioning, revocation,
  // MIG delegation, per-tool policy, audit and BAL's durable retry journal.
  app.post("/api/mcp", requireMcpAuth, async (req: Request, res: Response) => {
    
    try {
      await mcpAuditSchemaReady;
    } catch {
      res.status(503).json({ error: "MCP_AUDIT_UNAVAILABLE" });
      return;
    }
    const transactionStartedAt = Date.now();
    const legacySessionId = typeof req.query.sessionId === "string" ? req.query.sessionId : undefined;
    const legacySession = legacySessionId ? legacyMcpSessions.get(legacySessionId) : undefined;
    if (legacySessionId) {
      if (!legacySession || legacySession.expiresAt <= Date.now()) {
        if (legacySession) await closeLegacyMcpSession(legacySessionId);
        res.status(404).json({ error: "MCP_LEGACY_SESSION_NOT_FOUND" });
        return;
      }
      if (!legacySessionMatches(req, legacySession)) {
        res.status(403).json({ error: "MCP_LEGACY_SESSION_IDENTITY_MISMATCH" });
        return;
      }
    }
    const responseChunks: Buffer[] = [];
    const captureChunk = (chunk: unknown) => {
      const buffer = normalizeMcpResponseChunk(chunk);
      if (buffer) responseChunks.push(buffer);
    };
    const originalWrite = res.write.bind(res);
    const originalEnd = res.end.bind(res);
    const redactCredentials = (value: unknown, depth = 0): unknown => {
      if (depth > 20 || value == null) return value;
      if (Array.isArray(value)) return value.map((item) => redactCredentials(item, depth + 1));
      if (typeof value !== "object") return value;
      const redacted: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
        redacted[key] = /(^|_)(api_?key|authorization|password|secret|token|credential|private_?key)($|_)/i.test(key)
          ? "[REDACTED]"
          : redactCredentials(item, depth + 1);
      }
      return redacted;
    };
    (res as any).write = (chunk: unknown, ...args: unknown[]) => {
      captureChunk(chunk);
      return (originalWrite as any)(chunk, ...args);
    };
    (res as any).end = (chunk?: unknown, ...args: unknown[]) => {
      captureChunk(chunk);
      return (originalEnd as any)(chunk, ...args);
    };

    const rpcBody = req.body && typeof req.body === "object" ? req.body as Record<string, any> : {};
    const rpcParams = rpcBody.params && typeof rpcBody.params === "object" ? rpcBody.params as Record<string, any> : {};
    const mcpMethod = typeof rpcBody.method === "string" ? rpcBody.method : "unknown";
    const requestId = typeof rpcBody.id === "string" || typeof rpcBody.id === "number"
      ? String(rpcBody.id)
      : `notification:${createHash("sha256").update(JSON.stringify(rpcBody)).digest("hex").slice(0, 24)}`;
    const toolName = typeof rpcParams.name === "string" ? rpcParams.name : undefined;
    const toolDefinition = toolName ? activeMcpTools.find(tool => tool.name === toolName) : undefined;
    // Compatibility clients do not supply MIG headers. Invalid business input
    // must not erase their target and masquerade as an authentication failure.
    // This is a negotiation response only: no tool or assessment is dispatched.
    const compatibilityInputProblem = (code: string, details: Record<string, unknown>) => {
      const problem = { code, accepted: false, assessment_executed: false, ...details };
      logConnectionAttempt({
        ts: new Date().toISOString(), ip: req.socket?.remoteAddress ?? "unknown",
        key_prefix_hint: "(none)", auth_ok: true, auth_error: null,
        http_status: 200, api_key_id: req.mcpApiKeyId, tenant_id: req.mcpTenantId,
        jsonrpc_method: mcpMethod, tool_name: toolName,
        response_body: problem, transaction_complete: true,
        auth_mechanism: "legacy_api_key", auth_stage: "admitted",
      });
      res.status(200).json({
        jsonrpc: "2.0", id: rpcBody.id ?? null,
        result: { isError: true, content: [{ type: "text", text: JSON.stringify(problem) }] },
      });
    };
    if (req.mcpLegacyCompatibility && req.mcpMigLineage && mcpMethod === "tools/call" && toolDefinition) {
      const parsed = toolDefinition.inputSchema.safeParse(rpcParams.arguments ?? {});
      if (!parsed.success) {
        compatibilityInputProblem("MCP_TOOL_ARGUMENTS_INVALID", {
          issues: parsed.error.issues.map(issue => ({ path: issue.path, code: issue.code })),
          next_action: "Correct the listed argument paths using the discovered tool schema, preserving the original source. Do not add MIG headers.",
        });
        return;
      }
    }
    const compatibilityTarget = req.mcpLegacyCompatibility ? canonicalToolTarget(req) : undefined;
    const compatibilityCatalog = req.mcpLegacyCompatibility ? buildBripeAuthorizationCatalog() : undefined;
    const compatibilityIntent = req.mcpMigLineage?.rootIntentId;
    const compatibilityDomain = compatibilityTarget?.domainIds[0] ??
      (compatibilityCatalog ? [...compatibilityCatalog.domains].sort()[0] : undefined);
    const compatibilityResource = compatibilityTarget?.resourceRefs[0] ??
      (mcpMethod === "tools/list" || toolDefinition?.classification === "read_only"
        ? `mcp:${toolName ?? "catalog"}:${req.mcpTenantId!}`
        : undefined);
    const intentId = req.mcpRemoteContext?.intentId ?? req.header("x-mig-intent-id") ??
      (req.mcpLegacyCompatibility ? compatibilityIntent : undefined);
    const domainId = req.mcpRemoteContext?.domainId ?? req.header("x-mig-domain-id") ??
      (req.mcpLegacyCompatibility
        ? compatibilityDomain
        : undefined);
    const resourceRef = req.mcpRemoteContext?.resourceRef ?? req.header("x-mig-resource-ref") ??
      (req.mcpLegacyCompatibility
        ? compatibilityResource
        : undefined);
    const resourceVersion = req.header("x-mig-resource-version") ?? undefined;
    let delegationToken: string | undefined;
    let migAllowedTools: string[] | undefined;
    let capabilityInventoryToolNames: string[] | undefined;
    let canonicalKnowledgeBinding: CanonicalMCPKnowledgeBinding | undefined;

    if (mcpMethod === "tools/list" || mcpMethod === "tools/call") {
      if (!req.mcpMigLineage) {
        res.status(403).json({
          error: "MIG_LINEAGE_REQUIRED",
          reason: "A successful server-owned MIG lineage anchor is required before tools may be disclosed or executed",
        });
        return;
      }
      if (!intentId || !domainId || !resourceRef) {
        if (req.mcpLegacyCompatibility && toolDefinition) {
          compatibilityInputProblem("MCP_AUTHORIZATION_TARGET_REQUIRED", {
            missing_context: [
              ...(!intentId ? ["intent"] : []), ...(!domainId ? ["domain"] : []),
              ...(!resourceRef ? ["resource"] : []),
            ],
            next_action: toolName === "run_bripe_decision"
              ? "For original JSON, confirm canonical_organization_id through organization_handshake using the exact source_system and source_account_id. For other modes supply the subject required by the discovered tool schema. Preserve the source and existing request references; do not invent IDs or add MIG headers."
              : "Supply the target required by the discovered tool schema. Preserve existing request references; do not invent IDs or add MIG headers.",
          });
          return;
        }
        res.status(403).json({ error: "MIG authorization context is required" });
        return;
      }
      let canonicalKnowledge: { resource: CanonicalKnowledgeResource; operation: NonNullable<CanonicalMCPKnowledgeBinding["operation"]> } | undefined;
      if (mcpMethod === "tools/call" && toolName === "read_persisted_csm_esp_result"
        && (!isCanonicalKnowledgeResourceRef(resourceRef) || !resourceVersion || domainId !== "CSM"
          || !req.mcpMigPrincipalId)) {
        res.status(403).json({ error: "MIG_CANONICAL_BINDING_UNRESOLVED" });
        return;
      }
      if (mcpMethod === "tools/call" && (isCanonicalKnowledgeResourceRef(resourceRef) || isProtectedCanonicalKnowledgeAlias(resourceRef))) {
        const resolved = await resolveProtectedMcpBinding({
          tenant_id: req.mcpTenantId!, mcp_server_id: req.mcpMigAgentId!,
          mcp_tool_name: toolName ?? "", resource_ref: resourceRef, resource_version: resourceVersion,
          evaluated_at: new Date().toISOString(),
        });
        if (!resolved) {
          res.status(403).json({ error: "MIG_CANONICAL_BINDING_UNRESOLVED" });
          return;
        }
        canonicalKnowledgeBinding = resolved.binding;
        if (toolName === "read_persisted_csm_esp_result"
          && (canonicalKnowledgeBinding.tenant_id !== req.mcpTenantId
            || canonicalKnowledgeBinding.partition !== "STRUCTURAL_READING"
            || canonicalKnowledgeBinding.knowledge_class !== "bripe_esp_result"
            || canonicalKnowledgeBinding.domain_id !== "CSM"
            || canonicalKnowledgeBinding.producer_domain !== "CSM"
            || canonicalKnowledgeBinding.operation !== "READ"
            || !canonicalKnowledgeBinding.canonical_object_id
            || !canonicalKnowledgeBinding.knowledge_id
            || canonicalKnowledgeBinding.resource_version !== resourceVersion
            || canonicalKnowledgeBinding.knowledge_id !== canonicalKnowledgeBinding.resource_version
            || canonicalKnowledgeBinding.mcp_tool_name !== toolName
            || canonicalKnowledgeBinding.intent_constraints.length === 0
            || !canonicalKnowledgeBinding.intent_constraints.includes(intentId))) {
          res.status(403).json({ error: "MIG_CANONICAL_BINDING_UNRESOLVED" });
          return;
        }
        canonicalKnowledge = {
          resource: resolved.resource,
          operation: canonicalKnowledgeBinding.operation!,
        };
      }
      const mig = await authorizeBripeMcpProtocolRequest({
        verifiedCredential: req.mcpVerifiedCredential!,
        classification: req.mcpKeyClassification!,
        allowedTools: req.mcpAllowedTools,
        allowedIntents: req.mcpAllowedIntents,
        method: mcpMethod,
        toolName,
        intentId,
        domainId,
        resourceRef,
        resourceVersion,
        requestId,
        clientId: req.mcpMigAgentId!,
        canonicalKnowledge,
        canonicalKnowledgeBinding,
      });
      if (!mig.allowed) {
        await recordMigAuditEvent({
          eventType: "execution", decision: "deny", tenantId: req.mcpTenantId!,
          agentId: req.mcpMigAgentId, authenticatedPrincipalId: req.mcpMigPrincipalId,
          journeyId: req.mcpMigLineage?.journeyId, parentCallId: req.mcpMigLineage?.parentCallId,
          originUserId: req.mcpMigLineage?.originUserId, originAgentId: req.mcpMigLineage?.originAgentId,
          rootIntentId: req.mcpMigLineage?.rootIntentId, compoundedIntentIds: req.mcpMigLineage?.compoundedIntentIds,
          graphCallIds: req.mcpMigLineage?.graphCallIds, intentId, toolName, capabilityId: undefined,
          resourceRef, policyDecision: "deny", reason: mig.reason,
        });
        res.status(403).json({
          error: "MIG_AUTHORIZATION_DENIED",
          reason: mig.reason,
          authorization_manifest_ids: mig.authorizationManifestIds,
        });
        return;
      }
      delegationToken = mig.delegationToken;
      migAllowedTools = mig.allowedToolNames;
      if (mcpMethod === "tools/call" && toolName &&
        ["list_capabilities", "search_capabilities", "get_capability_contract"].includes(toolName)) {
        const inventory = await authorizeBripeMcpProtocolRequest({
          verifiedCredential: req.mcpVerifiedCredential!,
          classification: req.mcpKeyClassification!,
          allowedTools: req.mcpAllowedTools,
          allowedIntents: req.mcpAllowedIntents,
          method: "tools/list",
          intentId,
          domainId,
          resourceRef,
          resourceVersion,
          requestId: `${requestId}:capability_inventory`,
          clientId: req.mcpMigAgentId!,
          canonicalKnowledge,
          canonicalKnowledgeBinding,
        });
        capabilityInventoryToolNames = inventory.allowed
          ? inventory.allowedToolNames
          : [];
      }
      await recordMigAuditEvent({
        eventType: "execution", decision: "allow", tenantId: req.mcpTenantId!,
        agentId: req.mcpMigAgentId, authenticatedPrincipalId: req.mcpMigPrincipalId,
        journeyId: req.mcpMigLineage?.journeyId, parentCallId: req.mcpMigLineage?.parentCallId,
        originUserId: req.mcpMigLineage?.originUserId, originAgentId: req.mcpMigLineage?.originAgentId,
        rootIntentId: req.mcpMigLineage?.rootIntentId,
        compoundedIntentIds: [...new Set([...(req.mcpMigLineage?.compoundedIntentIds ?? []), intentId])],
        graphCallIds: req.mcpMigLineage?.graphCallIds, intentId, toolName,
        resourceRef, manifestId: mig.authorizationManifestIds[0],
        policyDecision: "allow", reason: "mcp_proxy_authorized",
      });
      if (mcpMethod === "tools/list") {
        const consumed = await consumeMigDelegation(delegationToken, {
          tenantId: req.mcpTenantId!,
          requestId,
          mcpMethod,
          resourceRef,
          resourceVersion,
        });
        if (!consumed.valid) {
          res.status(403).json({ error: "MIG_DELEGATION_DENIED", reason: consumed.reason });
          return;
        }
      }
    }

    const ctx: McpServerContext = {
      tenantId: req.mcpTenantId!,
      principalId: req.mcpMigPrincipalId,
      apiKeyId: req.mcpApiKeyId,
      classification: req.mcpKeyClassification!,
      allowedTools: req.mcpAllowedTools,
      delegationToken,
      delegationExpectation: resourceRef ? {
        requestId,
        mcpMethod,
        resourceRef,
        resourceVersion,
        toolName,
      } : undefined,
      migAllowedTools,
      canonicalKnowledgeBinding: toolName === "read_persisted_csm_esp_result"
        ? canonicalKnowledgeBinding
        : undefined,
      capabilityInventoryToolNames,
      migAudit: {
        migClientId: req.mcpMigAgentId!,
        migPrincipalId: req.mcpMigPrincipalId!,
        ...req.mcpMigLineage!,
        currentIntentId: intentId,
        compoundedIntentIds: [...new Set([...(req.mcpMigLineage?.compoundedIntentIds ?? []), ...(intentId ? [intentId] : [])])],
        resourceRef,
        resourceVersion,
      },
    };
    const toolArguments = rpcParams.arguments && typeof rpcParams.arguments === "object"
      ? rpcParams.arguments as Record<string, unknown>
      : {};
    const requestedIntent = toolArguments.intent ?? toolArguments.operation ?? toolArguments.action ?? null;
    const ip = (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim()
      ?? req.socket?.remoteAddress
      ?? "unknown";

    res.once("finish", () => {
      const responseText = Buffer.concat(responseChunks).toString("utf8");
      const responseContentType = String(res.getHeader("content-type") ?? "");
      let responseBody: unknown = responseContentType.includes("text/event-stream")
        ? "[SSE_RESPONSE_BODY_OMITTED]"
        : responseText || null;
      if (!responseContentType.includes("text/event-stream")) {
        try {
          responseBody = responseText ? JSON.parse(responseText) : null;
        } catch {
          responseBody = "[NON_JSON_RESPONSE_BODY_OMITTED]";
        }
      }
      logConnectionAttempt({
        ts: new Date().toISOString(),
        ip,
        key_prefix_hint: req.header("x-mig-api-key")?.startsWith("mig_mcp_") ? "mig_mcp_" : "(none)",
        auth_ok: true,
        auth_error: null,
        http_status: res.statusCode,
        api_key_id: ctx.apiKeyId,
        tenant_id: ctx.tenantId,
        classification: ctx.classification,
        jsonrpc_method: typeof rpcBody.method === "string" ? rpcBody.method : null,
        request_id: typeof rpcBody.id === "string" || typeof rpcBody.id === "number" ? rpcBody.id : null,
        protocol_version: typeof rpcParams.protocolVersion === "string" ? rpcParams.protocolVersion : null,
        client_name: typeof rpcParams.clientInfo?.name === "string" ? rpcParams.clientInfo.name : null,
        client_version: typeof rpcParams.clientInfo?.version === "string" ? rpcParams.clientInfo.version : null,
        user_agent: req.header("user-agent") ?? null,
        tool_name: typeof rpcParams.name === "string" ? rpcParams.name : null,
        requested_intent: requestedIntent == null ? null : String(requestedIntent),
        params: redactCredentials(rpcParams),
        request_body: redactCredentials(rpcBody),
        response_body: redactCredentials(responseBody),
        duration_ms: Date.now() - transactionStartedAt,
        transaction_complete: true,
        auth_mechanism: req.mcpAuthAdapter === "entra_oidc" ? "bearer" : "mig_proxy",
        auth_stage: "admitted",
      });
    });

    // ── Contract Invocation Gate ─────────────────────────────────────────────
    // Checks the 17 constitutional conditions before any tool execution.
    // Operates in backward-compat mode: if the client has no active contract,
    // the gate passes transparently. If a contract exists, the envelope must be
    // valid and the signature must match the stored migAttestation.
    //
    // The envelope is expected as a top-level field "contractEnvelope" in the
    // JSON-RPC request body (alongside jsonrpc/method/params). The MCP transport
    // ignores unknown top-level fields, so this is forward-compatible.
    const contractEnvelope = (req.body as any)?.contractEnvelope ?? undefined;
    const contractMethod = (req.body as any)?.method ?? "unknown";
    const contractToolName = (req.body as any)?.params?.name ?? contractMethod;
    const gateCtx: ContractGateContext = {
      tenantId: ctx.tenantId,
      clientId: req.mcpMigAgentId!,
      toolName: contractToolName,
      // Derive capabilityId from the actual invoked tool — NOT from the envelope.
      // The envelope's capabilityId is client-supplied and untrustworthy for gate scoping.
      // toolName is derived from params.name (MCP tools/call) or method (discovery calls),
      // which maps 1:1 to capability_id in the registry.
      capabilityId: contractToolName,
    };
    try {
      await assertContractValid(contractEnvelope, storage as unknown as ContractGateRepository, gateCtx, getCapabilityContract);
    } catch (err) {
      if (err instanceof ContractGateError) {
        await recordFailedGateInvocation(contractEnvelope, storage as unknown as ContractGateRepository, gateCtx, err.code);
        res.status(403).json({ error: err.code, message: err.message });
        return;
      }
      throw err;
    }
    // ── End Contract Gate ────────────────────────────────────────────────────

    if (legacySession) {
      if (legacySession.messageInFlight) {
        res.status(409).json({ error: "MCP_LEGACY_SESSION_MESSAGE_IN_FLIGHT" });
        return;
      }
      legacySession.messageInFlight = true;
      const expectsJsonRpcResponse = rpcBody.jsonrpc === "2.0"
        && typeof rpcBody.method === "string"
        && (typeof rpcBody.id === "string" || typeof rpcBody.id === "number");
      legacySession.inFlightRequestId = expectsJsonRpcResponse
        ? rpcBody.id
        : undefined;
      Object.assign(legacySession.context, ctx);
      refreshBripeMcpServerTools(legacySession.server, legacySession.context);
      try {
        await legacySession.transport.handlePostMessage(req, res, req.body);
        if (!expectsJsonRpcResponse || res.statusCode >= 400) {
          legacySession.messageInFlight = false;
          legacySession.inFlightRequestId = undefined;
        }
      } catch (err) {
        legacySession.messageInFlight = false;
        legacySession.inFlightRequestId = undefined;
        console.error("[MCP] Legacy session message handling failed:", err);
        if (!res.headersSent) res.status(500).json({ error: "MCP legacy message handling failed" });
      }
      return;
    }

    const server = createBripeMcpServer(ctx);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

    res.on("close", () => {
      transport.close();
      server.close();
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("[MCP] Request handling failed:", err);
      if (!res.headersSent) {
        res.status(500).json({ error: "MCP request handling failed" });
      }
    }
  });

  app.get("/api/mcp", requireMcpAuth, async (req: Request, res: Response) => {
    if (req.mcpRemoteContext) {
      // Ordinary quick-config clients use stateless Streamable HTTP. No retained
      // SSE session can outlive revocation; every POST authenticates anew.
      res.setHeader("Allow", "POST");
      res.status(405).json({ error: "Use Streamable HTTP POST for remote clients." });
      return;
    }
    if (!req.mcpMigLineage) {
      res.status(403).json({ error: "MIG_LINEAGE_REQUIRED" });
      return;
    }
    const context: McpServerContext = {
      tenantId: req.mcpTenantId!,
      principalId: req.mcpMigPrincipalId,
      apiKeyId: req.mcpApiKeyId,
      classification: req.mcpKeyClassification!,
      allowedTools: req.mcpAllowedTools,
      migAudit: {
        migClientId: req.mcpMigAgentId!,
        migPrincipalId: req.mcpMigPrincipalId!,
        ...req.mcpMigLineage,
        compoundedIntentIds: req.mcpMigLineage.compoundedIntentIds,
      },
    };
    const transport = new SSEServerTransport("/api/mcp", res);
    const server = createBripeMcpServer(context);
    const sessionId = transport.sessionId;
    const session: LegacyMcpSession = {
      transport,
      server,
      context,
      tenantId: req.mcpTenantId!,
      principalId: req.mcpMigPrincipalId!,
      agentId: req.mcpMigAgentId!,
      credentialRef: req.mcpVerifiedCredential!.credentialRef,
      journeyId: req.mcpMigLineage.journeyId,
      parentCallId: req.mcpMigLineage.parentCallId,
      expiresAt: Date.now() + LEGACY_MCP_SESSION_TTL_MS,
      timer: undefined as unknown as NodeJS.Timeout,
      closing: false,
      messageInFlight: false,
      inFlightRequestId: undefined,
    };
    const originalSend = transport.send.bind(transport);
    transport.send = async (message) => {
      try {
        await originalSend(message);
      } finally {
        if ("id" in message && message.id === session.inFlightRequestId) {
          session.messageInFlight = false;
          session.inFlightRequestId = undefined;
        }
      }
    };
    session.timer = setTimeout(() => void closeLegacyMcpSession(sessionId), LEGACY_MCP_SESSION_TTL_MS);
    session.timer.unref?.();
    legacyMcpSessions.set(sessionId, session);
    res.once("close", () => void closeLegacyMcpSession(sessionId));
    try {
      await server.connect(transport);
    } catch (err) {
      await closeLegacyMcpSession(sessionId);
      console.error("[MCP] Legacy SSE session failed:", err);
      if (!res.headersSent) res.status(500).json({ error: "MCP legacy session failed" });
    }
  });

  app.delete("/api/mcp", requireMcpAuth, async (req: Request, res: Response) => {
    const sessionId = typeof req.query.sessionId === "string" ? req.query.sessionId : undefined;
    const session = sessionId ? legacyMcpSessions.get(sessionId) : undefined;
    if (!sessionId || !session || session.expiresAt <= Date.now()) {
      if (sessionId && session) await closeLegacyMcpSession(sessionId);
      res.status(404).json({ error: "MCP_LEGACY_SESSION_NOT_FOUND" });
      return;
    }
    if (!legacySessionMatches(req, session)) {
      res.status(403).json({ error: "MCP_LEGACY_SESSION_IDENTITY_MISMATCH" });
      return;
    }
    await closeLegacyMcpSession(sessionId);
    res.status(204).end();
  });

  // ── Admin: MCP API key management (verified internal admin session only) ──
  const presets = MCP_ACCESS_PRESETS;
  type EnterpriseInput = { principal: string; domains: string[]; intents: string[]; preset: keyof typeof presets; constraints: Record<string, unknown>; effectiveScopes: string[]; classification: McpKeyClassification; sodConflicts: string[] };
  const stringList = (value: unknown) => Array.isArray(value) ? [...new Set(value.filter((v): v is string => typeof v === "string" && v.trim().length > 0).map(v => v.trim()))] : [];
  const resolveEnterpriseInput = async (tenantId: string, body: any): Promise<EnterpriseInput | { error: string }> => {
    const principal = typeof (body?.canonicalPrincipal ?? body?.principal) === "string" ? (body.canonicalPrincipal ?? body.principal).trim() : "";
    const domains = stringList(body?.domains);
    const intents = stringList(body?.intents ?? body?.allowedIntents);
    const preset = (body?.access_preset ?? body?.accessPreset ?? "read_only") as keyof typeof presets;
    if (!principal || !domains.length || !intents.length || !(preset in presets)) return { error: "canonical principal, at least one domain, intent, and valid access preset are required" };
    const canonicalPrincipal = await storage.getMigPrincipal(tenantId, principal);
    if (!canonicalPrincipal || canonicalPrincipal.status !== "active") return { error: "canonical principal is unknown or inactive for tenant" };
    const definitions = await storage.listMigIntentDefinitions();
    const selected = definitions.filter(i => intents.includes(i.intentId) && i.status === "published");
    if (selected.length !== intents.length) return { error: "one or more intents are not published canonical intents" };
    const legitimateDomains = new Set(selected.flatMap(i => Array.isArray(i.domainScope) ? i.domainScope.filter((d): d is string => typeof d === "string") : []));
    if (!domains.every(domain => legitimateDomains.has("*") || legitimateDomains.has(domain))) return { error: "one or more domains are not permitted by selected canonical intents" };
    const constraints = body?.constraints && typeof body.constraints === "object" ? body.constraints as Record<string, unknown> : {};
    const customScopes = stringList(body?.accessScopes ?? body?.semanticScopes);
    const validScopes = new Set(["read", "analyze", "propose", "approve", "execute"]);
    if (preset === "custom" && (!customScopes.length || customScopes.some(scope => !validScopes.has(scope)))) {
      return { error: "custom preset requires one or more canonical access scopes" };
    }
    const requested = preset === "custom" ? customScopes : [...presets[preset]];
    const maxClassification: McpKeyClassification = requested.includes("approve") ? "admin" : requested.includes("analyze") ? "execution" : "read_only";
    const tools = activeMcpTools.filter(t => MCP_CLASSIFICATION_RANK[t.classification] <= MCP_CLASSIFICATION_RANK[maxClassification]).map(t => t.name);
    const highRisk = activeMcpTools.filter(t => tools.includes(t.name) && t.classification === "admin").map(t => t.name);
    const policy = await storage.getMigTenantAuthorizationPolicy(tenantId);
    const roles = (await storage.getActiveMigPrincipalEntitlement(tenantId, principal))?.assignedRoles;
    const assigned = new Set(Array.isArray(roles) ? roles.filter((r): r is string => typeof r === "string") : []);
    const conflicts = Array.isArray(policy?.staticSodConflicts) ? policy!.staticSodConflicts.filter((pair: any) => Array.isArray(pair) && assigned.has(pair[0]) && assigned.has(pair[1])).map((pair: any) => pair.join(" ↔ ")) : [];
    return { principal, domains, intents, preset, constraints, effectiveScopes: requested, classification: maxClassification, sodConflicts: conflicts };
  };
  const summarize = async (tenantId: string, input: EnterpriseInput) => {
    const max = input.classification;
    const exposed = activeMcpTools.filter(t => MCP_CLASSIFICATION_RANK[t.classification] <= MCP_CLASSIFICATION_RANK[max]);
    const [entitlementRow, tenantRow] = await Promise.all([
      storage.getActiveMigPrincipalEntitlement(tenantId, input.principal),
      storage.getMigTenantAuthorizationPolicy(tenantId),
    ]);
    const entitlement: MigEffectiveEntitlement | undefined = entitlementRow ? {
      capabilityIds: stringList(entitlementRow.capabilityIds),
      domainIds: stringList(entitlementRow.domainIds),
      intentIds: stringList(entitlementRow.intentIds),
      resourceScopes: stringList(entitlementRow.resourceScopes),
      assignedRoles: stringList(entitlementRow.assignedRoles),
    } : undefined;
    const tenantPolicy: MigTenantAuthorizationPolicy | undefined = tenantRow ? {
      status: tenantRow.status === "active" ? "active" : "suspended",
      capabilityIds: stringList(tenantRow.capabilityIds),
      domainIds: stringList(tenantRow.domainIds),
      intentIds: stringList(tenantRow.intentIds),
      resourceScopes: stringList(tenantRow.resourceScopes),
      allowedRiskZones: stringList(tenantRow.allowedRiskZones).filter((zone): zone is "low" | "medium" | "high" | "critical" => ["low", "medium", "high", "critical"].includes(zone)),
      allowedResourceStates: stringList(tenantRow.allowedResourceStates),
      staticSodConflicts: Array.isArray(tenantRow.staticSodConflicts) ? tenantRow.staticSodConflicts as Array<[string, string]> : [],
    } : undefined;
    const baseCatalog = buildBripeAuthorizationCatalog(input.intents);
    // Published intent definitions are canonical domain authorities too; make
    // their exact domain IDs visible to this no-write catalog evaluation.
    const catalog = { ...baseCatalog, domains: new Set([...baseCatalog.domains, ...input.domains]) };
    const constrainedResources = stringList(input.constraints.resources);
    const resourceRef = constrainedResources[0] ?? entitlement?.resourceScopes.find(scope => scope !== "*") ?? "preview:*";
    const actionAllowed = (action: string) =>
      action === "read" ? input.effectiveScopes.includes("read") :
      action === "execute" ? input.effectiveScopes.some(scope => scope === "analyze" || scope === "propose" || scope === "execute") :
      action === "administer" ? input.effectiveScopes.includes("approve") :
      false;
    const policyAllowed = exposed.filter(tool => {
      const mapping = getBripeToolAuthorizationEntry(tool.name);
      if (!mapping?.capability_id || !mapping.semantic_action || !actionAllowed(mapping.semantic_action)) return false;
      return input.domains.some(domainId => input.intents.some(intentId =>
        evaluateAuthorization({
          tenantId,
          intentId,
          capabilityId: mapping.capability_id,
          semanticAction: mapping.semantic_action as "read" | "execute" | "administer",
          domainId,
          resourceRef,
          credential: {
            credentialRef: "preview:no-write",
            credentialType: "api_key",
            principalId: input.principal,
            tenantId,
            principalType: "service",
            principalStatus: "active",
            credentialStatus: "active",
            credentialCapabilityCeiling: ["*"],
            credentialScopes: ["*"],
            credentialIntentCeiling: ["*"],
            credentialDomainCeiling: ["*"],
            credentialMcpTargetCeiling: ["*"],
            credentialResourceCeiling: ["*"],
          },
        }, entitlement, catalog, tenantPolicy).decision === "allow"
      ));
    });
    return {
      capabilities: Object.fromEntries(["read", "analyze", "propose", "approve", "execute"].map(p => [p, input.effectiveScopes.includes(p)])),
      ...Object.fromEntries(["read", "analyze", "propose", "approve", "execute"].map(p => [p, input.effectiveScopes.includes(p)])),
      exposed_tool_count: policyAllowed.length,
      high_risk_permissions: policyAllowed.filter(t => t.classification === "admin").map(t => t.name),
      allowed_tool_names: policyAllowed.map(tool => tool.name),
      effective_capabilities: [...new Set(policyAllowed.map(tool => getBripeToolAuthorizationEntry(tool.name)?.capability_id).filter((value): value is string => Boolean(value)))],
      evidence_ceiling: input.effectiveScopes.includes("approve") ? "approval_evidence_required" : "standard",
      sod_conflicts: input.sodConflicts,
      effective_scopes: input.effectiveScopes,
    };
  };
  // Keep the effective identity on the request so legacy route handlers cannot
  // accidentally treat a caller-supplied tenant/user header as authority.
  app.use("/api/mcp/admin", requireEnterpriseSchemaReady);
  app.use("/api/mcp/admin", async (req: Request, res: Response, next: NextFunction) => {
    const context = await requireEnterpriseAdminContext(req, res, {
      platformOnly: req.path.startsWith("/entra-mappings"),
    });
    if (!context) return;
    const canonicalTenants = await storage.getAllOrganizations();
    const canonicalTenant = canonicalTenants.find(org => org.id === context.tenantId && org.isActive);
    if (!canonicalTenant) {
      return void res.status(403).json({ error: "An active canonical tenant must be selected." });
    }
    req.headers["x-tenant-id"] = context.tenantId;
    req.headers["x-user-id"] = context.actorUserId;
    res.locals.enterpriseAdminContext = context;
    next();
  });

  app.get("/api/mcp/admin/tenants", async (req: Request, res: Response) => {
    const context = res.locals.enterpriseAdminContext;
    const orgs = await storage.getAllOrganizations();
    if (context.isPlatformAdmin) {
      res.json(orgs.filter(o => o.isActive).map(o => ({ id: o.id, name: o.name })));
      return;
    }
    const canonicalTenant = orgs.find(o => o.id === context.tenantId && o.isActive);
    res.json(canonicalTenant ? [{ id: canonicalTenant.id, name: canonicalTenant.name }] : []);
  });

  app.get("/api/mcp/admin/catalog", async (req: Request, res: Response) => {
    const tenantId = res.locals.enterpriseAdminContext.tenantId as string;
    const [principals, intents, policy] = await Promise.all([
      storage.listMigPrincipals(tenantId),
      storage.listMigIntentDefinitions(),
      storage.getMigTenantAuthorizationPolicy(tenantId),
    ]);
    const published = intents.filter(i => i.status === "published");
    const uniquePublished = [...new Map(
      published
        .sort((a, b) =>
          Number(b.libraryId === "bripe-core-v1") - Number(a.libraryId === "bripe-core-v1")
          || a.libraryId.localeCompare(b.libraryId)
          || a.intentId.localeCompare(b.intentId),
        )
        .map(intent => [intent.intentId, intent]),
    ).values()];
    const domains = [...new Set(uniquePublished.flatMap(i => Array.isArray(i.domainScope) ? i.domainScope.filter((d): d is string => typeof d === "string" && d !== "*") : []))];
    res.json({
      principals: principals.filter(p => p.status === "active").map(p => ({ id: p.principalId, display_name: p.displayName })),
      product_domains: domains,
      intents: uniquePublished.map(i => ({ id: i.intentId, display_name: i.name })),
      presets: Object.keys(presets).map(id => ({ id, semantic_scopes: presets[id as keyof typeof presets] })),
      semantic_scopes: ["read", "analyze", "propose", "approve", "execute"],
      tools: activeMcpTools.map(tool => {
        const mapping = getBripeToolAuthorizationEntry(tool.name);
        return { name: tool.name, capability_id: mapping?.capability_id, semantic_action: mapping?.semantic_action, risk: mapping?.risk_zone, classification: tool.classification };
      }),
      risk_zones: ["low", "medium", "high", "critical"],
      sod_conflicts: policy?.staticSodConflicts ?? [],
    });
  });

  app.post("/api/mcp/admin/keys/preview", async (req: Request, res: Response) => {
    const tenantId = res.locals.enterpriseAdminContext.tenantId as string;
    const resolved = await resolveEnterpriseInput(tenantId, req.body);
    if ("error" in resolved) return void res.status(400).json({ error: resolved.error });
    res.json(await summarize(tenantId, resolved));
  });

  app.post("/api/mcp/admin/keys", async (req: Request, res: Response) => {
    res.status(410).json({
      error: "MCP_API_KEY_ISSUANCE_RETIRED",
      message: "Direct MCP credentials are disabled. Register a MIG MCP client instead.",
    });
    return;
    /* istanbul ignore next -- retained temporarily for historical migration readability */
    const tenantId = res.locals.enterpriseAdminContext.tenantId as string;
    if (req.body?.tenantId && req.body.tenantId !== tenantId) {
      return void res.status(400).json({ error: "Selected tenant does not match the canonical authorized tenant." });
    }

    const { displayName, classification, allowedTools, clientType } = req.body ?? {};
    if (!displayName || typeof displayName !== "string") {
      res.status(400).json({ error: "displayName is required" });
      return;
    }
    if (clientType !== "llm" && clientType !== "mcp") {
      res.status(400).json({ error: "clientType must be llm or mcp" });
      return;
    }
    const resolvedEnterprise = await resolveEnterpriseInput(tenantId, req.body);
    if ("error" in resolvedEnterprise) {
      res.status(400).json({ error: (resolvedEnterprise as { error: string }).error });
      return;
    }
    const enterpriseInput = resolvedEnterprise as EnterpriseInput;
    if (enterpriseInput.sodConflicts.length > 0) {
      res.status(409).json({ error: "static_segregation_of_duties_conflict", sod_conflicts: enterpriseInput.sodConflicts });
      return;
    }
    // The enterprise preset is the authority ceiling. A caller cannot elevate
    // it through the legacy classification field.
    const cls: McpKeyClassification = enterpriseInput.classification;

    // Optional per-key tool allow-list: every entry must be a real tool name
    // whose own classification is at or below the key's ceiling. Empty/omitted
    // means "no restriction" (all tools at or below classification), which is
    // the backward-compatible default.
    let allowedToolsList: string[] | null = null;
    if (Array.isArray(allowedTools) && allowedTools.length > 0) {
      const validNames = new Set(activeMcpTools.map((t) => t.name));
      const invalid = allowedTools.filter((name: unknown) => typeof name !== "string" || !validNames.has(name));
      if (invalid.length > 0) {
        res.status(400).json({ error: `Unknown tool name(s) in allowedTools: ${invalid.join(", ")}` });
        return;
      }
      const overCeiling = activeMcpTools.filter(
        (t) => allowedTools.includes(t.name) && MCP_CLASSIFICATION_RANK[t.classification] > MCP_CLASSIFICATION_RANK[cls],
      );
      if (overCeiling.length > 0) {
        res.status(400).json({
          error: `allowedTools includes tool(s) above the key's "${cls}" classification: ${overCeiling.map((t) => t.name).join(", ")}`,
        });
        return;
      }
      allowedToolsList = Array.from(new Set(allowedTools as string[]));
    }

    const rawKey = `mcp_${randomBytes(24).toString("hex")}`;
    const keyHash = hashMcpApiKey(rawKey);
    const keyPrefix = rawKey.slice(0, 12);

    const effectiveAccess = await summarize(tenantId, enterpriseInput);
    if (effectiveAccess.exposed_tool_count === 0) {
      res.status(409).json({ error: "canonical_policy_resolves_no_effective_access" });
      return;
    }
    const record = await storage.createMcpApiKey(
      tenantId,
      displayName,
      keyHash,
      keyPrefix,
      cls,
      req.header("x-user-id") ?? undefined,
      allowedToolsList ?? effectiveAccess.allowed_tool_names,
      {
        principalId: enterpriseInput.principal,
        allowedDomains: enterpriseInput.domains,
        allowedIntents: enterpriseInput.intents,
        preset: enterpriseInput.preset,
        semanticScopes: enterpriseInput.effectiveScopes,
        effectiveScopes: effectiveAccess.effective_capabilities,
        resourceConstraints: { resources: stringList(enterpriseInput.constraints.resources) },
        environmentConstraints: { environment: enterpriseInput.constraints.environment ?? null },
        networkConstraints: { network: enterpriseInput.constraints.network ?? null },
        expiresAt: typeof enterpriseInput.constraints.expiresAt === "string"
          ? new Date(enterpriseInput.constraints.expiresAt as string)
          : null,
        reviewRequired: false,
        reviewState: "approved",
      },
    );

    // BRIPe MCP owns registration of newly issued MCP clients into MIG.
    // The MIG admin import flow remains only for credentials that pre-date
    // this server-owned registration path.
    const migAgentId = `mcp-client-${record.id}`;
    let migAgent = await storage.getMigAgentByAgentId(migAgentId);
    let ticketSecret: string | undefined;
    try {
      if (migAgent && migAgent!.tenantId !== tenantId) {
        throw new Error("MIG_CLIENT_ID_TENANT_COLLISION");
      }
      if (!migAgent) {
        const registered = await registerMigAgent({
          agentId: migAgentId,
          tenantId,
          displayName,
          agentType: clientType === "llm" ? "llm_client" : "external_mcp_client",
          principalId: enterpriseInput.principal,
          trustLevel: "standard",
          allowedIntentLibraries: ["bripe-core-v1"],
          allowedIntents: enterpriseInput.intents,
          allowedDomains: enterpriseInput.domains,
          allowedRiskZones: ["low"],
          maxCapabilityClassification: cls,
          requiresHumanApproval: false,
          lifecycleState: "discovery",
          createdBy: "system:bripe-mcp-registration",
        });
        migAgent = registered.agent;
        ticketSecret = registered.ticketSecret;
      }
      const bound = await storage.updateMcpApiKeyEnterprise(record.id, tenantId, { migAgentId });
      if (!bound || bound!.migAgentId !== migAgentId) throw new Error("MIG_CLIENT_BINDING_FAILED");
    } catch (error) {
      await storage.setMcpApiKeyStatus(record.id, tenantId, "disabled");
      await storage.recordMcpKeyAuditEvent({
        tenantId,
        apiKeyId: record.id,
        action: "disabled",
        actorUserId: req.header("x-user-id") ?? null,
        detail: "Disabled because BRIPe MCP could not register the client in MIG",
      });
      console.error("[MCP] MIG client registration failed:", error);
      res.status(500).json({ error: "MCP client could not be registered in MIG; issued credential was disabled" });
      return;
    }

    await storage.recordMcpKeyAuditEvent({
      tenantId,
      apiKeyId: record.id,
      action: "created",
      actorUserId: req.header("x-user-id") ?? null,
      detail: `Created "${displayName}" (${cls})`,
    });

    // The raw key is returned exactly once — it is never retrievable again.
    res.status(201).json({
      id: record.id,
      tenant_id: record.tenantId,
      display_name: record.displayName,
      client_type: clientType,
      classification: record.classification,
      principal_id: record.principalId,
      domains: record.allowedDomains ?? [],
      intents: record.allowedIntents ?? [],
      access_preset: record.preset,
      ...effectiveAccess,
      allowed_tools: record.allowedTools ?? null,
      key_prefix: record.keyPrefix,
      api_key: rawKey,
      mig_client: migAgent,
      mig_agent_id: migAgentId,
      ticket_secret: ticketSecret,
      created_at: record.createdAt,
    });
  });

  const keyView = (key: any) => ({
    id: key.id, tenant_id: key.tenantId, display_name: key.displayName,
    classification: key.classification, principal_id: key.principalId,
    mig_agent_id: key.migAgentId,
    domains: key.allowedDomains ?? [], intents: key.allowedIntents ?? [],
    allowed_tools: key.allowedTools ?? null, access_preset: key.preset,
    semantic_scopes: key.semanticScopes ?? [], effective_scopes: key.effectiveScopes ?? [],
    resource_constraints: key.resourceConstraints ?? {}, environment_constraints: key.environmentConstraints ?? {},
    network_constraints: key.networkConstraints ?? {}, status: key.status,
    review_required: key.reviewRequired, review_state: key.reviewState,
    expires_at: key.expiresAt, key_prefix: key.keyPrefix, created_at: key.createdAt,
    created_by: key.createdBy, last_used_at: key.lastUsedAt, revoked_at: key.revokedAt,
    rotated_from_id: key.rotatedFromId, rotated_to_id: key.rotatedToId,
  });

  app.get("/api/mcp/admin/keys/:id", async (req: Request, res: Response) => {
    const key = await storage.getMcpApiKeyById(Number(req.params.id), res.locals.enterpriseAdminContext.tenantId);
    if (!key) return void res.status(404).json({ error: "Key not found" });
    res.json({ ...keyView(key), effective_access: {
      read: Array.isArray(key.effectiveScopes) && key.effectiveScopes.includes("read"),
      analyze: Array.isArray(key.effectiveScopes) && key.effectiveScopes.includes("analyze"),
      propose: Array.isArray(key.effectiveScopes) && key.effectiveScopes.includes("propose"),
      approve: Array.isArray(key.effectiveScopes) && key.effectiveScopes.includes("approve"),
      execute: Array.isArray(key.effectiveScopes) && key.effectiveScopes.includes("execute"),
    } });
  });

  app.patch("/api/mcp/admin/keys/:id", async (req: Request, res: Response) => {
    const tenantId = res.locals.enterpriseAdminContext.tenantId as string;
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return void res.status(400).json({ error: "Invalid key id" });
    const current = await storage.getMcpApiKeyById(id, tenantId);
    if (!current) return void res.status(404).json({ error: "Key not found" });
    const merged = {
      ...req.body,
      canonicalPrincipal: req.body?.canonicalPrincipal ?? current.principalId,
      domains: req.body?.domains ?? current.allowedDomains,
      intents: req.body?.intents ?? current.allowedIntents,
      accessPreset: req.body?.accessPreset ?? req.body?.access_preset ?? current.preset,
      constraints: req.body?.constraints ?? {
        resources: (current.resourceConstraints as any)?.resources ?? [],
        environment: (current.environmentConstraints as any)?.environment ?? undefined,
        network: (current.networkConstraints as any)?.network ?? undefined,
        expiresAt: current.expiresAt?.toISOString(),
      },
    };
    const resolved = await resolveEnterpriseInput(tenantId, merged);
    if ("error" in resolved) return void res.status(400).json({ error: resolved.error });
    if (resolved.sodConflicts.length > 0) return void res.status(409).json({ error: "static_segregation_of_duties_conflict", sod_conflicts: resolved.sodConflicts });
    const effectiveAccess = await summarize(tenantId, resolved);
    if (effectiveAccess.exposed_tool_count === 0) return void res.status(409).json({ error: "canonical_policy_resolves_no_effective_access" });
    const updated = await storage.updateMcpApiKeyEnterprise(id, tenantId, {
      displayName: typeof req.body?.displayName === "string" ? req.body.displayName.trim() : current.displayName,
      principalId: resolved.principal, allowedDomains: resolved.domains, allowedIntents: resolved.intents,
      allowedTools: effectiveAccess.allowed_tool_names,
      preset: resolved.preset, semanticScopes: resolved.effectiveScopes, effectiveScopes: effectiveAccess.effective_capabilities,
      resourceConstraints: { resources: stringList(resolved.constraints.resources) },
      environmentConstraints: { environment: resolved.constraints.environment ?? null },
      networkConstraints: { network: resolved.constraints.network ?? null },
      expiresAt: typeof resolved.constraints.expiresAt === "string" ? new Date(resolved.constraints.expiresAt) : current.expiresAt,
    });
    await storage.recordMcpKeyAuditEvent({ tenantId, apiKeyId: id, action: "updated", actorUserId: res.locals.enterpriseAdminContext.actorUserId, detail: "Enterprise authorization scope updated" });
    res.json(keyView(updated));
  });

  for (const operation of ["disable", "enable", "expire"] as const) {
    app.post(`/api/mcp/admin/keys/:id/${operation}`, async (req: Request, res: Response) => {
      const tenantId = res.locals.enterpriseAdminContext.tenantId as string;
      const id = Number(req.params.id);
      if (!Number.isInteger(id)) return void res.status(400).json({ error: "Invalid key id" });
      const current = await storage.getMcpApiKeyById(id, tenantId);
      if (!current) return void res.status(404).json({ error: "Key not found" });
      if (current.status === "revoked" || current.status === "pending_revocation" || current.status === "review_required") {
        return void res.status(409).json({ error: `Key in ${current.status} state cannot transition to ${operation}` });
      }
      if (operation === "enable") {
        if (current.status !== "disabled") return void res.status(409).json({ error: "Only a disabled key can be enabled" });
        if (current.expiresAt && current.expiresAt.getTime() <= Date.now()) return void res.status(409).json({ error: "Expired key cannot be enabled" });
        const principal = current.principalId ? await storage.getMigPrincipal(tenantId, current.principalId) : undefined;
        if (!principal || principal.status !== "active") return void res.status(409).json({ error: "Canonical principal is not active" });
      }
      if (operation === "disable" && current.status !== "active") return void res.status(409).json({ error: "Only an active key can be disabled" });
      const status: import("@shared/schema").McpKeyStatus = operation === "disable" ? "disabled" : operation === "enable" ? "active" : "expired";
      const updated = await storage.setMcpApiKeyStatus(id, tenantId, status, operation === "expire" ? new Date() : operation === "enable" ? null : undefined);
      if (!updated) return void res.status(404).json({ error: "Key not found" });
      await storage.recordMcpKeyAuditEvent({ tenantId, apiKeyId: id, action: operation === "expire" ? "expired" : operation === "enable" ? "enabled" : "disabled", actorUserId: res.locals.enterpriseAdminContext.actorUserId, detail: `Key ${operation}d by administrator` });
      res.json(keyView(updated));
    });
  }

  // Idempotent authority-conserving upgrade for credentials created before
  // canonical principal binding. Ambiguous mappings are disabled for review.
  app.post("/api/mcp/admin/keys/legacy-migrate", async (_req: Request, res: Response) => {
    const context = res.locals.enterpriseAdminContext;
    if (!context.isPlatformAdmin) return void res.status(403).json({ error: "Platform administrator role required" });
    const keys = await storage.listMcpApiKeys(context.tenantId);
    let migrated = 0, flagged = 0;
    for (const key of keys) {
      if (key.reviewState === "legacy_scope_unproven") continue;
      const scopes = Array.isArray(key.effectiveScopes) ? key.effectiveScopes.filter((s): s is string => typeof s === "string") : [];
      const implied: McpKeyClassification = scopes.includes("approve") || scopes.includes("propose") ? "admin" : scopes.includes("analyze") ? "execution" : "read_only";
      const principal = key.principalId ? await storage.getMigPrincipal(key.tenantId, key.principalId) : undefined;
      if (!principal || MCP_CLASSIFICATION_RANK[implied] > MCP_CLASSIFICATION_RANK[key.classification as McpKeyClassification]) {
        await storage.updateMcpApiKeyEnterprise(key.id, key.tenantId, { reviewRequired: true, reviewState: "legacy_scope_unproven" });
        await storage.setMcpApiKeyStatus(key.id, key.tenantId, "review_required");
        await storage.recordMcpKeyAuditEvent({ tenantId: key.tenantId, apiKeyId: key.id, action: "legacy_flagged", actorUserId: context.actorUserId, detail: "Legacy authority cannot be proven subset of prior ceiling" });
        flagged++;
      } else {
        await storage.updateMcpApiKeyEnterprise(key.id, key.tenantId, { reviewRequired: false, reviewState: "approved" });
        await storage.recordMcpKeyAuditEvent({ tenantId: key.tenantId, apiKeyId: key.id, action: "legacy_migrated", actorUserId: context.actorUserId, detail: "Authority-conservation proof passed" });
        migrated++;
      }
    }
    res.json({ tenant_id: context.tenantId, migrated, flagged });
  });

  // ── Admin: rotate a key with a grace-period cutover ──────────────────────

  app.post("/api/mcp/admin/keys/:id/rotate", async (req: Request, res: Response) => {
    res.status(410).json({
      error: "MCP_API_KEY_ROTATION_RETIRED",
      message: "Direct MCP credentials are disabled. Rotate the MIG MCP client credential instead.",
    });
    return;
    /* istanbul ignore next -- retained temporarily for historical migration readability */
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) {
      res.status(400).json({ error: "Invalid key id" });
      return;
    }

    const existing = await storage.getMcpApiKeyById(id, tenantId!);
    if (!existing) {
      res.status(404).json({ error: "Key not found" });
      return;
    }
    if (existing!.status !== "active") {
      res.status(409).json({ error: `Key is "${existing!.status}" and cannot be rotated. Only active keys can be rotated.` });
      return;
    }

    const rawGraceDays = req.body?.gracePeriodDays;
    const gracePeriodDays = Number.isFinite(rawGraceDays) && rawGraceDays >= 0 && rawGraceDays <= 90
      ? Math.floor(rawGraceDays)
      : 7;

    const rawKey = `mcp_${randomBytes(24).toString("hex")}`;
    const keyHash = hashMcpApiKey(rawKey);
    const keyPrefix = rawKey.slice(0, 12);
    const actorUserId = req.header("x-user-id") ?? undefined;

    const result = await storage.rotateMcpApiKey(id, tenantId!, gracePeriodDays, keyHash, keyPrefix, actorUserId);
    if (!result) {
      res.status(409).json({ error: "Key could not be rotated (it may have changed status concurrently)." });
      return;
    }
    const { oldKey, newKey } = result!;

    await storage.recordMcpKeyAuditEvent({
      tenantId: tenantId!,
      apiKeyId: oldKey.id,
      action: "rotated_out",
      relatedKeyId: newKey.id,
      actorUserId: actorUserId ?? null,
      detail: `Rotated out; grace period ${gracePeriodDays}d, auto-revokes at ${oldKey.expiresAt?.toISOString()}`,
    });
    await storage.recordMcpKeyAuditEvent({
      tenantId: tenantId!,
      apiKeyId: newKey.id,
      action: "rotated_in",
      relatedKeyId: oldKey.id,
      actorUserId: actorUserId ?? null,
      detail: `Rotated in from key #${oldKey.id} ("${oldKey.displayName}")`,
    });

    // The raw key for the new credential is returned exactly once here — the
    // old key keeps working (unchanged) until its grace period expires.
    res.status(201).json({
      old_key: {
        id: oldKey.id,
        status: oldKey.status,
        expires_at: oldKey.expiresAt,
        rotated_to_id: oldKey.rotatedToId,
      },
      new_key: {
        id: newKey.id,
        tenant_id: newKey.tenantId,
        display_name: newKey.displayName,
        classification: newKey.classification,
        allowed_tools: newKey.allowedTools ?? null,
        allowed_intents: newKey.allowedIntents ?? null,
        key_prefix: newKey.keyPrefix,
        api_key: rawKey,
        created_at: newKey.createdAt,
        rotated_from_id: newKey.rotatedFromId,
      },
      grace_period_days: gracePeriodDays,
    });
  });

  // ── Admin: tool registry (for allow-list pickers in the UI) ──────────────

  app.get("/api/mcp/admin/tools", async (_req: Request, res: Response) => {
    // Build a reverse-lookup from tool name → capability group
    const capabilityGroupByTool = new Map<string, string>();
    for (const g of MCP_CAPABILITY_GROUPS) {
      for (const toolName of g.tools) {
        capabilityGroupByTool.set(toolName, g.group);
      }
    }
    res.json(
      activeMcpTools.map((t) => ({
        name: t.name,
        classification: t.classification,
        description: t.description,
        canonical_service: t.canonical_service,
        capability_group: capabilityGroupByTool.get(t.name) ?? null,
      })),
    );
  });

  // ── Admin: intent library (for intent pickers in the UI) ─────────────────

  app.get("/api/mcp/admin/intents", async (_req: Request, res: Response) => {
    const { listIntentDefinitions } = await import("../mig/mig-intent-library");
    const all = await listIntentDefinitions();
    const published = all
      .filter((d) => d.status === "published")
      .sort((a, b) =>
        Number(b.libraryId === "bripe-core-v1") - Number(a.libraryId === "bripe-core-v1")
        || a.libraryId.localeCompare(b.libraryId)
        || a.intentId.localeCompare(b.intentId),
      );
    // Intent IDs are the persisted canonical identity. Repeated seeding can
    // leave duplicate rows, but must not create duplicate picker options.
    const uniqueByIntentId = new Map<string, typeof published[number]>();
    for (const definition of published) {
      if (!uniqueByIntentId.has(definition.intentId)) {
        uniqueByIntentId.set(definition.intentId, definition);
      }
    }
    res.json([...uniqueByIntentId.values()].map((d) => ({
      option_key: `${d.libraryId}:${d.intentId}`,
      intent_id: d.intentId,
      library_id: d.libraryId,
      display_name: d.name,
      description: d.description,
      risk_zone: d.riskZone,
      status: d.status,
    })));
  });

  // ── Admin: per-key intent read/write ─────────────────────────────────────

  app.get("/api/mcp/admin/keys/:id/intents", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) { res.status(401).json({ error: "Missing X-Tenant-Id header" }); return; }
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid key id" }); return; }
    const key = await storage.getMcpApiKeyById(id, tenantId);
    if (!key) { res.status(404).json({ error: "Key not found" }); return; }
    res.json({ id: key.id, allowed_intents: key.allowedIntents ?? [] });
  });

  // Sets the per-key MIG intent allow-list on an mcp_api_keys record.
  //
  // Design note — intentional decoupling from mig_remote_agents:
  // mcp_api_keys.allowedIntents is the authoritative per-key restriction checked
  // at MCP API-key authentication time.  mig_remote_agents.allowedIntents governs
  // MIG ticket-based agent scope and is managed separately via /api/mig/admin/agents.
  // These two tables have no FK relationship; a single MIG agent may use multiple API
  // keys with different intent restrictions, and a key may exist independently of any
  // registered agent. Syncing them is therefore not meaningful here — admins control
  // key-level scope via this endpoint and agent-level scope via the MIG admin routes.
  app.put("/api/mcp/admin/keys/:id/intents", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) { res.status(401).json({ error: "Missing X-Tenant-Id header" }); return; }
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid key id" }); return; }

    const { allowedIntents } = req.body ?? {};
    if (!Array.isArray(allowedIntents)) {
      res.status(400).json({ error: "allowedIntents must be an array of intent ID strings" });
      return;
    }
    const invalid = allowedIntents.filter((x: unknown) => typeof x !== "string" || !x.trim());
    if (invalid.length > 0) {
      res.status(400).json({ error: "All entries in allowedIntents must be non-empty strings" });
      return;
    }

    const existing = await storage.getMcpApiKeyById(id, tenantId);
    if (!existing) { res.status(404).json({ error: "Key not found" }); return; }

    const intents: string[] = Array.from(new Set(allowedIntents.map((s: string) => s.trim())));
    if (intents.length === 0) {
      res.status(400).json({ error: "At least one published canonical intent is required" });
      return;
    }
    const resolved = await resolveEnterpriseInput(tenantId, {
      canonicalPrincipal: existing.principalId,
      domains: existing.allowedDomains,
      intents,
      accessPreset: existing.preset,
    });
    if ("error" in resolved) { res.status(400).json({ error: resolved.error }); return; }
    if (resolved.sodConflicts.length > 0) {
      res.status(409).json({ error: "static_segregation_of_duties_conflict", sod_conflicts: resolved.sodConflicts });
      return;
    }
    const updated = await storage.updateMcpApiKeyIntents(id, tenantId, resolved.intents);
    if (!updated) { res.status(404).json({ error: "Key not found or update failed" }); return; }

    await storage.recordMcpKeyAuditEvent({
      tenantId,
      apiKeyId: id,
      action: "intents_updated",
      actorUserId: req.header("x-user-id") ?? null,
      detail: intents.length > 0
        ? `Approved intents set to: ${intents.join(", ")}`
        : "Approved intents cleared (no restrictions)",
    });

    res.json({ id: updated.id, allowed_intents: updated.allowedIntents ?? [] });
  });

  app.get("/api/mcp/admin/keys", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const keys = await storage.listMcpApiKeys(tenantId);
    res.json(keys.map(keyView));
  });

  app.delete("/api/mcp/admin/keys/:id", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) {
      res.status(400).json({ error: "Invalid key id" });
      return;
    }
    const revoked = await storage.revokeMcpApiKey(id, tenantId);
    if (!revoked) {
      res.status(404).json({ error: "Key not found" });
      return;
    }
    await storage.recordMcpKeyAuditEvent({
      tenantId,
      apiKeyId: revoked.id,
      action: "revoked",
      actorUserId: req.header("x-user-id") ?? null,
      detail: `Revoked "${revoked.displayName}"`,
    });
    res.json({ id: revoked.id, status: revoked.status });
  });

  // ── Admin: audit trail read-back ──────────────────────────────────────────
  //
  // Tenant resolution order:
  // 1. If ?keyId=N is provided, resolve the tenant from that key's own record
  //    (so the UI can just pass the selected key id without knowing its tenant).
  // 2. Tenant scope always comes from the verified enterprise admin context.
  //    all invocations across all tenants (for cross-tenant admin views).
  // 3. Otherwise filter strictly by the tenant header.

  app.get("/api/mcp/admin/audit", async (req: Request, res: Response) => {
    const headerTenantId = req.header("x-tenant-id");
    if (!headerTenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 200;
    const safeLimit = isNaN(limit) ? 200 : limit;

    // Optional ADAM gate outcome filter — restricts rows to a specific gate verdict.
    // Valid values: AUTHORIZED | QUALIFIED | HUMAN_REVIEW_REQUIRED | BLOCKED
    const adamOutcome = req.query.outcome ? String(req.query.outcome) : null;

    // A specific key must still belong to the effective admin tenant.  Never
    // resolve a tenant from an unscoped key ID.
    const rawKeyId = req.query.keyId ? parseInt(String(req.query.keyId), 10) : null;
    if (rawKeyId !== null && !isNaN(rawKeyId)) {
      const key = await storage.getMcpApiKeyById(rawKeyId, headerTenantId);
      if (key) {
        const invocations = await storage.listMcpToolInvocations(key.tenantId, safeLimit, adamOutcome, key.id);
        res.json(invocations);
        return;
      }
      // Key not found at all — fall through to tenant-based query
    }

    const invocations = await storage.listMcpToolInvocations(headerTenantId, safeLimit, adamOutcome);
    res.json(invocations);
  });

  // ── Admin: full BRIPe output manifest — complete GDP JSON per execution ───────

  app.get("/api/mcp/admin/manifest", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const rawLimit = req.query.limit ? parseInt(String(req.query.limit), 10) : 100;
    const limit = isNaN(rawLimit) ? 100 : Math.min(rawLimit, 500);
    const toolName = req.query.tool ? String(req.query.tool) : "run_bripe_decision";
    const status = req.query.status ? String(req.query.status) : undefined;
    const rows = await storage.getMcpBripeOutputManifest({ tenantId, limit, toolName, status });
    res.json(rows);
  });

  // ── Admin: key lifecycle audit trail (created/revoked/rotated/auto_revoked) ─

  app.get("/api/mcp/admin/key-audit", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    // Opportunistic sweep so a slow/unvisited key-audit tab still reflects
    // grace periods that have already elapsed, without needing a cron job.
    await storage.sweepExpiredMcpApiKeys().catch((err) => {
      console.warn("[MCP] sweepExpiredMcpApiKeys failed:", err);
    });
    const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 200;
    const safeLimit = isNaN(limit) ? 200 : limit;
    const events = await storage.listMcpKeyAuditLog(tenantId, safeLimit);
    res.json(events);
  });

  // ── Admin: troubleshooting findings ring buffer ──────────────────────────────
  app.get("/api/mcp/admin/ts-findings", (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const limit = Math.min(Number(req.query.limit ?? 20), 100);
    const entries = readTsFindings(isNaN(limit) ? 20 : limit);
    res.json({ count: entries.length, entries });
  });

  // ── Admin: last-calls ring buffer (instant JSON access, no auth beyond tenant header) ──
  app.get("/api/mcp/admin/last-calls", (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const limit = Math.min(Number(req.query.limit ?? 20), 50);
    const entries = readMcpCallLog(isNaN(limit) ? 20 : limit);
    res.json({ count: entries.length, entries });
  });

  // ── Admin: connection-attempt ring buffer ─────────────────────────────────
  // Records every POST /api/mcp attempt (auth successes AND failures) so
  // operators can diagnose failed connection attempts and missing/wrong keys.
  app.get("/api/mcp/admin/connection-log", (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const limit = Math.min(Number(req.query.limit ?? 50), 200);
    const entries = readConnectionLog(isNaN(limit) ? 50 : limit);
    res.json({ count: entries.length, entries });
  });

  // ── Admin: Entra ID tenant mapping CRUD ──────────────────────────────────
  // These routes manage the DB-backed entra_tenant_mappings table, which the
  // Entra JWT middleware checks first before falling back to BCENTRISK_TENANT_MAPPING.
  // Any write immediately invalidates the middleware's 1-minute cache so the
  // new mapping is live on the next MCP request.

  app.get("/api/mcp/admin/entra-mappings", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const rows = await storage.listEntraTenantMappings();
    res.json(rows.map((r) => ({
      id: r.id,
      entra_tenant_id: r.entraTenantId,
      bcentrisk_tenant_id: r.bcentriskTenantId,
      display_label: r.displayLabel ?? null,
      created_by: r.createdBy ?? null,
      created_at: r.createdAt,
      updated_at: r.updatedAt,
    })));
  });

  app.post("/api/mcp/admin/entra-mappings", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const { entra_tenant_id, bcentrisk_tenant_id, display_label } = req.body ?? {};
    if (!entra_tenant_id || typeof entra_tenant_id !== "string") {
      res.status(400).json({ error: "entra_tenant_id is required (the Azure AD / Entra tenant GUID)" });
      return;
    }
    if (!bcentrisk_tenant_id || typeof bcentrisk_tenant_id !== "string") {
      res.status(400).json({ error: "bcentrisk_tenant_id is required (the bCentRisk tenant slug)" });
      return;
    }
    const row = await storage.upsertEntraTenantMapping(
      entra_tenant_id.trim(),
      bcentrisk_tenant_id.trim(),
      display_label ? String(display_label).trim() : undefined,
      req.header("x-user-id") ?? undefined,
    );
    invalidateEntraTenantMappingCache();
    res.status(201).json({
      id: row.id,
      entra_tenant_id: row.entraTenantId,
      bcentrisk_tenant_id: row.bcentriskTenantId,
      display_label: row.displayLabel ?? null,
      created_at: row.createdAt,
      updated_at: row.updatedAt,
    });
  });

  app.delete("/api/mcp/admin/entra-mappings/:id", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    if (!tenantId) {
      res.status(401).json({ error: "Missing X-Tenant-Id header" });
      return;
    }
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) {
      res.status(400).json({ error: "Invalid mapping id" });
      return;
    }
    const deleted = await storage.deleteEntraTenantMapping(id);
    if (!deleted) {
      res.status(404).json({ error: "Mapping not found" });
      return;
    }
    invalidateEntraTenantMappingCache();
    res.json({ id, deleted: true });
  });

  console.log("[MCP] BRIPe MCP interface routes registered at /api/mcp (+ /api/mcp/admin/*)");

  // Best-effort periodic sweep so pending_revocation keys flip to revoked even
  // when nobody opens the admin UI. Auth-time expiry check (bripe-mcp-auth.ts)
  // is the fail-closed backstop regardless of this interval firing.
  setInterval(() => {
    storage.sweepExpiredMcpApiKeys().catch((err) => {
      console.warn("[MCP] periodic sweepExpiredMcpApiKeys failed:", err);
    });
  }, 60 * 60 * 1000).unref();
}
