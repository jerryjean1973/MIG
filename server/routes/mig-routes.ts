/**
 * server/routes/mig-routes.ts
 *
 * MIG (MCP Intent Gateway) HTTP surface:
 *   - Admin CRUD for remote agents, intent libraries, intent definitions
 *     (tenant-header auth — same convention as mcp-routes.ts admin endpoints)
 *   - Ticket issuance for a registered agent
 *   - External gateway endpoints (POST /api/mig/discover, /api/mig/execute)
 *     that a remote agent calls with its signed ticket instead of hitting
 *     /api/mcp directly
 *   - Manifest preview + audit log read endpoints for the admin UI
 *
 * Registered from server/index.ts AFTER registerRoutes(), same convention
 * as mcp-routes.ts.
 */

import type { Express, Request, Response, NextFunction } from "express";
import { randomUUID } from "node:crypto";
import { storage } from "../storage";
import {
  MIG_RISK_ZONES, MIG_TRUST_LEVELS,
  type MigRiskZone, type MigTrustLevel,
} from "@shared/schema";
import { registerMigAgent, listMigAgents, setMigAgentStatus, updateMigAgentScope } from "../mig/mig-agent-registry";
import {
  createIntentLibrary, publishIntentLibrary, listIntentLibraries,
  createIntentDefinition, listIntentDefinitions, deprecateIntentDefinition, activateIntentDefinition,
} from "../mig/mig-intent-library";
import { issueTicket, authorizeDiscovery, authorizeExecution, revokeTicket, resolveAndValidateTicket } from "../mig/mig-core";
import { listMigAuditEvents, listMigIntentTransitionApprovalEvents } from "../mig/mig-audit";
import { bripeToolCatalog, seedDefaultBripeIntentLibrary, BRIPE_CORE_INTENT_LIBRARY_ID } from "../mig/mig-bripe-adapter";
import { DEFAULT_TENANT_ID } from "../storage";
import { createMigContextualApproval } from "../mig/mig-structural-approval";
import { verifyInternalSession, requireEnterpriseAdminContext } from "../routes-shared";
import {
  runMS5Review,
  getLatestMS5Report,
  getMS5ReportHistory,
  getMS5Findings,
  acknowledgeMS5Finding,
} from "../mig/ms5/ms5-engine";
import {
  startDiscoveryMode, listDiscoveryEvents, synthesizeDraftProfile,
  getDraftProfile, listDraftProfiles, approveDraftProfile, rejectDraftProfile,
  listDriftEvents, resolveDriftEvent, requestMoreDiscovery, setDiscoveryException,
} from "../mig/mig-discovery";
import {
  assertAuthenticatedMcpCapability, authenticateMigClient, authorizeMigJourneyCall, preauthorizeMigJourneyCall, beginAuthenticatedMcpRuntimeCall, beginMigJourneyCall, buildMigJourneyAccessContext, issueGovernedMigJourneyIntentTransition, reconstructMigJourney, revokeGovernedMigJourneyIntentTransition,
  registerMigClient, revokeMigClient, sealMigCallOutcome, sealExternalMigCallOutcome,
} from "../mig/mig-client-lineage";
import { requireEnterpriseSchemaReady } from "../migrations/enterprise-schema-readiness";
import {
  classifyMigRegistryCandidate, createMigRegistryCandidate, discoverProximityCandidates,
  identifyMigRegistryCandidate, importRegistryCandidates, registerTrustedMigRegistryCandidate,
  revokeMigRegistryCandidate, scanApprovedNetworkCandidates, setMigRegistryValidationEvidence,
  suspendMigRegistryCandidate, transitionMigRegistryCandidate,
} from "../mig/mig-governed-registry";
import { selectPreauthorizedScopes } from "../mig/mig-registry-network";
import { discoverMigDnsServices, normalizeMigDnsZone, MIG_APPROVED_PUBLIC_DNS_ZONES } from "../mig/mig-dns-discovery";
import { decideMcpHandshakeElevation, performMcpHandshake } from "../mig/mig-mcp-handshake";
import { resolveMcpApiKey } from "../mcp/bripe-mcp-auth";
import { resolveTenantAuthority } from "../mig/mig-authority-provider";
import { hashPayload } from "../mig/mig-audit";
import type { MigJourneyEvaluationResult } from "../mig/mig-types";
import { ingestMigObservation, MIG_OBSERVATION_OPERATING_MODE, evaluateObservedJourneyCanonical, appendMigObservedCustomerOutcome } from "../mig/mig-observation";
import { canonicalKnowledgeAuthorityService } from "../standalone/knowledge-owner";
import { listRemoteMcpClients, provisionRemoteMcpClient, revokeRemoteMcpClient, remoteMcpReadiness, REMOTE_MCP_PRESETS } from "../mig/mig-remote-mcp-clients";
import { registerMigHostOperatorRoutes } from "./mig-host-operator-routes";
import { projectSimpleTools } from "../mig/mig-simple-connection";
import { registerMigSimpleConnectionRoutes } from "./mig-simple-connection-routes";

function requireTenant(req: Request, res: Response): string | undefined {
  const tenantId = res.locals.enterpriseAdminContext?.tenantId;
  if (!tenantId) {
    res.status(401).json({ error: "Authentication required" });
    return undefined;
  }
  return tenantId;
}

/**
 * requireTenant() only validates the header is present — it never checks
 * that the caller's tenant actually owns the :agentId/:draftId resource
 * being mutated. These helpers close that gap for every agent- and
 * draft-scoped admin route: a resource that exists but belongs to a
 * different tenant is treated identically to "not found" (never a 403) so
 * the response never discloses cross-tenant existence.
 */
async function loadOwnedAgent(agentId: string, tenantId: string, res: Response) {
  const agent = await storage.getMigAgentByAgentId(agentId);
  if (!agent || agent.tenantId !== tenantId) {
    res.status(404).json({ error: "Agent not found" });
    return undefined;
  }
  return agent;
}

async function loadOwnedDraft(draftId: string, tenantId: string, res: Response) {
  const draft = await getDraftProfile(draftId);
  if (!draft || draft.tenantId !== tenantId) {
    res.status(404).json({ error: "Draft not found" });
    return undefined;
  }
  return draft;
}

export function registerMigRoutes(app: Express): void {
  // This is a bounded edge replay throttle. Persisted candidate idempotency is
  // still the source of truth for retry safety across instances.
  const mcpRegistrationNonces = new Map<string, number>();
  app.post("/api/mig/mcp/registration-request", async (req: Request, res: Response) => {
    const body = req.body ?? {};
    const credential = await resolveMcpApiKey(req.header("x-api-key"));
    if (!credential.ok || !credential.canonicalPrincipalBound) {
      return void res.status(401).json({ error: "MCP_REGISTRATION_AUTHENTICATION_REQUIRED" });
    }
    const principal = await storage.getMigPrincipal(credential.tenantId, credential.principalId);
    if (!principal || principal.status !== "active") {
      return void res.status(401).json({ error: "MCP_REGISTRATION_ACTIVE_PRINCIPAL_REQUIRED" });
    }
    if (body.tenant_id !== undefined && body.tenant_id !== credential.tenantId) {
      return void res.status(403).json({ error: "MCP_REGISTRATION_TENANT_MISMATCH" });
    }
    const tenantId = credential.tenantId;
    const nonce = typeof body.nonce === "string" ? body.nonce : "";
    const expiresAt = Number(body.expires_at);
    const now = Date.now();
    for (const [used, expiry] of mcpRegistrationNonces) if (expiry <= now) mcpRegistrationNonces.delete(used);
    if (!tenantId || !/^[A-Za-z0-9._:-]{16,128}$/.test(nonce) || !Number.isFinite(expiresAt) ||
      expiresAt <= now || expiresAt > now + 10 * 60_000) {
      return void res.status(400).json({ error: "MCP_REGISTRATION_REQUEST_INVALID" });
    }
    const replayKey = `${tenantId}:${nonce}`;
    if (mcpRegistrationNonces.has(replayKey)) return void res.status(409).json({ error: "MCP_REGISTRATION_REPLAYED" });
    if (mcpRegistrationNonces.size >= 10_000) return void res.status(429).json({ error: "MCP_REGISTRATION_RATE_LIMITED" });
    mcpRegistrationNonces.set(replayKey, expiresAt);
    try {
      const result: any = await performMcpHandshake({
        tenantId, actorId: `mcp-request:${nonce.slice(0, 12)}`, origin: "mcp_initiated",
        endpoint: body.endpoint, principalId: credential.principalId,
        requestedRiskZone: body.requested_risk_zone ?? "low",
        requestedTrust: body.requested_trust, capabilityCeiling: body.capability_ceiling,
        requestedScopes: body.requested_scopes, requestedIntents: body.requested_intents,
        requestedDomains: body.requested_domains, requestedMcpTargets: body.requested_mcp_targets,
        idempotencyKey: typeof body.idempotency_key === "string" ? body.idempotency_key : undefined,
      });
      // Never return trust material beyond the one-time credential exchange.
      res.status(result.idempotent ? 200 : 202).json({
        candidate_id: result.candidate.candidateId, status: result.candidate.state,
        trust_level: result.assignedTrust ?? "restricted", max_risk_zone: result.assignedRiskZone ?? "low",
      });
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.use(["/api/mig/admin", "/api/mig/security"], requireEnterpriseSchemaReady);
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    if (!req.path.startsWith("/api/mig/admin") && !req.path.startsWith("/api/mig/security")) return next();
    const context = await requireEnterpriseAdminContext(req, res);
    if (!context) return;
    req.headers["x-tenant-id"] = context.tenantId;
    req.headers["x-user-id"] = context.actorUserId;
    res.locals.enterpriseAdminContext = context;
    next();
  });
  registerMigHostOperatorRoutes(app);
  registerMigSimpleConnectionRoutes(app);
  // External telemetry is accepted only through the tenant-authenticated admin
  app.get("/api/mig/admin/remote-mcp-clients", async (_req: Request, res: Response) => {
    const context = res.locals.enterpriseAdminContext;
    res.setHeader("Cache-Control", "no-store");
    try {
      const clients = await listRemoteMcpClients(context.tenantId);
      let endpoint: string | null = null;
      let setupError: string | null = null;
      try { endpoint = (await remoteMcpReadiness(context.tenantId)).endpoint; }
      catch (error) { setupError = error instanceof Error ? error.message : "Remote MCP setup is unavailable."; }
      res.json({ clients, presets: REMOTE_MCP_PRESETS, endpoint, setupError });
    } catch { res.status(503).json({ error: "Remote MCP client list is unavailable." }); }
  });
  app.post("/api/mig/admin/remote-mcp-clients", async (req: Request, res: Response) => {
    const context = res.locals.enterpriseAdminContext;
    res.setHeader("Cache-Control", "no-store");
    try {
      res.status(201).json(await provisionRemoteMcpClient(context.tenantId, context.actorUserId, req.body));
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : "Remote MCP provisioning failed." });
    }
  });
  app.post("/api/mig/admin/remote-mcp-clients/:id/revoke", async (req: Request, res: Response) => {
    const context = res.locals.enterpriseAdminContext;
    res.setHeader("Cache-Control", "no-store");
    if (req.body?.confirmed !== true || Object.keys(req.body).some(key => key !== "confirmed")) {
      return void res.status(400).json({ error: "Confirm this client's revocation." });
    }
    try {
      const id = req.params.id;
      if (typeof id !== "string") return void res.status(400).json({ error: "A single client identity is required." });
      const revoked = await revokeRemoteMcpClient(context.tenantId, context.actorUserId, id);
      if (!revoked) return void res.status(404).json({ error: "Remote MCP client not found." });
      res.json({ revoked: true });
    } catch { res.status(503).json({ error: "Remote MCP revocation failed. Retry before assuming access is blocked." }); }
  });

  // External telemetry is accepted only through the tenant-authenticated admin
  // context.  This path intentionally has no adapter dispatch or execution.
  app.post("/api/mig/admin/observations/events", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    try {
      const result = await ingestMigObservation(tenantId, req.body);
      res.status(202).json({ observation_event_id: result.event.observationEventId,
        correlation_status: result.correlation_status, observed_journey_version_id: result.journey?.journeyVersionId ?? null,
        operating_mode: MIG_OBSERVATION_OPERATING_MODE });
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : "MIG_OBSERVATION_INGEST_FAILED" });
    }
  });
  app.get("/api/mig/admin/observations/journeys/:observedJourneyId", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    res.json({ operating_mode: MIG_OBSERVATION_OPERATING_MODE,
      ...(await storage.getMigObservationProjection(tenantId, req.params.observedJourneyId)) });
  });
  app.get("/api/mig/admin/observations", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    res.json(await storage.getMigObservationExperienceProjection(tenantId));
  });
  app.post("/api/mig/admin/observations/journeys/:observedJourneyId/feedback", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const version = await storage.getMigObservedJourneyVersion(tenantId, String(req.body?.journey_version_id ?? ""));
    if (!version || version.observedJourneyId !== req.params.observedJourneyId) {
      return void res.status(404).json({ error: "Observed journey version not found" });
    }
    const disposition = String(req.body?.disposition ?? "");
    const note = String(req.body?.note ?? "").trim();
    if (!["confirmed", "disputed", "needs_more_evidence"].includes(disposition) || note.length > 500) {
      return void res.status(400).json({ error: "MIG_OBSERVATION_FEEDBACK_INVALID" });
    }
    const outcomeId = `mig_obs_feedback_${randomUUID()}`;
    const row = await appendMigObservedCustomerOutcome({
      tenantId, outcomeId, journeyVersionId: version.journeyVersionId,
      outcome: JSON.stringify({ kind: "finding_feedback", disposition, note }),
      evidenceRefs: ((version.snapshot as any)?.event_refs ?? []),
    });
    res.status(201).json({ feedback_id: row.outcomeId, policy_changed: false, graph_changed: false });
  });
  app.post("/api/mig/admin/observations/journeys/:observedJourneyId/enforcement-readiness", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const version = await storage.getMigObservedJourneyVersion(tenantId, String(req.body?.journey_version_id ?? ""));
    if (!version || version.observedJourneyId !== req.params.observedJourneyId) {
      return void res.status(404).json({ error: "Observed journey version not found" });
    }
    if (req.body?.confirmed !== true) return void res.status(400).json({ error: "EXPLICIT_CONFIRMATION_REQUIRED" });
    const conditionRef = String(req.body?.condition_ref ?? "");
    const projection = await storage.getMigObservationProjection(tenantId, version.observedJourneyId) as any;
    const decision = (projection.decisions ?? []).find((item: any) =>
      item.journeyVersionId === version.journeyVersionId && item.observationStructuralDecisionId === conditionRef);
    const proof = (projection.proofs ?? []).find((item: any) => item.observationStructuralDecisionId === conditionRef);
    const finding = (projection.findings ?? []).find((item: any) => item.structuralDecisionRef === conditionRef);
    if (!decision || !proof || !finding) {
      return void res.status(400).json({ error: "ENFORCEMENT_READINESS_PROVEN_CONDITION_REQUIRED" });
    }
    const row = await appendMigObservedCustomerOutcome({
      tenantId, outcomeId: `mig_obs_readiness_${randomUUID()}`, journeyVersionId: version.journeyVersionId,
      outcome: JSON.stringify({ kind: "enforcement_readiness_selection",
        selected_condition: { condition_ref: decision.observationStructuralDecisionId, translated_state: decision.reason } }),
      evidenceRefs: ((version.snapshot as any)?.event_refs ?? []),
    });
    res.status(201).json({ selection_id: row.outcomeId, state: "ready_for_deliberate_policy_review",
      enforcement_enabled: false, policy_changed: false, graph_changed: false });
  });
  app.post("/api/mig/admin/observations/journeys/:observedJourneyId/evaluate", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    try {
      const result = await evaluateObservedJourneyCanonical({ tenantId,
        observedJourneyId: req.params.observedJourneyId,
        journeyVersionId: typeof req.body?.journey_version_id === "string" ? req.body.journey_version_id : "",
        canonicalRequest: req.body?.canonical_request });
      res.status(201).json(result);
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : "MIG_OBSERVATION_EVALUATION_FAILED",
        operating_mode: MIG_OBSERVATION_OPERATING_MODE });
    }
  });
  // ── Bootstrap ────────────────────────────────────────────────────────────

  app.get("/api/mig/admin/control-plane", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const stored = await storage.getMigTenantAuthorityConfig(tenantId);
    const config = stored ?? {
      configId: null, tenantId, version: null, deploymentMode: "full_control_plane",
      authorityProvider: "mig_native", executionFabric: "mig_managed",
      providerTenantRef: null, maximumSnapshotAgeSeconds: 300, status: "implicit_default",
      createdAt: null,
    };
    const [snapshots, policy, manifests, candidates, journeys] = await Promise.all([
      storage.listMigAuthoritySnapshots(tenantId, {
        limit: 250,
        provider: config.authorityProvider,
        providerTenantRef: config.providerTenantRef,
      }),
      storage.getMigTenantAuthorizationPolicy(tenantId),
      storage.listMigAuthorizationManifests({ tenantId, limit: 250 }),
      storage.listMigRegistryCandidates(tenantId, 1000),
      storage.listMigJourneys(tenantId, 250),
    ]);
    const latest = snapshots[0];
    const now = Date.now();
    const latestObservedAt = latest?.observedAt ? new Date(latest.observedAt).getTime() : undefined;
    const stale = latestObservedAt === undefined
      ? config.deploymentMode === "enterprise_intelligence_plane"
      : now - latestObservedAt > Number(config.maximumSnapshotAgeSeconds) * 1000;
    const providerState = config.deploymentMode === "full_control_plane"
      ? "not_applicable"
      : !config.providerTenantRef ? "incomplete"
      : !latest ? "disconnected"
      : new Date(latest.expiresAt).getTime() <= now ? "disconnected"
      : stale ? "stale"
      : latest.syncState;
    const mcpEstate = candidates.filter(candidate => candidate.clientClass === "MCP").map(candidate => {
      const target = (candidate.target ?? {}) as Record<string, any>;
      const enterpriseManaged = target.authority_provider === "microsoft_entra" ||
        target.ownership === "enterprise_managed" || target.registration_origin === "enterprise";
      return {
        component_id: candidate.componentId,
        identity: target.identity ?? target.display_name ?? candidate.componentId,
        ownership: enterpriseManaged ? "enterprise_managed" : "mig_managed",
        eligibility_source: target.eligibility_source ?? target.credential_authority?.source ??
          (enterpriseManaged ? "enterprise_authority" : candidate.entryAdapter),
        status: candidate.state,
        journey_usage: journeys.filter(journey => journey.originAgentId === candidate.componentId).length,
        governed_risk: target.assigned_risk_zone ?? target.max_risk_zone ?? "unknown",
      };
    });
    res.json({
      config,
      provider: {
        id: config.authorityProvider,
        display_name: config.authorityProvider === "microsoft_entra" ? "Microsoft Entra" : "MIG Native",
        tenant_ref: config.providerTenantRef,
        state: providerState,
        supported: ["mig_native", "microsoft_entra"].includes(config.authorityProvider),
      },
      sync: {
        state: providerState,
        last_observed_at: latest?.observedAt ?? null,
        expires_at: latest?.expiresAt ?? null,
        snapshots: snapshots.length,
        projected_principals: new Set(snapshots.map(snapshot => snapshot.principalId)).size,
        projected_capabilities: new Set(snapshots.flatMap(snapshot => snapshot.capabilityIds as string[])).size,
      },
      policy: {
        state: policy?.status ?? "incomplete",
        version: policy?.version ?? null,
        authorization_records: manifests.length,
        denied_records: manifests.filter(manifest => manifest.decision !== "allow").length,
      },
      estate: mcpEstate,
    });
  });

  app.post("/api/mig/admin/control-plane/mode", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const body = req.body ?? {};
    const enterprise = body.deployment_mode === "enterprise_intelligence_plane";
    if (!["full_control_plane", "enterprise_intelligence_plane"].includes(body.deployment_mode)) {
      return void res.status(400).json({ error: "MIG_DEPLOYMENT_MODE_INVALID" });
    }
    if (enterprise && (body.authority_provider !== "microsoft_entra" || typeof body.provider_tenant_ref !== "string" || !body.provider_tenant_ref.trim())) {
      return void res.status(400).json({ error: "Microsoft Entra tenant reference is required for Enterprise Intelligence Plane" });
    }
    if (!enterprise && body.authority_provider !== "mig_native") {
      return void res.status(400).json({ error: "Full Control Plane requires MIG-native authority" });
    }
    try {
      const row = await storage.createMigTenantAuthorityConfig({
        configId: `mig_authority_config_${randomUUID()}`,
        tenantId,
        version: `${Date.now()}-${randomUUID()}`,
        deploymentMode: body.deployment_mode,
        authorityProvider: body.authority_provider,
        executionFabric: enterprise ? (body.execution_fabric === "mig_managed" ? "mig_managed" : "enterprise_managed") : "mig_managed",
        providerTenantRef: enterprise ? body.provider_tenant_ref.trim() : null,
        maximumSnapshotAgeSeconds: Number.isInteger(body.maximum_snapshot_age_seconds) ? body.maximum_snapshot_age_seconds : 300,
        status: "active",
      });
      res.status(201).json(row);
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : "MIG_AUTHORITY_CONFIGURATION_FAILED" });
    }
  });

  app.get("/api/mig/admin/journeys", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const rows = await storage.listMigJourneys(tenantId, 250);
    const projections = await Promise.all(rows.map(async journey => {
      const reconstructed = await reconstructMigJourney(tenantId, journey.journeyId);
      const calls = reconstructed?.calls ?? [];
      const latest = calls[calls.length - 1];
      return {
        journey_id: journey.journeyId,
        origin_agent_id: journey.originAgentId,
        root_intent: journey.rootIntent,
        current_intent: latest?.currentIntent ?? journey.rootIntent,
        hop_count: calls.length,
        authorization_state: latest?.outcome?.outcome ?? "incomplete",
        temperature: latest?.outcome?.journeyState ?? "COOL",
        created_at: journey.createdAt,
      };
    }));
    res.json(projections);
  });

  app.post("/api/mig/admin/seed-defaults", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    await seedDefaultBripeIntentLibrary();
    res.json({ seeded: true, library_id: BRIPE_CORE_INTENT_LIBRARY_ID });
  });

  // ── Remote Agent Registry ────────────────────────────────────────────────

  app.post("/api/mig/admin/agents", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;

    const body = req.body ?? {};
    const mcpKeyId = Number(body.mcpKeyId);
    if (!Number.isInteger(mcpKeyId)) {
      res.status(400).json({ error: "mcpKeyId is required for an MCP client import" });
      return;
    }
    const sourceKey = await storage.getMcpApiKeyById(mcpKeyId, tenantId);
    if (!sourceKey || sourceKey.status !== "active") {
      res.status(404).json({ error: "Active tenant-owned MCP client credential not found" });
      return;
    }
    if (sourceKey.migAgentId) {
      res.status(409).json({ error: "MCP client is already registered in MIG" });
      return;
    }
    const agentId = `mcp-client-${sourceKey.id}`;
    const riskZones: MigRiskZone[] = Array.isArray(body.allowedRiskZones)
      ? body.allowedRiskZones.filter((z: string) => MIG_RISK_ZONES.includes(z as MigRiskZone))
      : ["low"];
    const trustLevel: MigTrustLevel = MIG_TRUST_LEVELS.includes(body.trustLevel) ? body.trustLevel : "standard";

    const { agent, ticketSecret } = await registerMigAgent({
      agentId,
      tenantId,
      displayName: sourceKey.displayName,
      agentType: body.clientType === "llm" ? "llm_client" : "external_mcp_client",
      principalId: sourceKey.principalId ?? undefined,
      trustLevel,
      allowedIntentLibraries: body.allowedIntentLibraries,
      allowedIntents: body.allowedIntents,
      allowedDomains: body.allowedDomains,
      allowedPackages: body.allowedPackages,
      allowedRiskZones: riskZones,
      maxCapabilityClassification: body.maxCapabilityClassification,
      requiresHumanApproval: body.requiresHumanApproval,
      createdBy: req.header("x-user-id") ?? undefined,
    });
    const bound = await storage.updateMcpApiKeyEnterprise(sourceKey.id, tenantId, { migAgentId: agent.agentId });
    if (!bound) {
      await setMigAgentStatus(agent.agentId, "suspended");
      res.status(500).json({ error: "MCP client import could not be bound to its credential" });
      return;
    }

    // ticket_secret returned exactly once, mirroring the mcp_api_keys raw-key convention.
    res.status(201).json({ agent, ticket_secret: ticketSecret });

    // Fire-and-forget MS5 review on new agent registration.
    runMS5Review({ tenantId, mcpServerId: "bripe-mcp-v1", triggeredBy: "registration" }).catch(err =>
      console.error("[MS5] registration-triggered review failed:", err)
    );
  });

  app.get("/api/mig/admin/agents", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    res.json(await listMigAgents(tenantId));
  });

  app.patch("/api/mig/admin/agents/:agentId", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedAgent(req.params.agentId, tenantId, res))) return;
    const updated = await updateMigAgentScope(req.params.agentId, req.body ?? {});
    if (!updated) {
      res.status(404).json({ error: "Agent not found" });
      return;
    }
    res.json(updated);

    // Fire-and-forget MS5 review on agent capability change.
    runMS5Review({ tenantId, mcpServerId: "bripe-mcp-v1", triggeredBy: "capability_change" }).catch(err =>
      console.error("[MS5] capability-change-triggered review failed:", err)
    );
  });

  app.post("/api/mig/admin/agents/:agentId/status", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedAgent(req.params.agentId, tenantId, res))) return;
    const { status } = req.body ?? {};
    if (!["active", "suspended", "revoked"].includes(status)) {
      res.status(400).json({ error: "status must be active|suspended|revoked" });
      return;
    }
    const updated = await setMigAgentStatus(req.params.agentId, status);
    if (!updated) {
      res.status(404).json({ error: "Agent not found" });
      return;
    }
    res.json(updated);
  });

  // ── Intent Libraries + Definitions ───────────────────────────────────────

  app.post("/api/mig/admin/intent-libraries", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const body = req.body ?? {};
    if (!body.libraryId || !body.name) {
      res.status(400).json({ error: "libraryId and name are required" });
      return;
    }
    const library = await createIntentLibrary({ libraryId: body.libraryId, name: body.name, version: body.version ?? "1.0.0", status: "draft" });
    res.status(201).json(library);
  });

  app.post("/api/mig/admin/intent-libraries/:libraryId/publish", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const library = await publishIntentLibrary(req.params.libraryId);
    if (!library) {
      res.status(404).json({ error: "Library not found" });
      return;
    }
    res.json(library);
  });

  app.get("/api/mig/admin/intent-libraries", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    res.json(await listIntentLibraries());
  });

  app.post("/api/mig/admin/intent-definitions", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const body = req.body ?? {};
    if (!body.intentId || !body.libraryId || !body.name) {
      res.status(400).json({ error: "intentId, libraryId and name are required" });
      return;
    }
    const intent = await createIntentDefinition({
      intentId: body.intentId,
      libraryId: body.libraryId,
      name: body.name,
      description: body.description ?? "",
      allowedCapabilityIds: body.allowedCapabilityIds ?? [],
      deniedCapabilityIds: body.deniedCapabilityIds ?? [],
      allowedToolNames: body.allowedToolNames ?? [],
      deniedToolNames: body.deniedToolNames ?? [],
      domainScope: body.domainScope ?? ["*"],
      packageScope: body.packageScope ?? ["*"],
      riskZone: MIG_RISK_ZONES.includes(body.riskZone) ? body.riskZone : "low",
      payloadClasses: body.payloadClasses ?? [],
      requiresHumanApproval: !!body.requiresHumanApproval,
      requiresEvidence: !!body.requiresEvidence,
      requiresManifest: body.requiresManifest !== false,
      status: "published",
    });
    res.status(201).json(intent);

    // Fire-and-forget MS5 review on new intent definition (capability governance change).
    runMS5Review({ tenantId, mcpServerId: "bripe-mcp-v1", triggeredBy: "capability_change" }).catch(err =>
      console.error("[MS5] intent-definition-triggered review failed:", err)
    );
  });

  app.get("/api/mig/admin/intent-definitions", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    res.json(await listIntentDefinitions(req.query.libraryId as string | undefined));
  });

  app.post("/api/mig/admin/intent-definitions/:intentId/deprecate", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const intent = await deprecateIntentDefinition(req.params.intentId);
    if (!intent) {
      res.status(404).json({ error: "Intent not found" });
      return;
    }
    res.json(intent);
  });

  app.post("/api/mig/admin/intent-definitions/:intentId/activate", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;

    // MS5 production-promotion gate (fail-closed):
    // CERTIFIED / CERTIFIED_WITH_WARNINGS → allow.
    // FAILED / BLOCKED / CONDITIONAL, no report yet, or gate evaluation error → 403.
    {
      let gateAllowed = false;
      let gateReason = "No MS5 certification report found. Run a security review before activating intent definitions.";
      let gateState: string = "UNCERTIFIED";
      try {
        const { getLatestMS5Report } = await import("../mig/ms5/ms5-engine");
        const { checkProductionPromotionGate } = await import("../mig/ms5/ms5-certification-engine");
        const latestReport = await getLatestMS5Report(tenantId);
        if (latestReport?.certification) {
          const gate = checkProductionPromotionGate(latestReport.certification);
          gateAllowed = gate.allowed;
          gateReason = gate.reason ?? "";
          gateState = gate.state;
        }
      } catch (gateErr: any) {
        gateReason = `Certification gate evaluation failed: ${gateErr?.message ?? "unknown error"}`;
      }
      if (!gateAllowed) {
        res.status(403).json({
          error: "production_promotion_blocked",
          certification_state: gateState,
          reason: gateReason,
        });
        return;
      }
    }

    const intent = await activateIntentDefinition(req.params.intentId);
    if (!intent) {
      res.status(404).json({ error: "Intent not found" });
      return;
    }
    res.json(intent);
  });

  // ── Ticket issuance (admin-initiated, on behalf of a registered agent) ───

  app.post("/api/mig/admin/tickets", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const { agentId, intentId, sessionId } = req.body ?? {};
    if (!agentId || !intentId) {
      res.status(400).json({ error: "agentId and intentId are required" });
      return;
    }
    const result = await issueTicket({ agentId, intentId, sessionId: sessionId ?? `sess_${Date.now()}` });
    if (result.decision !== "allow") {
      res.status(403).json({ error: result.reason });
      return;
    }
    res.status(201).json(result.data);
  });

  app.post("/api/mig/admin/approvals", async (req: Request, res: Response) => {
    const session = await verifyInternalSession(req).catch(() => null);
    if (!session) return void res.status(401).json({ error: "Authentication required" });
    const role = session.platformRole === "PLATFORM_ADMIN" ? session.platformRole : session.orgRole;
    if (!isMigApprovalAdminRole(role)) return void res.status(403).json({ error: "Approval administrator role required" });
    const tenantId = session.orgId;
    const approverId = session.userId;
    const body = req.body ?? {};
    if (!body.principal_id || !body.intent_id || !body.purpose || !body.path || !body.project_or_process || !body.valid_from || !body.expires_at || !Array.isArray(body.resource_refs)) {
      res.status(400).json({ error: "principal_id, intent_id, purpose, path, resource_refs, validity, and project_or_process are required" });
      return;
    }
    try {
      const approval = await createMigContextualApproval(tenantId, approverId, body, {
        role: role!, evidence: `internal_session:${session.userId}:${session.orgId}`,
      });
      res.status(201).json({ approval_id: approval.approval_id, expires_at: approval.expires_at });
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : "approval_creation_failed" });
    }
  });

  app.post("/api/mig/admin/tickets/:jti/revoke", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    await revokeTicket(req.params.jti, req.body?.reason ?? "admin_revoked");
    res.json({ revoked: true });
  });

  app.get("/api/mig/admin/tickets", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    res.json(await storage.listMigTickets(req.query.agentId as string | undefined));
  });

  // ── Audit log ─────────────────────────────────────────────────────────────

  app.get("/api/mig/admin/audit", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const events = await listMigAuditEvents({
      tenantId,
      agentId: req.query.agentId as string | undefined,
      limit: req.query.limit ? parseInt(req.query.limit as string, 10) : undefined,
    });
    res.json(events);
  });

  app.post("/api/mig/admin/clients", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const { component_id, origin_user_id } = req.body ?? {};
    const candidateId = req.body?.candidate_id ?? component_id;
    if (candidateId?.startsWith?.("mig_candidate_")) {
      try {
        const candidate = await storage.getMigRegistryCandidate(tenantId, candidateId);
        if (candidate?.clientClass === "MCP") {
          const target = candidate.target as any;
          const result = await performMcpHandshake({
            tenantId, actorId: res.locals.enterpriseAdminContext?.actorUserId ?? "admin",
            origin: "mig_initiated", endpoint: target.url ?? target.endpoint ?? target,
            principalId: candidate.principalId,
            requestedRiskZone: target.max_risk_zone ?? target.assigned_risk_zone ?? "low",
            requestedTrust: target.trust_level ?? target.assigned_trust ?? "restricted",
            capabilityCeiling: target.capabilities ?? [],
            idempotencyKey: `candidate-handshake:${candidate.candidateId}`,
          });
          return void res.status(result.idempotent ? 200 : 201).json({ client: result.client });
        }
        const result = await registerTrustedMigRegistryCandidate(tenantId, candidateId, res.locals.enterpriseAdminContext?.actorUserId ?? "admin", origin_user_id);
        return void res.status(result.idempotent ? 200 : 201).json({ client: result.client && { component_id: result.client.componentId, client_class: result.client.clientClass, status: result.client.status }, api_key: result.apiKey });
      } catch (err: any) { return void res.status(400).json({ error: err.message }); }
    }
    return void res.status(400).json({ error: "candidate_id is required; direct MIG client registration is not permitted" });
  });
  app.get("/api/mig/admin/clients", async (req, res) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const candidates = await storage.listMigRegistryCandidates(tenantId);
    // Registry projection intentionally excludes credential hashes and any ticket material.
    const clients = await Promise.all(candidates.filter(c => c.state === "registered" || c.state === "trusted" || c.state === "revoked").map(async c => {
      const active = await storage.getActiveMigClientByComponent(tenantId, c.componentId);
      const target = c.target as any;
      return {
        component_id: c.componentId, identity: target.identity ?? c.componentId,
        display_name: target.display_name ?? c.componentId, client_class: c.clientClass,
        status: active?.status ?? (c.state === "revoked" ? "revoked" : c.state),
        lifecycle_status: c.state, onboarding_method: c.entryAdapter,
        registration_origin: target.registration_origin ?? c.entryAdapter,
        handshake_status: target.handshake?.result ?? (c.clientClass === "MCP" ? "pending" : "not_applicable"),
        trust_level: target.assigned_trust ?? (c.state === "trusted" ? "trusted" : "restricted"),
        max_risk_zone: target.assigned_risk_zone ?? target.max_risk_zone ?? "low",
        // A safe credential projection: prefix/class/tenant and ceiling only.
        // Neither the hash nor any bearer material crosses this admin boundary.
        credential: active ? {
          masked: `${active.credentialPrefix}••••••••`,
          class: active.clientClass,
          tenant_id: active.tenantId,
          status: active.status,
          assigned_authority: target.credential_authority?.assigned,
        } : undefined,
        authority: target.credential_authority,
      };
    }));
    res.json(clients);
  });

  app.get("/api/mig/admin/journeys/:journeyId", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const journey = await reconstructMigJourney(tenantId, req.params.journeyId);
    if (!journey) return void res.status(404).json({ error: "Journey not found" });
    res.json(journey);
  });
  app.get("/api/mig/admin/journeys/:journeyId/intent-transition-attempts", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const limit = req.query.limit ? Number.parseInt(String(req.query.limit), 10) : undefined;
    const events = await listMigIntentTransitionApprovalEvents({
      tenantId,
      journeyId: req.params.journeyId,
      limit: Number.isFinite(limit) ? limit : undefined,
    });
    res.json(events);
  });
  app.post("/api/mig/admin/journeys/:journeyId/intent-transitions", async (req: Request, res: Response) => {
    const session = await verifyInternalSession(req).catch(() => null);
    if (!session) {
      return void res.status(401).json({ error: "Authentication required" });
    }
    const tenantId = res.locals.enterpriseAdminContext?.tenantId;
    if (!tenantId) return void res.status(401).json({ error: "Authentication required" });
    const body = req.body ?? {};
    if (!body.parent_call_id || !body.source_intent_id || !body.target_intent_id ||
        !body.authority_delta || !body.expires_at) {
      return void res.status(400).json({ error: "parent_call_id, source_intent_id, target_intent_id, authority_delta, and expires_at are required" });
    }
    try {
      const transition = await issueGovernedMigJourneyIntentTransition({
        tenantId,
        authenticatedUserId: session.userId,
        journeyId: req.params.journeyId,
        parentCallId: body.parent_call_id,
        sourceIntentId: body.source_intent_id,
        targetIntentId: body.target_intent_id,
        authorityDelta: body.authority_delta,
        expiresAt: new Date(body.expires_at),
      });
      res.status(201).json({
        transition_id: transition.transitionId,
        journey_id: transition.journeyId,
        parent_call_id: transition.parentCallId,
        source_intent_id: transition.sourceIntentId,
        target_intent_id: transition.targetIntentId,
        expires_at: transition.expiresAt,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "MIG_INTENT_TRANSITION_ISSUANCE_FAILED";
      const forbidden = message.includes("GOVERNOR") || message.includes("SOD") || message.includes("AUTHORITY");
      res.status(forbidden ? 403 : 400).json({ error: message });
    }
  });
  app.post("/api/mig/admin/journeys/:journeyId/intent-transitions/:transitionId/revoke", async (req: Request, res: Response) => {
    const session = await verifyInternalSession(req).catch(() => null);
    if (!session) return void res.status(401).json({ error: "Authentication required" });
    const tenantId = res.locals.enterpriseAdminContext?.tenantId;
    if (!tenantId) return void res.status(401).json({ error: "Authentication required" });
    try {
      const revocation = await revokeGovernedMigJourneyIntentTransition({
        tenantId, authenticatedUserId: session.userId,
        journeyId: req.params.journeyId, transitionId: req.params.transitionId,
        reason: req.body?.reason,
      });
      res.status(201).json({
        revocation_id: revocation.revocationId,
        transition_id: revocation.transitionId,
        journey_id: revocation.journeyId,
        revoked_at: revocation.createdAt,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "MIG_INTENT_TRANSITION_REVOCATION_FAILED";
      const forbidden = message.includes("GOVERNOR") || message.includes("SOD") || message.includes("AUTHORITY");
      res.status(forbidden ? 403 : 400).json({ error: message });
    }
  });

  app.post("/api/mig/admin/clients/:componentId/revoke", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const candidate = (await storage.listMigRegistryCandidates(tenantId, 1000)).find(row => row.componentId === req.params.componentId);
    const client = candidate
      ? await revokeMigRegistryCandidate(tenantId, candidate.candidateId, res.locals.enterpriseAdminContext?.actorUserId ?? "admin").then(() => ({ componentId: candidate.componentId }))
      : await revokeMigClient(tenantId, req.params.componentId);
    if (!client) return void res.status(404).json({ error: "Active MIG client not found" });
    res.json({ revoked: true, component_id: client.componentId });
  });

  // Governed registry: validation permits canonical registration and one-time
  // credential issuance; explicit trust activation remains a separate admin act.
  const registryAdmin = async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    return { tenantId, actorId: res.locals.enterpriseAdminContext?.actorUserId ?? "admin" };
  };
  const configuredNetworkScopes = async (tenantId: string): Promise<string[]> =>
    (await storage.listMcpApiKeys(tenantId))
      .filter(key => key.status === "active" && key.reviewState === "approved")
      .flatMap(key => {
        const network = (key.networkConstraints as any)?.network;
        return typeof network === "string" && network ? [network] : Array.isArray(network) ? network.filter((value): value is string => typeof value === "string") : [];
      });
  const resolveApprovedNetworkScopes = async (tenantId: string, requested: unknown): Promise<string[]> => {
    return selectPreauthorizedScopes(requested, await configuredNetworkScopes(tenantId));
  };
  const defaultDnsZone = async (tenantId: string) => {
    const organization = await storage.getOrganization(tenantId);
    const profile = organization?.profile as Record<string, unknown> | undefined;
    const configured = profile?.domain ?? profile?.websiteUrl ?? profile?.website;
    if (typeof configured === "string" && configured.trim()) {
      const host = configured.includes("://") ? new URL(configured).hostname : configured;
      return { zone: normalizeMigDnsZone(host), source: "organization" };
    }
    // A default lookup zone is never tenant membership or network authority.
    return { zone: "bcentrisk.com", source: "platform_default" };
  };
  app.get("/api/mig/admin/onboarding/dns-default", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try { res.json({ ...await defaultDnsZone(auth.tenantId), approved_public_zones: MIG_APPROVED_PUBLIC_DNS_ZONES }); }
    catch (error) { res.status(400).json({ error: error instanceof Error ? error.message : "Invalid organization DNS domain." }); }
  });
  app.post("/api/mig/admin/onboarding/discover-dns", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const zone = req.body?.zone || (await defaultDnsZone(auth.tenantId)).zone;
      res.json(await discoverMigDnsServices(zone, await configuredNetworkScopes(auth.tenantId)));
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : "DNS discovery failed." });
    }
  });
  app.post("/api/mig/admin/registry/candidates", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const body = req.body ?? {};
      const result = await createMigRegistryCandidate({
        ...auth, componentId: body.component_id, principalId: body.principal_id, clientClass: body.client_class,
        entryAdapter: body.entry_adapter, approvedScopes: body.approved_scopes, target: body.target,
        metadata: body.metadata,
        idempotencyKey: req.header("idempotency-key") ?? body.idempotency_key,
      });
      res.status(result.idempotent ? 200 : 201).json(result);
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/onboarding/manual", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const body = req.body ?? {};
      const result = await createMigRegistryCandidate({
        ...auth, componentId: body.component_id ?? body.identity, principalId: body.principal_id,
        clientClass: body.client_class, entryAdapter: "manual", approvedScopes: [],
        target: body.endpoint, idempotencyKey: req.header("idempotency-key") ?? body.idempotency_key,
        metadata: { display_name: body.identity, capabilities: body.capabilities ?? [], auth_hints: body.auth_hints ?? [],
          evidence: ["administrator_manual_entry"], trust_level: body.trust_level, max_risk_zone: body.max_risk_zone,
          validation: body.validation ?? {}, origin_user_id: body.origin_user_id },
      });
      res.status(result.idempotent ? 200 : 201).json(result);
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/mcp/connect-register", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const body = req.body ?? {};
      const result: any = await performMcpHandshake({
        ...auth, origin: "mig_initiated", endpoint: body.endpoint, componentId: body.component_id,
        principalId: body.principal_id, declaration: body.declaration,
        requestedRiskZone: body.max_risk_zone ?? "low", requestedTrust: body.trust_level,
        capabilityCeiling: body.capability_ceiling,
        requestedScopes: body.requested_scopes, requestedIntents: body.requested_intents,
        requestedDomains: body.requested_domains, requestedMcpTargets: body.requested_mcp_targets,
        idempotencyKey: req.header("idempotency-key") ?? body.idempotency_key,
      });
      res.status(result.idempotent ? 200 : 201).json({
        candidate: result.candidate, client: result.client && {
          component_id: result.client.componentId, client_class: result.client.clientClass, status: result.client.status,
        },
        endpoint: body.endpoint,
        identity: (result.candidate.target as any)?.display_name ?? result.candidate.componentId,
        capabilities: (result.candidate.target as any)?.capabilities ?? [],
        tools: projectSimpleTools((result.candidate.target as any)?.handshake?.probe?.toolDeclarations),
        capability_ids: [...new Set(projectSimpleTools((result.candidate.target as any)?.handshake?.probe?.toolDeclarations)
          .flatMap(tool => tool.capability_id ? [tool.capability_id] : []))],
        lineage_support: (result.candidate.target as any)?.handshake?.declaration?.supportsMigLineage === true,
        outcome_support: (result.candidate.target as any)?.handshake?.declaration?.supportsTerminalOutcomes === true,
        handshake_status: (result.candidate.target as any)?.handshake?.result ?? "compatible",
        assigned_risk_zone: result.assignedRiskZone, assigned_trust: result.assignedTrust,
        authority: (result.candidate.target as any)?.credential_authority, idempotent: result.idempotent,
      });
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/mcp/registrations/:candidateId/decision", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const body = req.body ?? {};
      res.json(await decideMcpHandshakeElevation({
        ...auth, candidateId: req.params.candidateId, decision: body.decision,
        riskZone: body.max_risk_zone, capabilityCeiling: body.capability_ceiling,
      }));
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.get("/api/mig/admin/mcp/registrations", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    const rows = await storage.listMigRegistryCandidates(auth.tenantId);
    res.json(rows.filter(row => row.clientClass === "MCP").map(row => {
      const target = row.target as Record<string, any>;
      return {
        candidate_id: row.candidateId, endpoint: target.url, component_id: row.componentId,
        identity: target.identity ?? row.componentId, mcp_name: target.display_name ?? row.componentId,
        origin: target.registration_origin, capabilities: target.capabilities ?? [],
        handshake_status: target.handshake?.result ?? "pending", handshake_result: target.handshake?.result ?? "pending",
        lineage_support: target.handshake?.declaration?.supportsMigLineage === true,
        outcome_support: target.handshake?.declaration?.supportsTerminalOutcomes === true,
        requested_ceiling: target.requested_risk_zone ?? "low", current_ceiling: target.assigned_risk_zone ?? "low",
        authority: target.credential_authority,
        lifecycle_status: row.state,
      };
    }));
  });
  app.get("/api/mig/admin/mcp/schema-access-alerts", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      res.json({ alerts: await canonicalKnowledgeAuthorityService.listMcpSchemaAccessAlerts(auth.tenantId) });
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/mcp/schema-access-alerts/:alertId/review", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const candidate = await canonicalKnowledgeAuthorityService.createMcpSchemaReviewCandidate({
        tenant_id: auth.tenantId,
        alert_id: req.params.alertId,
        actor_ref: auth.actorId,
      });
      res.status(201).json({
        candidate: {
          binding_id: candidate.binding_id,
          status: candidate.status,
          predecessor_binding_id: candidate.supersedes_binding_id,
          tenant_id: candidate.tenant_id,
          mcp_server_id: candidate.mcp_server_id,
          mcp_tool_name: candidate.mcp_tool_name,
          schema_version: candidate.mcp_schema_version,
          schema_fingerprint: candidate.schema_fingerprint,
        },
        authority_restored: false,
      });
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/onboarding/discover-nearby", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const raw = typeof req.body?.observations === "string" ? JSON.parse(req.body.observations) : req.body?.observations;
      const results = await discoverProximityCandidates({ ...auth, observations: raw });
      res.status(201).json({ candidates: results.map(result => result.candidate), candidate: results[0]?.candidate });
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/onboarding/scan-network", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const body = req.body ?? {};
      const target = body.target ?? body.endpoint;
      const endpoint = /^https?:\/\//.test(target ?? "") ? target : `http://${target}:${Number(body.port) || 80}/`;
      const approvedScopes = await resolveApprovedNetworkScopes(auth.tenantId, body.approved_scopes);
      const results = await scanApprovedNetworkCandidates({ ...auth, approvedScopes, targets: body.targets ?? [endpoint] });
      res.status(201).json({ candidates: results.map(result => result.candidate), candidate: results[0]?.candidate });
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/onboarding/import", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const body = req.body ?? {};
      const results = await importRegistryCandidates({ ...auth, registryUrl: body.registry_url ?? body.endpoint,
        approvedScopes: body.approved_scopes, authorization: typeof body.auth_value === "string" && body.auth_value ? body.auth_value : undefined });
      res.status(201).json({ candidates: results.map(result => result.candidate), candidate: results[0]?.candidate });
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.get("/api/mig/admin/onboarding/candidates", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    const rows = await storage.listMigRegistryCandidates(auth.tenantId);
    res.json(rows.map(row => {
      const target = row.target as any;
      return { candidate_id: row.candidateId, component_id: row.componentId,
        identity: target.identity ?? row.componentId, display_name: target.display_name ?? row.componentId,
        source: row.entryAdapter, endpoint: target.url, capabilities: target.capabilities ?? [], auth_hints: target.auth_hints ?? [],
        evidence: target.evidence ?? [], validation_evidence: target.validation_evidence ?? target.validation ?? {},
        origin_user_id: target.origin_user_id, trust_level: row.state === "trusted" ? "trusted" : "pending", max_risk_zone: target.max_risk_zone ?? "low",
        client_class: row.clientClass, status: row.state, onboarding_method: row.entryAdapter, principal_id: row.principalId,
        authority: target.credential_authority };
    }));
  });
  app.get("/api/mig/admin/registry", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 100));
    res.json(await storage.listMigRegistryCandidates(auth.tenantId, limit));
  });
  app.get("/api/mig/admin/registry/:candidateId", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    const candidate = await storage.getMigRegistryCandidate(auth.tenantId, req.params.candidateId);
    if (!candidate) return void res.status(404).json({ error: "Registry candidate not found" });
    res.json({ candidate, history: await storage.listMigRegistryHistory(auth.tenantId, candidate.candidateId) });
  });
  app.post("/api/mig/admin/registry/:candidateId/validate", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      if (req.body?.validation) await setMigRegistryValidationEvidence(auth.tenantId, req.params.candidateId, req.body.validation, auth.actorId);
      res.json(await transitionMigRegistryCandidate(auth.tenantId, req.params.candidateId, "validated", auth.actorId));
    }
    catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/registry/:candidateId/trust", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try { res.json(await transitionMigRegistryCandidate(auth.tenantId, req.params.candidateId, "trusted", auth.actorId)); }
    catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  for (const [action, state] of [["validate", "validated"], ["trust", "trusted"]] as const) {
    app.post(`/api/mig/admin/onboarding/candidates/:candidateId/${action}`, async (req, res) => {
      const auth = await registryAdmin(req, res); if (!auth) return;
      try {
        if (action === "validate" && req.body?.validation) await setMigRegistryValidationEvidence(auth.tenantId, req.params.candidateId, req.body.validation, auth.actorId);
        res.json(await transitionMigRegistryCandidate(auth.tenantId, req.params.candidateId, state, auth.actorId));
      }
      catch (err: any) { res.status(400).json({ error: err.message }); }
    });
  }
  app.post("/api/mig/admin/onboarding/candidates/:candidateId/identify", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try { res.json(await identifyMigRegistryCandidate(auth.tenantId, req.params.candidateId, req.body?.principal_id, auth.actorId)); }
    catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/onboarding/candidates/:candidateId/classify", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try { res.json(await classifyMigRegistryCandidate(auth.tenantId, req.params.candidateId, req.body?.client_class, auth.actorId)); }
    catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/onboarding/candidates/:candidateId/suspend", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try { res.json(await suspendMigRegistryCandidate(auth.tenantId, req.params.candidateId, auth.actorId)); }
    catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/registry/:candidateId/register", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try {
      const candidate = await storage.getMigRegistryCandidate(auth.tenantId, req.params.candidateId);
      if (candidate?.clientClass === "MCP") {
        const target = candidate.target as any;
        const result = await performMcpHandshake({
          ...auth, origin: "mig_initiated", endpoint: target.url ?? target.endpoint ?? target,
          principalId: candidate.principalId,
          requestedRiskZone: req.body?.max_risk_zone ?? target.max_risk_zone ?? "low",
          requestedTrust: req.body?.trust_level ?? target.trust_level ?? "restricted",
          capabilityCeiling: req.body?.capability_ceiling ?? target.capabilities ?? [],
          idempotencyKey: `candidate-handshake:${candidate.candidateId}`,
        });
        return void res.status(result.idempotent ? 200 : 201).json({ candidate: result.candidate, client: result.client });
      }
      const result = await registerTrustedMigRegistryCandidate(auth.tenantId, req.params.candidateId, auth.actorId, req.body?.origin_user_id);
      // api_key exists only in this response and is never recoverable from a list/detail endpoint.
      res.status(result.idempotent ? 200 : 201).json(result);
    } catch (err: any) { res.status(400).json({ error: err.message }); }
  });
  app.post("/api/mig/admin/registry/:candidateId/revoke", async (req, res) => {
    const auth = await registryAdmin(req, res); if (!auth) return;
    try { res.json(await revokeMigRegistryCandidate(auth.tenantId, req.params.candidateId, auth.actorId)); }
    catch (err: any) { res.status(400).json({ error: err.message }); }
  });

  // ── Discovery Mode & Intent Approval ─────────────────────────────────────

  app.post("/api/mig/admin/agents/:agentId/discovery/start", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedAgent(req.params.agentId, tenantId, res))) return;
    const agent = await startDiscoveryMode(req.params.agentId);
    if (!agent) {
      res.status(404).json({ error: "Agent not found" });
      return;
    }
    res.json(agent);
  });

  app.get("/api/mig/admin/agents/:agentId/discovery/events", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedAgent(req.params.agentId, tenantId, res))) return;
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : undefined;
    res.json(await listDiscoveryEvents(req.params.agentId, limit));
  });

  app.post("/api/mig/admin/agents/:agentId/discovery/generate-draft", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedAgent(req.params.agentId, tenantId, res))) return;
    try {
      const draft = await synthesizeDraftProfile(req.params.agentId);
      res.status(201).json(draft);
    } catch (err: any) {
      res.status(400).json({ error: err?.message ?? "failed_to_synthesize_draft" });
    }
  });

  app.get("/api/mig/admin/drafts", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const all = await listDraftProfiles(req.query.agentId as string | undefined);
    res.json(all.filter(d => d.tenantId === tenantId));
  });

  app.get("/api/mig/admin/drafts/:draftId", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const draft = await loadOwnedDraft(req.params.draftId, tenantId, res);
    if (!draft) return;
    res.json(draft);
  });

  app.post("/api/mig/admin/drafts/:draftId/approve", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedDraft(req.params.draftId, tenantId, res))) return;
    const body = req.body ?? {};
    try {
      const result = await approveDraftProfile({
        draftId: req.params.draftId,
        reviewedBy: req.header("x-user-id") ?? "admin",
        reviewNotes: body.reviewNotes,
        edits: body.edits,
      });
      res.json(result);
    } catch (err: any) {
      res.status(400).json({ error: err?.message ?? "failed_to_approve_draft" });
    }
  });

  app.post("/api/mig/admin/agents/:agentId/discovery/request-more", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedAgent(req.params.agentId, tenantId, res))) return;
    const agent = await requestMoreDiscovery(req.params.agentId);
    if (!agent) {
      res.status(404).json({ error: "Agent not found" });
      return;
    }
    res.json(agent);
  });

  app.post("/api/mig/admin/agents/:agentId/discovery/exception", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedAgent(req.params.agentId, tenantId, res))) return;
    const { granted } = req.body ?? {};
    if (typeof granted !== "boolean") {
      res.status(400).json({ error: "granted must be a boolean" });
      return;
    }
    const agent = await setDiscoveryException(req.params.agentId, granted);
    if (!agent) {
      res.status(404).json({ error: "Agent not found" });
      return;
    }
    res.json(agent);
  });

  app.post("/api/mig/admin/drafts/:draftId/reject", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    if (!(await loadOwnedDraft(req.params.draftId, tenantId, res))) return;
    try {
      const draft = await rejectDraftProfile(req.params.draftId, req.header("x-user-id") ?? "admin", req.body?.reviewNotes);
      res.json(draft);
    } catch (err: any) {
      res.status(400).json({ error: err?.message ?? "failed_to_reject_draft" });
    }
  });

  app.get("/api/mig/admin/drift-events", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const resolvedParam = req.query.resolved as string | undefined;
    res.json(await listDriftEvents({
      tenantId,
      agentId: req.query.agentId as string | undefined,
      resolved: resolvedParam === undefined ? undefined : resolvedParam === "true",
    }));
  });

  app.post("/api/mig/admin/drift-events/:eventId/resolve", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    // Ownership must be verified BEFORE mutating: fetch the tenant-scoped
    // event list first so a cross-tenant eventId never reaches resolveDriftEvent.
    const ownedEvents = await listDriftEvents({ tenantId });
    if (!ownedEvents.some(e => e.eventId === req.params.eventId)) {
      res.status(404).json({ error: "Drift event not found" });
      return;
    }
    const event = await resolveDriftEvent(req.params.eventId, req.header("x-user-id") ?? "admin");
    if (!event) {
      res.status(404).json({ error: "Drift event not found" });
      return;
    }
    res.json(event);
  });

  // ── External gateway: discovery + execution (ticket-bearer auth) ────────

  function extractBearerTicket(req: Request): string | undefined {
    const header = req.header("authorization");
    if (header?.startsWith("Bearer ")) return header.slice(7);
    return typeof req.body?.ticket === "string" ? req.body.ticket : undefined;
  }

  app.post("/api/mig/discover", async (req: Request, res: Response) => {
    const ticket = extractBearerTicket(req);
    if (!ticket) {
      res.status(401).json({ error: "Missing MIG ticket" });
      return;
    }
    const result = await authorizeDiscovery(ticket);
    if (result.decision !== "allow" || !result.data) {
      res.status(403).json({ error: result.reason, transition_proof_id: result.transition_proof_id });
      return;
    }
    res.json({
      manifest_id: result.data.manifest.manifestId,
      expires_at: result.data.manifest.expiresAt,
      tools: result.data.tools,
    });
  });

  app.post("/api/mig/execute", async (req: Request, res: Response) => {
    const ticket = extractBearerTicket(req);
    if (!ticket) {
      res.status(401).json({ error: "Missing MIG ticket" });
      return;
    }
    const apiKey = req.header("x-mig-api-key");
    const authenticatedClient = apiKey ? await authenticateMigClient(apiKey) : undefined;
    if (!authenticatedClient) {
      res.status(401).json({ error: "Valid full MIG client key required" });
      return;
    }
    const { tool_name, input, lineage } = req.body ?? {};
    if (!tool_name) {
      res.status(400).json({ error: "tool_name is required" });
      return;
    }
    if (authenticatedClient.clientClass === "MCP") {
      const capability = bripeToolCatalog().find(tool => tool.tool_name === tool_name)?.capability_id;
      try {
        await assertAuthenticatedMcpCapability(authenticatedClient, capability ?? "");
      } catch {
        return void res.status(403).json({ error: "mcp_capability_ceiling_denied" });
      }
    }

    const peekedTenant = req.header("x-tenant-id") ?? "default";
    if (peekedTenant !== authenticatedClient.tenantId) return void res.status(403).json({ error: "tenant_context_mismatch" });
    const ticketIdentity = await resolveAndValidateTicket(ticket);
    if (ticketIdentity.decision !== "allow" || !ticketIdentity.data) {
      return void res.status(403).json({ error: ticketIdentity.reason });
    }
    if (ticketIdentity.data.ticketRow.tenantId !== authenticatedClient.tenantId) {
      return void res.status(403).json({ error: "ticket_client_tenant_mismatch" });
    }
    if (authenticatedClient.clientClass === "AGENT" &&
        ticketIdentity.data.agent?.principalId !== authenticatedClient.principalId) {
      return void res.status(403).json({ error: "ticket_client_identity_mismatch" });
    }
    if (typeof lineage?.target_component_id !== "string" ||
        (authenticatedClient.clientClass === "MCP" && typeof lineage?.parent_call_id !== "string")) {
      return void res.status(400).json({ error: "server_lineage_anchor_required" });
    }
    let activeCall;
    try {
      const lineagePayload = input && typeof input === "object" && !Array.isArray(input)
        ? Object.fromEntries(Object.entries(input).filter(([key]) => key !== "structural_pdp"))
        : input ?? {};
      const currentIntentId = ticketIdentity.data.ticketRow.intentId;
      const currentIntent = ticketIdentity.data.intent?.name ?? currentIntentId;
      activeCall = authenticatedClient.clientClass === "MCP"
        ? await beginAuthenticatedMcpRuntimeCall(authenticatedClient, {
            parentCallId: lineage?.parent_call_id,
            currentIntentId,
            currentIntent,
            targetComponentId: lineage?.target_component_id,
            payload: lineagePayload,
          })
        : await beginMigJourneyCall(authenticatedClient, {
            rootIntentId: currentIntentId,
            rootIntent: currentIntent,
            currentIntentId,
            currentIntent,
            targetComponentId: lineage?.target_component_id,
            payload: lineagePayload,
          });
    } catch (error) {
      return void res.status(403).json({ error: error instanceof Error ? error.message : "MIG_LINEAGE_INVALID" });
    }
    const journeyAccessContext = await buildMigJourneyAccessContext({
      tenantId: authenticatedClient.tenantId, journey: activeCall.journey, currentCall: activeCall.call,
      requestCorrelationId: activeCall.call.callId,
    });
    let result;
    let journeyAdmissionOutcome: "allowed" | "denied" | undefined;
    let journeyPersistenceAttempted = false;
    try {
      result = await authorizeExecution(ticket, tool_name, input ?? {}, {
        tenantId: peekedTenant,
        requestCorrelationId: activeCall.call.callId,
        requestedMcpTargetId: activeCall.call.targetComponentId,
        journeyAccessContext,
        journeyPreauthorization: authority => preauthorizeMigJourneyCall(authenticatedClient, activeCall.journey, activeCall.call, authority as any),
        journeyAuthorization: async authority => {
          const decision = await authorizeMigJourneyCall(authenticatedClient, activeCall.journey, activeCall.call, {
            ...authority, targetComponentId: activeCall.call.targetComponentId,
          });
          journeyPersistenceAttempted = true;
          await sealMigCallOutcome({
            tenantId: authenticatedClient.tenantId, journeyId: activeCall.journey.journeyId, callId: activeCall.call.callId,
            outcome: decision.allowed ? "allowed" : "denied", reason: decision.reason,
            requestedAuthority: decision.requestedAuthority,
            effectiveAuthority: decision.allowed ? decision.effectiveAuthority : undefined,
            accumulatedState: decision.accumulatedState, structuralDecisionRef: authority.structuralDecisionRef,
            journeyState: decision.state, authorizationManifestId: authority.authorizationManifestId,
          });
          journeyAdmissionOutcome = decision.allowed ? "allowed" : "denied";
          return decision;
        },
      });
    } catch (error) {
      if (!journeyPersistenceAttempted) await sealMigCallOutcome({
        tenantId: authenticatedClient.tenantId, journeyId: activeCall.journey.journeyId,
        callId: activeCall.call.callId, outcome: journeyAdmissionOutcome === "allowed" ? "failed" : "denied", reason: "gateway_execution_failed",
        result: { error: error instanceof Error ? error.message : "unknown" },
      });
      throw error;
    }
    if (result.decision !== "allow") {
      if (journeyAdmissionOutcome !== "denied") await sealMigCallOutcome({
        tenantId: authenticatedClient.tenantId, journeyId: activeCall.journey.journeyId,
        callId: activeCall.call.callId, outcome: "denied", reason: result.reason,
        resultRef: result.transition_proof_id, authorizationManifestId: result.authorization_manifest_id,
      });
      res.status(403).json({ error: result.reason, transition_proof_id: result.transition_proof_id });
      return;
    }
    await sealMigCallOutcome({
      tenantId: authenticatedClient.tenantId, journeyId: activeCall.journey.journeyId,
      callId: activeCall.call.callId, outcome: "succeeded", reason: result.reason, result: result.data,
      authorizationManifestId: result.authorization_manifest_id,
    });
    res.json({ result: result.data, journey_id: activeCall.journey.journeyId, call_id: activeCall.call.callId });
  });

  /**
   * Enterprise-fabric policy enforcement point. The bearer token is verified
   * by the configured authority provider; request fields never supply tenant,
   * principal, role, scope, or authority. The canonical MIG execution spine is
   * run in decision-only mode and therefore cannot dispatch an MCP operation.
   */
  app.post("/api/mig/evaluate", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    const authorization = req.header("authorization") ?? "";
    const entraJwt = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
    const ticket = typeof req.body?.ticket === "string" ? req.body.ticket : undefined;
    const { tool_name, input, lineage } = req.body ?? {};
    if (!tenantId || !entraJwt || !ticket) {
      return void res.status(401).json({ error: "Verified enterprise authority and MIG ticket are required" });
    }
    if (typeof tool_name !== "string" || typeof lineage?.target_component_id !== "string") {
      return void res.status(400).json({ error: "tool_name and lineage.target_component_id are required" });
    }
    const verifiedCredential = await resolveTenantAuthority({ tenantId, entraJwt });
    if (!verifiedCredential || verifiedCredential.authorityProvider !== "microsoft_entra" ||
        !verifiedCredential.authorityRef) {
      return void res.status(403).json({ error: "external_authority_denied" });
    }
    const client = await storage.getActiveMigClientByPrincipal(tenantId, verifiedCredential.principalId);
    if (!client) return void res.status(403).json({ error: "canonical_participant_binding_required" });
    const ticketIdentity = await resolveAndValidateTicket(ticket);
    if (ticketIdentity.decision !== "allow" || !ticketIdentity.data ||
        ticketIdentity.data.ticketRow.tenantId !== tenantId) {
      return void res.status(403).json({ error: ticketIdentity.reason ?? "ticket_tenant_mismatch" });
    }
    if (ticketIdentity.data.agent?.principalId !== verifiedCredential.principalId) {
      return void res.status(403).json({ error: "ticket_authority_principal_mismatch" });
    }
    const payload = input && typeof input === "object" && !Array.isArray(input)
      ? Object.fromEntries(Object.entries(input).filter(([key]) => key !== "structural_pdp"))
      : input ?? {};
    let activeCall;
    try {
      const currentIntentId = ticketIdentity.data.ticketRow.intentId;
      const currentIntent = ticketIdentity.data.intent?.name ?? currentIntentId;
      activeCall = client.clientClass === "MCP"
        ? await beginAuthenticatedMcpRuntimeCall(client, {
            parentCallId: lineage?.parent_call_id,
            currentIntentId, currentIntent,
            targetComponentId: lineage.target_component_id, payload,
          })
        : await beginMigJourneyCall(client, {
            rootIntentId: currentIntentId, rootIntent: currentIntent,
            currentIntentId, currentIntent,
            targetComponentId: lineage.target_component_id, payload,
          });
    } catch (error) {
      return void res.status(403).json({ error: error instanceof Error ? error.message : "MIG_LINEAGE_INVALID" });
    }
    const journeyAccessContext = await buildMigJourneyAccessContext({
      tenantId, journey: activeCall.journey, currentCall: activeCall.call,
      requestCorrelationId: activeCall.call.callId,
    });
    let journeyState: MigJourneyEvaluationResult["journey_state"] = "COOL";
    let structuralDecisionRef: string | undefined;
    let journeyDenied = false;
    const result = await authorizeExecution(ticket, tool_name, input ?? {}, {
      tenantId,
      enterpriseAuthorization: {
        verifiedCredential,
        domainId: typeof req.body?.domain_id === "string" ? req.body.domain_id : "unknown",
        resourceRef: typeof req.body?.resource_ref === "string" ? req.body.resource_ref : `mig-journey:${activeCall.journey.journeyId}`,
        resourceVersion: typeof req.body?.resource_version === "string" ? req.body.resource_version : undefined,
        requestCorrelationId: activeCall.call.callId,
      },
      executionStrategy: "external_decision_only",
      requestedMcpTargetId: activeCall.call.targetComponentId,
      journeyAccessContext,
      journeyPreauthorization: authority => preauthorizeMigJourneyCall(client, activeCall.journey, activeCall.call, authority as any),
      journeyAuthorization: async authority => {
        structuralDecisionRef = authority.structuralDecisionRef;
        const decision = await authorizeMigJourneyCall(client, activeCall.journey, activeCall.call, {
          ...authority, targetComponentId: activeCall.call.targetComponentId,
        });
        journeyState = decision.state;
        journeyDenied = !decision.allowed;
        await sealMigCallOutcome({
          tenantId, journeyId: activeCall.journey.journeyId, callId: activeCall.call.callId,
          outcome: decision.allowed ? "allowed" : "denied", reason: decision.reason,
          requestedAuthority: {
            ...decision.requestedAuthority,
            deploymentMode: "enterprise_intelligence_plane",
            authorityProvider: verifiedCredential.authorityProvider,
            authorityRef: verifiedCredential.authorityRef,
            authoritySnapshotId: verifiedCredential.authoritySnapshotId,
            originAgentId: activeCall.journey.originAgentId,
            hop: activeCall.call.sequence,
            payloadHash: activeCall.call.inputHash,
            structuralExecution: authority.structuralExecution ? {
              ...authority.structuralExecution,
              structuralDecisionRef: authority.structuralDecisionRef,
              toolName: authority.toolName,
            } : undefined,
          },
          effectiveAuthority: decision.allowed ? decision.effectiveAuthority : undefined,
          accumulatedState: decision.accumulatedState,
          authorizationManifestId: authority.authorizationManifestId,
          structuralDecisionRef: authority.structuralDecisionRef,
          journeyState: decision.state,
        });
        return decision;
      },
    });
    if (result.decision !== "allow" || !result.authorization_manifest_id || journeyDenied) {
      if (!journeyDenied) await sealMigCallOutcome({
        tenantId, journeyId: activeCall.journey.journeyId, callId: activeCall.call.callId,
        outcome: "denied", reason: result.reason, authorizationManifestId: result.authorization_manifest_id,
        structuralDecisionRef,
      });
      const response: Partial<MigJourneyEvaluationResult> = {
        decision: "STOP", reason: result.reason, deployment_mode: "enterprise_intelligence_plane",
        journey_state: journeyState, journey_id: activeCall.journey.journeyId, call_id: activeCall.call.callId,
        authority: { provider: "microsoft_entra", reference: verifiedCredential.authorityRef,
          snapshot_id: verifiedCredential.authoritySnapshotId },
        decision_proof_ref: result.authorization_manifest_id ?? result.transition_proof_id ?? "unavailable",
        structural_decision_ref: structuralDecisionRef, payload_hash: hashPayload(payload),
      };
      return void res.status(200).json(response);
    }
    const evaluated = result.data as {
      decision: MigJourneyEvaluationResult["decision"];
      structural_decision_ref?: string;
      control_ref?: string;
    };
    const response: MigJourneyEvaluationResult = {
      decision: evaluated.decision, reason: result.reason, deployment_mode: "enterprise_intelligence_plane",
      journey_state: journeyState, journey_id: activeCall.journey.journeyId, call_id: activeCall.call.callId,
      authority: { provider: "microsoft_entra", reference: verifiedCredential.authorityRef,
        snapshot_id: verifiedCredential.authoritySnapshotId },
      decision_proof_ref: result.authorization_manifest_id,
      structural_decision_ref: evaluated.structural_decision_ref, payload_hash: hashPayload(payload),
      control_ref: evaluated.control_ref,
    };
    res.json(response);
  });

  app.post("/api/mig/evaluate/:journeyId/:callId/outcome", async (req: Request, res: Response) => {
    const tenantId = req.header("x-tenant-id");
    const authorization = req.header("authorization") ?? "";
    const entraJwt = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
    if (!tenantId || !entraJwt) return void res.status(401).json({ error: "Verified enterprise authority is required" });
    const verified = await resolveTenantAuthority({ tenantId, entraJwt });
    if (!verified || verified.authorityProvider !== "microsoft_entra") {
      return void res.status(403).json({ error: "external_authority_denied" });
    }
    const outcome = req.body?.outcome;
    if (outcome !== "succeeded" && outcome !== "failed") {
      return void res.status(400).json({ error: "outcome must be succeeded or failed" });
    }
    try {
      const sealed = await sealExternalMigCallOutcome({
        tenantId, journeyId: req.params.journeyId, callId: req.params.callId,
        authorityRef: verified.authorityRef ?? verified.credentialRef,
        payload: req.body?.payload, outcome, reason: String(req.body?.reason ?? outcome),
        result: req.body?.result, resultRef: typeof req.body?.result_ref === "string" ? req.body.result_ref : undefined,
      });
      res.json({ outcome_id: sealed.outcomeId, sealed: true });
    } catch (error) {
      res.status(409).json({ error: error instanceof Error ? error.message : "MIG_EXTERNAL_OUTCOME_INVALID" });
    }
  });

  // ── MS5 Security Endpoints ────────────────────────────────────────────────

  /** POST /api/mig/security/review — trigger a full MS5 review */
  app.post("/api/mig/security/review", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const mcpServerId: string = (req.body?.mcp_server_id as string) || "bripe-mcp-v1";
    try {
      const report = await runMS5Review({ tenantId, mcpServerId, triggeredBy: "on_demand" });
      res.json({ ok: true, report });
    } catch (err: any) {
      console.error("[MS5] review failed:", err);
      res.status(500).json({ ok: false, error: err?.message ?? "review_failed" });
    }
  });

  /** GET /api/mig/security/report — latest MS5 report */
  app.get("/api/mig/security/report", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const mcpServerId: string = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
    try {
      const report = await getLatestMS5Report(tenantId, mcpServerId);
      res.json({ ok: true, report });
    } catch (err: any) {
      console.error("[MS5] get report failed:", err);
      res.status(500).json({ ok: false, error: err?.message ?? "fetch_failed" });
    }
  });

  /** GET /api/mig/security/history — list of past MS5 reports */
  app.get("/api/mig/security/history", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const mcpServerId: string = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
    const limit = parseInt(req.query.limit as string) || 20;
    const offset = parseInt(req.query.offset as string) || 0;
    if (isNaN(limit) || isNaN(offset)) {
      res.status(400).json({ ok: false, error: "invalid limit/offset" });
      return;
    }
    try {
      const history = await getMS5ReportHistory(tenantId, mcpServerId, limit, offset);
      res.json({ ok: true, history });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "fetch_failed" });
    }
  });

  /** GET /api/mig/security/findings — findings from the latest report (unresolved by default) */
  app.get("/api/mig/security/findings", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const { mcp_server_id, severity, layer, acknowledged } = req.query as Record<string, string>;
    const mcpServerId: string = mcp_server_id || "bripe-mcp-v1";
    try {
      const findings = await getMS5Findings(tenantId, mcpServerId, {
        severity: severity || undefined,
        layer: layer || undefined,
        // Default to unresolved findings unless caller explicitly requests acknowledged ones.
        acknowledged: acknowledged !== undefined ? acknowledged === "true" : false,
      });
      res.json({ ok: true, findings });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "fetch_failed" });
    }
  });

  /**
   * POST /api/mig/security/remediate
   *
   * Acknowledges a finding. Optionally triggers self-healing validation for
   * REPAIR-class findings when `trigger_self_heal: true` is sent in the body.
   *
   * Body:
   *   finding_id       — numeric row id (required)
   *   acknowledged_by  — actor performing acknowledgment (optional, default "admin")
   *   mcp_server_id    — server scope (optional, default "bripe-mcp-v1")
   *   trigger_self_heal — boolean; when true, runs the self-healing validator
   *                       for REPAIR-class capabilities and returns findings +
   *                       an audit event. Applies only to REPAIR-class tool findings.
   */
  app.post("/api/mig/security/remediate", async (req: Request, res: Response) => {
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const { finding_id, acknowledged_by, mcp_server_id, trigger_self_heal } = req.body ?? {};
    const mcpServerId: string = (mcp_server_id as string) || "bripe-mcp-v1";
    if (!finding_id) {
      res.status(400).json({ ok: false, error: "finding_id is required" });
      return;
    }
    const id = parseInt(finding_id);
    if (isNaN(id)) {
      res.status(400).json({ ok: false, error: "finding_id must be a numeric row id" });
      return;
    }
    try {
      const finding = await acknowledgeMS5Finding(id, acknowledged_by ?? "admin", tenantId, mcpServerId);
      if (!finding) {
        res.status(404).json({ ok: false, error: "finding not found or not owned by this tenant" });
        return;
      }

      // ── Optional self-healing trigger for REPAIR-class findings ──────────
      // When trigger_self_heal=true AND the finding relates to a REPAIR-class
      // tool, run the self-healing validator and append its results.
      // This is an AUTHZ-gated read-only scan: it never modifies tool definitions.
      let selfHealResult: Record<string, unknown> | undefined;
      if (trigger_self_heal === true || trigger_self_heal === "true") {
        try {
          const { classifyTool } = await import("@shared/ms5-capability-classification");
          const capabilityName = finding.capabilityName ?? "";
          const isRepairClass = capabilityName
            ? classifyTool(capabilityName) === "REPAIR"
            : finding.category === "repair_workflow_incomplete";

          if (isRepairClass) {
            const { runSelfHealingValidation } = await import("../mig/ms5/self-healing-validator");
            const result = runSelfHealingValidation();
            selfHealResult = {
              triggered: true,
              repair_capability_count: result.repair_capability_count,
              self_heal_score: result.score,
              findings_count: result.findings.length,
              findings: result.findings.slice(0, 10),
              audit_note: `Self-healing scan triggered by acknowledgment of finding #${id} by '${acknowledged_by ?? "admin"}'.`,
            };
          } else {
            selfHealResult = {
              triggered: false,
              reason: "Finding capability is not REPAIR-class; self-healing scan not applicable.",
            };
          }
        } catch (healErr: any) {
          selfHealResult = {
            triggered: false,
            reason: `Self-healing scan failed: ${healErr?.message ?? "unknown error"}`,
          };
        }
      }

      res.json({ ok: true, finding, ...(selfHealResult ? { self_heal: selfHealResult } : {}) });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "acknowledge_failed" });
    }
  });

  // ──────────────────────────────────────────────────────────────────────────
  // MS5 CERTIFICATION & AUTO-REMEDIATION ENDPOINTS
  // ──────────────────────────────────────────────────────────────────────────

  /** GET /api/mig/security/certification — latest certification state */
  app.get("/api/mig/security/certification", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const mcpServerId = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
      const report = await getLatestMS5Report(tenantId, mcpServerId);
      if (!report) {
        res.json({ ok: true, certification: null });
        return;
      }
      res.json({ ok: true, certification: report.certification ?? null, overall_score: report.overall_score, overall_grade: report.overall_grade });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "certification_error" });
    }
  });

  /** GET /api/mig/security/escape-routes — escape route graph */
  app.get("/api/mig/security/escape-routes", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const mcpServerId = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
      const report = await getLatestMS5Report(tenantId, mcpServerId);
      if (!report?.escape_route_analysis) {
        const { runEscapeRouteAnalysis } = await import("../mig/ms5/escape-route-analyzer");
        const analysis = runEscapeRouteAnalysis();
        res.json({ ok: true, escape_route_analysis: analysis });
        return;
      }
      res.json({ ok: true, escape_route_analysis: report.escape_route_analysis });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "escape_route_error" });
    }
  });

  /** GET /api/mig/security/intent-validation — per-product intent validation report */
  app.get("/api/mig/security/intent-validation", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const mcpServerId = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
      const report = await getLatestMS5Report(tenantId, mcpServerId);
      if (!report?.intent_validation) {
        const intentDefs = await storage.listMigIntentDefinitions();
        const agents = await storage.listMigAgents(tenantId);
        const { runIntentValidation } = await import("../mig/ms5/intent-validator");
        const validation = runIntentValidation(intentDefs as any, agents as any);
        res.json({ ok: true, intent_validation: validation });
        return;
      }
      res.json({ ok: true, intent_validation: report.intent_validation });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "intent_validation_error" });
    }
  });

  /** GET /api/mig/security/tests — all generated tests */
  app.get("/api/mig/security/tests", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const mcpServerId = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
      const tests = await storage.listAllMigGeneratedTests(mcpServerId, tenantId);
      res.json({ ok: true, tests, total: tests.length });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "tests_error" });
    }
  });

  /** GET /api/mig/security/patches — list patches (optionally filtered by status) */
  app.get("/api/mig/security/patches", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const mcpServerId = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
      const status = req.query.status as string | undefined;
      const patches = await storage.listMigPatches(mcpServerId, tenantId, status);
      res.json({ ok: true, patches, total: patches.length });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "patches_error" });
    }
  });

  /** POST /api/mig/security/patches/:id/approve — approve a patch */
  app.post("/api/mig/security/patches/:id/approve", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const id = parseInt(req.params.id, 10);
      if (isNaN(id)) { res.status(400).json({ ok: false, error: "invalid_id" }); return; }
      const patch = await storage.updateMigPatchStatus(id, "APPROVED", tenantId, new Date());
      if (!patch) { res.status(404).json({ ok: false, error: "patch_not_found" }); return; }
      res.json({ ok: true, patch });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "approve_error" });
    }
  });

  /** POST /api/mig/security/patches/:id/reject — reject a patch */
  app.post("/api/mig/security/patches/:id/reject", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const id = parseInt(req.params.id, 10);
      if (isNaN(id)) { res.status(400).json({ ok: false, error: "invalid_id" }); return; }
      const patch = await storage.updateMigPatchStatus(id, "REJECTED", tenantId, new Date());
      if (!patch) { res.status(404).json({ ok: false, error: "patch_not_found" }); return; }
      res.json({ ok: true, patch });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "reject_error" });
    }
  });

  /** POST /api/mig/security/patches/:id/queue — queue a patch for merge */
  app.post("/api/mig/security/patches/:id/queue", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const id = parseInt(req.params.id, 10);
      if (isNaN(id)) { res.status(400).json({ ok: false, error: "invalid_id" }); return; }
      const patch = await storage.updateMigPatchStatus(id, "QUEUED", tenantId, new Date());
      if (!patch) { res.status(404).json({ ok: false, error: "patch_not_found" }); return; }
      res.json({ ok: true, patch });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "queue_error" });
    }
  });

  /** POST /api/mig/security/patches/:id/merge — trigger merge + post-merge validation */
  app.post("/api/mig/security/patches/:id/merge", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const mcpServerId = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
      const id = parseInt(req.params.id, 10);
      if (isNaN(id)) { res.status(400).json({ ok: false, error: "invalid_id" }); return; }
      const patch = await storage.getMigPatch(id, tenantId);
      if (!patch) { res.status(404).json({ ok: false, error: "patch_not_found" }); return; }
      if (patch.status !== "APPROVED" && patch.status !== "QUEUED") {
        res.status(400).json({ ok: false, error: `patch_status_${patch.status.toLowerCase()}_not_mergeable` });
        return;
      }
      const { runPostMergeValidation } = await import("../mig/ms5/post-merge-validator");
      const validation = await runPostMergeValidation({ patchId: id, mcpServerId, tenantId });
      res.json({ ok: true, validation });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "merge_error" });
    }
  });

  /** GET /api/mig/security/patches/:id/validation — get post-merge validation result */
  app.get("/api/mig/security/patches/:id/validation", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const id = parseInt(req.params.id, 10);
      if (isNaN(id)) { res.status(400).json({ ok: false, error: "invalid_id" }); return; }
      const validation = await storage.getMigPatchValidation(id, tenantId);
      if (!validation) { res.json({ ok: true, validation: null }); return; }
      res.json({ ok: true, validation });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "validation_error" });
    }
  });

  /** GET /api/mig/security/merges/recent — list recently applied patches with validation reports */
  app.get("/api/mig/security/merges/recent", async (req: Request, res: Response) => {
    try {
      const tenantId = requireTenant(req, res);
      if (!tenantId) return;
      const mcpServerId = (req.query.mcp_server_id as string) || "bripe-mcp-v1";
      const limit = Math.min(50, parseInt((req.query.limit as string) || "20", 10) || 20);
      const merges = await storage.listRecentMerges(mcpServerId, tenantId, limit);
      res.json({ ok: true, merges });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? "recent_merges_error" });
    }
  });
}

export function isMigApprovalAdminRole(role: unknown): boolean {
  return role === "ORG_ADMIN" || role === "ops_admin" || role === "PLATFORM_ADMIN";
}
