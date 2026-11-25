import { ownerCall } from "./standalone/owner-client";
import { db } from "./db";

import { DEFAULT_TENANT_ID, tenantRoles, type Organization } from "@shared/schema";

import { eq, desc, and, sql, inArray, lte } from "drizzle-orm";

export class DatabaseStorage {
constructor(
    private tenantId: string = DEFAULT_TENANT_ID,
    // Registration's dependent writes must share its caller's transaction.
    private registrationDb: Pick<typeof db, "select" | "insert" | "update"> = db,
  ) {}

async getMcpApiKeyByHash(keyHash: string): Promise<import("@shared/schema").McpApiKey | undefined> {
    const { mcpApiKeys } = await import("@shared/schema");
    const [row] = await db
      .select()
      .from(mcpApiKeys)
      .where(eq(mcpApiKeys.keyHash, keyHash));
    return row;
  }

async createMigTenantAuthorizationPolicy(data: import("@shared/schema").InsertMigTenantAuthorizationPolicy): Promise<import("@shared/schema").MigTenantAuthorizationPolicyRecord> {
    const { migTenantAuthorizationPolicies } = await import("@shared/schema");
    const [row] = await db.insert(migTenantAuthorizationPolicies).values(data).returning();
    return row;
  }

async getLatestMigTenantAuthorizationPolicy(tenantId: string): Promise<import("@shared/schema").MigTenantAuthorizationPolicyRecord | undefined> {
    const { migTenantAuthorizationPolicies } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    const [row] = await db.select().from(migTenantAuthorizationPolicies)
      .where(eq(migTenantAuthorizationPolicies.tenantId, tenantId))
      .orderBy(desc(migTenantAuthorizationPolicies.createdAt));
    return row;
  }

async getMigPrincipal(tenantId: string, principalId: string): Promise<import("@shared/schema").MigPrincipal | undefined> {
    const { migPrincipals } = await import("@shared/schema");
    const [row] = await db.select().from(migPrincipals).where(and(
      eq(migPrincipals.tenantId, tenantId), eq(migPrincipals.principalId, principalId),
    ));
    return row;
  }

async getActiveMigClientByComponent(tenantId: string, componentId: string): Promise<import("@shared/schema").MigClient | undefined> {
    const { migClients } = await import("@shared/schema");
    const [row] = await db.select().from(migClients).where(and(
      eq(migClients.tenantId, tenantId), eq(migClients.componentId, componentId), eq(migClients.status, "active"),
    ));
    return row;
  }

async getActiveMigPrincipalEntitlement(tenantId: string, principalId: string): Promise<import("@shared/schema").MigPrincipalEntitlement | undefined> {
    const { migPrincipalEntitlements } = await import("@shared/schema");
    const [row] = await db.select().from(migPrincipalEntitlements).where(and(
      eq(migPrincipalEntitlements.tenantId, tenantId),
      eq(migPrincipalEntitlements.principalId, principalId),
      eq(migPrincipalEntitlements.status, "active"),
    ));
    return row;
  }

async createMigPrincipal(data: import("@shared/schema").InsertMigPrincipal): Promise<import("@shared/schema").MigPrincipal> {
    const { migPrincipals } = await import("@shared/schema");
    const [row] = await db.insert(migPrincipals).values(data).returning();
    return row;
  }

async createMigPrincipalEntitlement(data: import("@shared/schema").InsertMigPrincipalEntitlement): Promise<import("@shared/schema").MigPrincipalEntitlement> {
    const { migPrincipalEntitlements } = await import("@shared/schema");
    const policy = await this.getMigTenantAuthorizationPolicy(data.tenantId);
    const active = await this.getActiveMigPrincipalEntitlement(data.tenantId, data.principalId);
    const roles = new Set([
      ...(Array.isArray(active?.assignedRoles) ? active.assignedRoles.filter((role): role is string => typeof role === "string") : []),
      ...(Array.isArray(data.assignedRoles) ? data.assignedRoles.filter((role): role is string => typeof role === "string") : []),
    ]);
    const conflicts = Array.isArray(policy?.staticSodConflicts) ? policy.staticSodConflicts : [];
    if (conflicts.some(pair =>
      Array.isArray(pair) && pair.length === 2 &&
      typeof pair[0] === "string" && typeof pair[1] === "string" &&
      roles.has(pair[0]) && roles.has(pair[1])
    )) {
      throw new Error("MIG_STATIC_SOD_ASSIGNMENT_CONFLICT");
    }
    if (active) throw new Error("MIG_ACTIVE_ENTITLEMENT_EXISTS");
    const [row] = await db.insert(migPrincipalEntitlements).values(data).returning();
    return row;
  }

async createMigAgent(data: import("@shared/schema").InsertMigRemoteAgent): Promise<import("@shared/schema").MigRemoteAgent> {
    const { migRemoteAgents } = await import("@shared/schema");
    const [row] = await db.insert(migRemoteAgents).values(data).returning();
    return row;
  }

async getMigAgentByAgentId(agentId: string): Promise<import("@shared/schema").MigRemoteAgent | undefined> {
    const { migRemoteAgents } = await import("@shared/schema");
    const [row] = await db.select().from(migRemoteAgents).where(eq(migRemoteAgents.agentId, agentId));
    return row;
  }

async listMigAgents(tenantId?: string): Promise<import("@shared/schema").MigRemoteAgent[]> {
    const { migRemoteAgents } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    const query = db.select().from(migRemoteAgents);
    if (tenantId) {
      return query.where(eq(migRemoteAgents.tenantId, tenantId)).orderBy(desc(migRemoteAgents.createdAt));
    }
    return query.orderBy(desc(migRemoteAgents.createdAt));
  }

async setMigAgentStatus(agentId: string, status: import("@shared/schema").MigAgentStatus): Promise<import("@shared/schema").MigRemoteAgent | undefined> {
    const { migRemoteAgents } = await import("@shared/schema");
    const [row] = await db
      .update(migRemoteAgents)
      .set({ status, updatedAt: new Date(), revokedAt: status === "revoked" ? new Date() : undefined })
      .where(eq(migRemoteAgents.agentId, agentId))
      .returning();
    return row;
  }

async updateMigAgent(agentId: string, patch: Partial<import("@shared/schema").InsertMigRemoteAgent>): Promise<import("@shared/schema").MigRemoteAgent | undefined> {
    const { migRemoteAgents } = await import("@shared/schema");
    const [row] = await db
      .update(migRemoteAgents)
      .set({ ...patch, updatedAt: new Date() })
      .where(eq(migRemoteAgents.agentId, agentId))
      .returning();
    return row;
  }

async recordMigAuditEvent(data: import("@shared/schema").InsertMigAuditLog): Promise<import("@shared/schema").MigAuditLog> {
    const { migAuditLog } = await import("@shared/schema");
    const [row] = await db.insert(migAuditLog).values(data).returning();
    return row;
  }

async listMigAuditEvents(filters?: {
    tenantId?: string; agentId?: string; journeyId?: string; eventType?: string; limit?: number;
  }): Promise<import("@shared/schema").MigAuditLog[]> {
    const { migAuditLog } = await import("@shared/schema");
    const { desc, and: andOp } = await import("drizzle-orm");
    const conditions = [];
    if (filters?.tenantId) conditions.push(eq(migAuditLog.tenantId, filters.tenantId));
    if (filters?.agentId) conditions.push(eq(migAuditLog.agentId, filters.agentId));
    if (filters?.journeyId) conditions.push(eq(migAuditLog.journeyId, filters.journeyId));
    if (filters?.eventType) conditions.push(eq(migAuditLog.eventType, filters.eventType));
    const limit = Math.min(Math.max(filters?.limit ?? 200, 1), 1000);
    if (conditions.length > 0) {
      return db.select().from(migAuditLog).where(andOp(...conditions)).orderBy(desc(migAuditLog.createdAt)).limit(limit);
    }
    return db.select().from(migAuditLog).orderBy(desc(migAuditLog.createdAt)).limit(limit);
  }

async createMigAuthorizationManifest(data: import("@shared/schema").InsertMigAuthorizationManifest): Promise<import("@shared/schema").MigAuthorizationManifest> {
    const { migAuthorizationManifests } = await import("@shared/schema");
    const [row] = await db.insert(migAuthorizationManifests).values(data).returning();
    return row;
  }

async getActiveMigCredentialBinding(credentialRef: string): Promise<import("@shared/schema").MigCredentialBinding | undefined> {
    const { migCredentialBindings } = await import("@shared/schema");
    const [row] = await db.select().from(migCredentialBindings).where(and(
      eq(migCredentialBindings.credentialRef, credentialRef),
      eq(migCredentialBindings.status, "active"),
    ));
    return row;
  }

async createMigAuthoritySnapshot(data: import("@shared/schema").InsertMigAuthoritySnapshot): Promise<import("@shared/schema").MigAuthoritySnapshot> {
    const { migAuthoritySnapshots } = await import("@shared/schema");
    const [row] = await db.insert(migAuthoritySnapshots).values(data).returning();
    return row;
  }

async getMigTenantAuthorityConfig(tenantId: string): Promise<import("@shared/schema").MigTenantAuthorityConfig | undefined> {
    const { migTenantAuthorityConfigs } = await import("@shared/schema");
    const [row] = await db.select().from(migTenantAuthorityConfigs)
      .where(and(eq(migTenantAuthorityConfigs.tenantId, tenantId), eq(migTenantAuthorityConfigs.status, "active")))
      .orderBy(desc(migTenantAuthorityConfigs.createdAt), desc(migTenantAuthorityConfigs.id));
    return row;
  }

async getMigIntentDefinition(intentId: string): Promise<import("@shared/schema").MigIntentDefinition | undefined> {
    const { migIntentDefinitions } = await import("@shared/schema");
    const [row] = await db.select().from(migIntentDefinitions).where(eq(migIntentDefinitions.intentId, intentId));
    return row;
  }

async updateMigIntentDefinition(intentId: string, patch: Partial<import("@shared/schema").InsertMigIntentDefinition>): Promise<import("@shared/schema").MigIntentDefinition | undefined> {
    const { migIntentDefinitions } = await import("@shared/schema");
    const [row] = await db
      .update(migIntentDefinitions)
      .set({ ...patch, updatedAt: new Date() })
      .where(eq(migIntentDefinitions.intentId, intentId))
      .returning();
    return row;
  }

async createMigClient(data: import("@shared/schema").InsertMigClient): Promise<import("@shared/schema").MigClient> {
    const { migClients } = await import("@shared/schema");
    const [row] = await db.insert(migClients).values(data).returning();
    return row;
  }

async createMigCredentialBinding(data: import("@shared/schema").InsertMigCredentialBinding): Promise<import("@shared/schema").MigCredentialBinding> {
    const { migCredentialBindings } = await import("@shared/schema");
    const [row] = await db.insert(migCredentialBindings).values(data).returning();
    return row;
  }

async getActiveMigClientByCredentialHash(credentialHash: string): Promise<import("@shared/schema").MigClient | undefined> {
    const { migClients } = await import("@shared/schema");
    const [row] = await db.select().from(migClients).where(and(eq(migClients.credentialHash, credentialHash), eq(migClients.status, "active")));
    return row;
  }

async revokeMigClient(tenantId: string, componentId: string, principalId?: string): Promise<import("@shared/schema").MigClient | undefined> {
    return this.setMigClientAuthorityStatus(tenantId, componentId, "revoked", principalId);
  }

async getMigJourney(tenantId: string, journeyId: string): Promise<import("@shared/schema").MigJourney | undefined> {
    const { migJourneys } = await import("@shared/schema");
    const [row] = await db.select().from(migJourneys).where(and(eq(migJourneys.tenantId, tenantId), eq(migJourneys.journeyId, journeyId)));
    return row;
  }

async getMigJourneyCall(tenantId: string, callId: string): Promise<import("@shared/schema").MigJourneyCall | undefined> {
    const { migJourneyCalls } = await import("@shared/schema");
    const [row] = await db.select().from(migJourneyCalls).where(and(eq(migJourneyCalls.tenantId, tenantId), eq(migJourneyCalls.callId, callId)));
    return row;
  }

async getMigJourneyOutcome(tenantId: string, callId: string): Promise<import("@shared/schema").MigJourneyOutcome | undefined> {
    const { migJourneyOutcomes } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    const [row] = await db.select().from(migJourneyOutcomes)
      .where(and(eq(migJourneyOutcomes.tenantId, tenantId), eq(migJourneyOutcomes.callId, callId)))
      .orderBy(desc(migJourneyOutcomes.createdAt), desc(migJourneyOutcomes.id));
    return row;
  }

async createMigJourneyIntentTransitionWithAudit(
    transition: import("@shared/schema").InsertMigJourneyIntentTransition,
    audit: import("@shared/schema").InsertMigAuditLog,
  ): Promise<import("@shared/schema").MigJourneyIntentTransition> {
    const { migAuditLog, migJourneyIntentTransitions } = await import("@shared/schema");
    const { sql } = await import("drizzle-orm");
    if (audit.tenantId !== transition.tenantId ||
        audit.journeyId !== transition.journeyId ||
        audit.parentCallId !== transition.parentCallId) {
      throw new Error("MIG_INTENT_TRANSITION_AUDIT_LINEAGE_MISMATCH");
    }
    return db.transaction(async tx => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`${transition.tenantId}|${transition.journeyId}|${transition.parentCallId}`}))`);
      const existing = await tx.select().from(migJourneyIntentTransitions).where(and(
        eq(migJourneyIntentTransitions.tenantId, transition.tenantId),
        eq(migJourneyIntentTransitions.journeyId, transition.journeyId),
        eq(migJourneyIntentTransitions.parentCallId, transition.parentCallId),
      ));
      if (existing.some(row => new Date(row.expiresAt).getTime() > Date.now())) {
        throw new Error("MIG_INTENT_TRANSITION_ACTIVE_APPROVAL_EXISTS");
      }
      const [created] = await tx.insert(migJourneyIntentTransitions).values(transition).returning();
      await tx.insert(migAuditLog).values(audit);
      return created;
    });
  }

async listMigPrincipals(tenantId: string): Promise<import("@shared/schema").MigPrincipal[]> {
    const { migPrincipals } = await import("@shared/schema");
    return db.select().from(migPrincipals).where(eq(migPrincipals.tenantId, tenantId));
  }

async getMigTenantAuthorizationPolicy(tenantId: string): Promise<import("@shared/schema").MigTenantAuthorizationPolicyRecord | undefined> {
    const { migTenantAuthorizationPolicies } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    const [row] = await db.select().from(migTenantAuthorizationPolicies)
      .where(and(
        eq(migTenantAuthorizationPolicies.tenantId, tenantId),
        eq(migTenantAuthorizationPolicies.status, "active"),
      ))
      .orderBy(desc(migTenantAuthorizationPolicies.createdAt));
    return row;
  }

async getMigJourneyIntentTransition(tenantId: string, journeyId: string, transitionId: string): Promise<import("@shared/schema").MigJourneyIntentTransition | undefined> {
    const { migJourneyIntentTransitions } = await import("@shared/schema");
    const [row] = await db.select().from(migJourneyIntentTransitions).where(and(
      eq(migJourneyIntentTransitions.tenantId, tenantId),
      eq(migJourneyIntentTransitions.journeyId, journeyId),
      eq(migJourneyIntentTransitions.transitionId, transitionId),
    ));
    return row;
  }

async createMigJourneyIntentTransitionRevocation(data: import("@shared/schema").InsertMigJourneyIntentTransitionRevocation): Promise<import("@shared/schema").MigJourneyIntentTransitionRevocation> {
    const { migJourneyIntentTransitionRevocations } = await import("@shared/schema");
    const { sql } = await import("drizzle-orm");
    return db.transaction(async tx => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`${data.tenantId}|${data.transitionId}`}))`);
      const [existing] = await tx.select().from(migJourneyIntentTransitionRevocations).where(and(
        eq(migJourneyIntentTransitionRevocations.tenantId, data.tenantId),
        eq(migJourneyIntentTransitionRevocations.transitionId, data.transitionId),
      ));
      if (existing) throw new Error("MIG_INTENT_TRANSITION_ALREADY_REVOKED");
      const [row] = await tx.insert(migJourneyIntentTransitionRevocations).values(data).returning();
      return row;
    });
  }

async listMigJourneyCalls(tenantId: string, journeyId: string): Promise<import("@shared/schema").MigJourneyCall[]> {
    const { migJourneyCalls } = await import("@shared/schema");
    const { asc } = await import("drizzle-orm");
    return db.select().from(migJourneyCalls).where(and(eq(migJourneyCalls.tenantId, tenantId), eq(migJourneyCalls.journeyId, journeyId))).orderBy(asc(migJourneyCalls.sequence), asc(migJourneyCalls.id));
  }

async listMigJourneyOutcomes(tenantId: string, journeyId: string): Promise<import("@shared/schema").MigJourneyOutcome[]> {
    const { migJourneyOutcomes } = await import("@shared/schema");
    const { asc } = await import("drizzle-orm");
    return db.select().from(migJourneyOutcomes).where(and(eq(migJourneyOutcomes.tenantId, tenantId), eq(migJourneyOutcomes.journeyId, journeyId))).orderBy(asc(migJourneyOutcomes.createdAt));
  }

async listMigJourneyIntentTransitions(tenantId: string, journeyId: string, parentCallId: string): Promise<import("@shared/schema").MigJourneyIntentTransition[]> {
    const { migJourneyIntentTransitions } = await import("@shared/schema");
    const { asc } = await import("drizzle-orm");
    return db.select().from(migJourneyIntentTransitions).where(and(
      eq(migJourneyIntentTransitions.tenantId, tenantId),
      eq(migJourneyIntentTransitions.journeyId, journeyId),
      eq(migJourneyIntentTransitions.parentCallId, parentCallId),
    )).orderBy(asc(migJourneyIntentTransitions.createdAt), asc(migJourneyIntentTransitions.id));
  }

async getMigJourneyIntentTransitionRevocation(tenantId: string, transitionId: string): Promise<import("@shared/schema").MigJourneyIntentTransitionRevocation | undefined> {
    const { migJourneyIntentTransitionRevocations } = await import("@shared/schema");
    const [row] = await db.select().from(migJourneyIntentTransitionRevocations).where(and(
      eq(migJourneyIntentTransitionRevocations.tenantId, tenantId),
      eq(migJourneyIntentTransitionRevocations.transitionId, transitionId),
    ));
    return row;
  }

async createMigJourney(data: import("@shared/schema").InsertMigJourney): Promise<import("@shared/schema").MigJourney> {
    const { migJourneys } = await import("@shared/schema");
    const [row] = await db.insert(migJourneys).values(data).returning();
    return row;
  }

async createMigJourneyCall(data: import("@shared/schema").InsertMigJourneyCall): Promise<import("@shared/schema").MigJourneyCall> {
    const { migJourneyCalls } = await import("@shared/schema");
    const [row] = await db.insert(migJourneyCalls).values(data).returning();
    return row;
  }

async createMigJourneyOutcome(data: import("@shared/schema").InsertMigJourneyOutcome): Promise<import("@shared/schema").MigJourneyOutcome> {
    const { migAuthorizationManifests, migJourneyCalls, migJourneyOutcomes } = await import("@shared/schema");
    const { asc, sql } = await import("drizzle-orm");
    return db.transaction(async tx => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`${data.tenantId}|${data.callId}`}))`);
      const [admittedCall] = await tx.select({ callId: migJourneyCalls.callId })
        .from(migJourneyCalls).where(and(
          eq(migJourneyCalls.tenantId, data.tenantId),
          eq(migJourneyCalls.journeyId, data.journeyId),
          eq(migJourneyCalls.callId, data.callId),
        ));
      if (!admittedCall) throw new Error("MIG_OUTCOME_JOURNEY_ADMISSION_INVALID");
      const existing = await tx.select().from(migJourneyOutcomes)
        .where(and(eq(migJourneyOutcomes.tenantId, data.tenantId), eq(migJourneyOutcomes.callId, data.callId)))
        .orderBy(asc(migJourneyOutcomes.createdAt), asc(migJourneyOutcomes.id));
      if (data.authorizationManifestId) {
        const [admittedManifest] = await tx.select({
          authorizationManifestId: migAuthorizationManifests.authorizationManifestId,
        }).from(migAuthorizationManifests).where(and(
          eq(migAuthorizationManifests.tenantId, data.tenantId),
          eq(migAuthorizationManifests.authorizationManifestId, data.authorizationManifestId),
          eq(migAuthorizationManifests.requestCorrelationId, data.callId),
        ));
        if (!admittedManifest) throw new Error("MIG_OUTCOME_AUTHORIZATION_MANIFEST_INVALID");
        if (data.outcome === "allowed") {
          const [allowedManifest] = await tx.select({
            authorizationManifestId: migAuthorizationManifests.authorizationManifestId,
          }).from(migAuthorizationManifests).where(and(
            eq(migAuthorizationManifests.tenantId, data.tenantId),
            eq(migAuthorizationManifests.authorizationManifestId, data.authorizationManifestId),
            eq(migAuthorizationManifests.decision, "allow"),
          ));
          if (!allowedManifest) throw new Error("MIG_OUTCOME_AUTHORIZATION_MANIFEST_INVALID");
        }
        if (existing.length > 0 &&
            existing[0].authorizationManifestId !== data.authorizationManifestId) {
          throw new Error("MIG_OUTCOME_AUTHORIZATION_MANIFEST_INVALID");
        }
      }
      if (existing.length > 0 && existing[0].authorizationManifestId && !data.authorizationManifestId) {
        throw new Error("MIG_OUTCOME_AUTHORIZATION_MANIFEST_INVALID");
      }
      if (data.outcome === "allowed") {
        if (existing.length > 0) throw new Error("MIG_OUTCOME_ADMISSION_ALREADY_RECORDED");
      } else if (data.outcome === "denied" && existing.length === 0) {
        // A journey governor may deny before admission/execution. It is still
        // a terminal, append-only decision rather than a synthetic allow.
      } else {
        if (existing.length !== 1 || existing[0].outcome !== "allowed") {
          throw new Error("MIG_OUTCOME_TERMINAL_TRANSITION_INVALID");
        }
      }
      const [row] = await tx.insert(migJourneyOutcomes).values(data).returning();
      return row;
    });
  }

async getMigAuthorizationManifest(tenantId: string, authorizationManifestId: string): Promise<import("@shared/schema").MigAuthorizationManifest | undefined> {
    const { migAuthorizationManifests } = await import("@shared/schema");
    const [row] = await db.select().from(migAuthorizationManifests).where(and(
      eq(migAuthorizationManifests.tenantId, tenantId),
      eq(migAuthorizationManifests.authorizationManifestId, authorizationManifestId),
    ));
    return row;
  }

async createMcpContractAuthRelationship(data: import("@shared/schema").InsertMcpContractAuthRelationship): Promise<import("@shared/schema").McpContractAuthRelationship> {
    const { mcpContractAuthRelationships } = await import("@shared/schema");
    const [row] = await db.insert(mcpContractAuthRelationships).values(data).returning();
    return row;
  }

async createMigTicket(data: import("@shared/schema").InsertMigTicket): Promise<import("@shared/schema").MigTicket> {
    const { migTickets } = await import("@shared/schema");
    const [row] = await db.insert(migTickets).values(data).returning();
    return row;
  }

async getMigTicketByJti(jti: string): Promise<import("@shared/schema").MigTicket | undefined> {
    const { migTickets } = await import("@shared/schema");
    const [row] = await db.select().from(migTickets).where(eq(migTickets.jti, jti));
    return row;
  }

async revokeMigTicket(jti: string, reason: string): Promise<import("@shared/schema").MigTicket | undefined> {
    const { migTickets } = await import("@shared/schema");
    const [row] = await db
      .update(migTickets)
      .set({ revoked: true, revokedAt: new Date(), revokedReason: reason })
      .where(eq(migTickets.jti, jti))
      .returning();
    return row;
  }

async recordMigDiscoveryEvent(data: import("@shared/schema").InsertMigDiscoveryEvent): Promise<import("@shared/schema").MigDiscoveryEvent> {
    const { migDiscoveryEvents } = await import("@shared/schema");
    const [row] = await db.insert(migDiscoveryEvents).values(data).returning();
    return row;
  }

async listMigDiscoveryEvents(agentId: string, limit?: number): Promise<import("@shared/schema").MigDiscoveryEvent[]> {
    const { migDiscoveryEvents } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    return db.select().from(migDiscoveryEvents)
      .where(eq(migDiscoveryEvents.agentId, agentId))
      .orderBy(desc(migDiscoveryEvents.createdAt))
      .limit(limit ?? 500);
  }

async createMigDraftProfile(data: import("@shared/schema").InsertMigDraftIntentProfile): Promise<import("@shared/schema").MigDraftIntentProfile> {
    const { migDraftIntentProfiles } = await import("@shared/schema");
    const [row] = await db.insert(migDraftIntentProfiles).values(data).returning();
    return row;
  }

async getMigDraftProfile(draftId: string): Promise<import("@shared/schema").MigDraftIntentProfile | undefined> {
    const { migDraftIntentProfiles } = await import("@shared/schema");
    const [row] = await db.select().from(migDraftIntentProfiles).where(eq(migDraftIntentProfiles.draftId, draftId));
    return row;
  }

async listMigDraftProfiles(agentId?: string): Promise<import("@shared/schema").MigDraftIntentProfile[]> {
    const { migDraftIntentProfiles } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    const query = db.select().from(migDraftIntentProfiles);
    if (agentId) {
      return query.where(eq(migDraftIntentProfiles.agentId, agentId)).orderBy(desc(migDraftIntentProfiles.createdAt));
    }
    return query.orderBy(desc(migDraftIntentProfiles.createdAt));
  }

async updateMigDraftProfile(
    draftId: string,
    patch: Partial<import("@shared/schema").InsertMigDraftIntentProfile> & { reviewedAt?: Date },
  ): Promise<import("@shared/schema").MigDraftIntentProfile | undefined> {
    const { migDraftIntentProfiles } = await import("@shared/schema");
    const [row] = await db.update(migDraftIntentProfiles)
      .set({ ...patch, updatedAt: new Date() })
      .where(eq(migDraftIntentProfiles.draftId, draftId))
      .returning();
    return row;
  }

async recordMigDriftEvent(data: import("@shared/schema").InsertMigDriftEvent): Promise<import("@shared/schema").MigDriftEvent> {
    const { migDriftEvents } = await import("@shared/schema");
    const [row] = await db.insert(migDriftEvents).values(data).returning();
    return row;
  }

async listMigDriftEvents(filters?: { tenantId?: string; agentId?: string; resolved?: boolean }): Promise<import("@shared/schema").MigDriftEvent[]> {
    const { migDriftEvents } = await import("@shared/schema");
    const { desc, and: andOp } = await import("drizzle-orm");
    const conditions = [];
    if (filters?.tenantId) conditions.push(eq(migDriftEvents.tenantId, filters.tenantId));
    if (filters?.agentId) conditions.push(eq(migDriftEvents.agentId, filters.agentId));
    if (filters?.resolved !== undefined) conditions.push(eq(migDriftEvents.resolved, filters.resolved));
    if (conditions.length > 0) {
      return db.select().from(migDriftEvents).where(andOp(...conditions)).orderBy(desc(migDriftEvents.createdAt));
    }
    return db.select().from(migDriftEvents).orderBy(desc(migDriftEvents.createdAt));
  }

async resolveMigDriftEvent(eventId: string, resolvedBy: string): Promise<import("@shared/schema").MigDriftEvent | undefined> {
    const { migDriftEvents } = await import("@shared/schema");
    const [row] = await db.update(migDriftEvents)
      .set({ resolved: true, resolvedBy, resolvedAt: new Date() })
      .where(eq(migDriftEvents.eventId, eventId))
      .returning();
    return row;
  }

async getMigRegistryCandidate(tenantId: string, candidateId: string): Promise<import("@shared/schema").MigRegistryCandidate | undefined> {
    const { migRegistryCandidates } = await import("@shared/schema");
    const [row] = await db.select().from(migRegistryCandidates).where(and(eq(migRegistryCandidates.tenantId, tenantId), eq(migRegistryCandidates.candidateId, candidateId)));
    return row;
  }

async createMigRegistryHistory(data: import("@shared/schema").InsertMigRegistryHistory): Promise<import("@shared/schema").MigRegistryHistory> {
    const { migRegistryHistory } = await import("@shared/schema");
    const [row] = await db.insert(migRegistryHistory).values(data).returning();
    return row;
  }

async getMigRegistryCandidateByIdempotencyKey(tenantId: string, idempotencyKey: string): Promise<import("@shared/schema").MigRegistryCandidate | undefined> {
    const { migRegistryCandidates } = await import("@shared/schema");
    const [row] = await db.select().from(migRegistryCandidates).where(and(eq(migRegistryCandidates.tenantId, tenantId), eq(migRegistryCandidates.idempotencyKey, idempotencyKey)));
    return row;
  }

async createMigRegistryCandidate(data: import("@shared/schema").InsertMigRegistryCandidate): Promise<import("@shared/schema").MigRegistryCandidate> {
    const { migRegistryCandidates } = await import("@shared/schema");
    const [row] = await db.insert(migRegistryCandidates).values(data).returning();
    return row;
  }

async updateMigRegistryCandidate(tenantId: string, candidateId: string, patch: Partial<Pick<import("@shared/schema").InsertMigRegistryCandidate, "principalId" | "clientClass" | "target">>): Promise<import("@shared/schema").MigRegistryCandidate | undefined> {
    const { migRegistryCandidates } = await import("@shared/schema");
    const [row] = await db.update(migRegistryCandidates).set(patch).where(and(
      eq(migRegistryCandidates.tenantId, tenantId), eq(migRegistryCandidates.candidateId, candidateId),
    )).returning();
    return row;
  }

async setMigRegistryCandidateState(tenantId: string, candidateId: string, state: import("@shared/schema").MigRegistryState): Promise<import("@shared/schema").MigRegistryCandidate | undefined> {
    const { migRegistryCandidates } = await import("@shared/schema");
    const [row] = await db.update(migRegistryCandidates).set({ state }).where(and(eq(migRegistryCandidates.tenantId, tenantId), eq(migRegistryCandidates.candidateId, candidateId))).returning();
    return row;
  }

async suspendMigClient(tenantId: string, componentId: string, principalId?: string): Promise<import("@shared/schema").MigClient | undefined> {
    return this.setMigClientAuthorityStatus(tenantId, componentId, "suspended", principalId);
  }

async getMigIntentLibrary(libraryId: string): Promise<import("@shared/schema").MigIntentLibrary | undefined> {
    const { migIntentLibraries } = await import("@shared/schema");
    const [row] = await db.select().from(migIntentLibraries).where(eq(migIntentLibraries.libraryId, libraryId));
    return row;
  }

async listMigRegistryCandidates(tenantId: string, limit = 100): Promise<import("@shared/schema").MigRegistryCandidate[]> {
    const { migRegistryCandidates } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    return db.select().from(migRegistryCandidates).where(eq(migRegistryCandidates.tenantId, tenantId)).orderBy(desc(migRegistryCandidates.createdAt)).limit(Math.min(Math.max(limit, 1), 100));
  }

async commitMigRegistryReview(input: {
    tenantId: string; candidateId: string; expectedState: string;
    expectedTarget: unknown; target: Record<string, unknown>;
    history: import("@shared/schema").InsertMigRegistryHistory;
  }): Promise<import("@shared/schema").MigRegistryCandidate> {
    const { migRegistryCandidates, migRegistryHistory } = await import("@shared/schema");
    if (input.history.tenantId !== input.tenantId || input.history.candidateId !== input.candidateId) {
      throw new Error("MIG_REGISTRY_REVIEW_SCOPE_MISMATCH");
    }
    return db.transaction(async tx => {
      const [candidate] = await tx.update(migRegistryCandidates).set({ target: input.target })
        .where(and(eq(migRegistryCandidates.tenantId, input.tenantId),
          eq(migRegistryCandidates.candidateId, input.candidateId), eq(migRegistryCandidates.state, input.expectedState),
          sql`${migRegistryCandidates.target} = ${JSON.stringify(input.expectedTarget)}::jsonb`)).returning();
      if (!candidate) throw new Error("MIG_REGISTRY_REVIEW_CONFLICT");
      await tx.insert(migRegistryHistory).values(input.history);
      return candidate;
    });
  }

async createMigIntentLibrary(data: import("@shared/schema").InsertMigIntentLibrary): Promise<import("@shared/schema").MigIntentLibrary> {
    const { migIntentLibraries } = await import("@shared/schema");
    const [row] = await db.insert(migIntentLibraries).values(data).returning();
    return row;
  }

async updateMigIntentLibraryStatus(libraryId: string, status: string): Promise<import("@shared/schema").MigIntentLibrary | undefined> {
    const { migIntentLibraries } = await import("@shared/schema");
    const [row] = await db
      .update(migIntentLibraries)
      .set({ status, updatedAt: new Date() })
      .where(eq(migIntentLibraries.libraryId, libraryId))
      .returning();
    return row;
  }

async listMigIntentLibraries(): Promise<import("@shared/schema").MigIntentLibrary[]> {
    const { migIntentLibraries } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    return db.select().from(migIntentLibraries).orderBy(desc(migIntentLibraries.createdAt));
  }

async createMigIntentDefinition(data: import("@shared/schema").InsertMigIntentDefinition): Promise<import("@shared/schema").MigIntentDefinition> {
    const { migIntentDefinitions } = await import("@shared/schema");
    const [row] = await db.insert(migIntentDefinitions).values(data).returning();
    return row;
  }

async listMigIntentDefinitions(libraryId?: string): Promise<import("@shared/schema").MigIntentDefinition[]> {
    const { migIntentDefinitions } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    const query = db.select().from(migIntentDefinitions);
    if (libraryId) {
      return query.where(eq(migIntentDefinitions.libraryId, libraryId)).orderBy(desc(migIntentDefinitions.createdAt));
    }
    return query.orderBy(desc(migIntentDefinitions.createdAt));
  }

async createMigCapabilityManifest(data: import("@shared/schema").InsertMigCapabilityManifest): Promise<import("@shared/schema").MigCapabilityManifest> {
    const { migCapabilityManifests } = await import("@shared/schema");
    const [row] = await db.insert(migCapabilityManifests).values(data).returning();
    return row;
  }

async updateMigCredentialBindingCeiling(credentialRef: string, tenantId: string, capabilityCeiling: string[]): Promise<import("@shared/schema").MigCredentialBinding | undefined> {
    const { migCredentialBindings } = await import("@shared/schema");
    const [row] = await db.update(migCredentialBindings).set({ capabilityCeiling }).where(and(
      eq(migCredentialBindings.credentialRef, credentialRef),
      eq(migCredentialBindings.tenantId, tenantId),
      eq(migCredentialBindings.status, "active"),
    )).returning();
    return row;
  }

async appendMigObservationFactualEdge(data: import("@shared/schema").InsertMigObservationFactualEdge): Promise<import("@shared/schema").MigObservationFactualEdge> {
    const { migObservationFactualEdges } = await import("@shared/schema"); const [row] = await db.insert(migObservationFactualEdges).values(data).onConflictDoNothing().returning(); if (row) return row; const [existing] = await db.select().from(migObservationFactualEdges).where(eq(migObservationFactualEdges.factualEdgeId, data.factualEdgeId)); return existing;
  }

async appendMigObservationEvent(data: import("@shared/schema").InsertMigObservationEvent): Promise<import("@shared/schema").MigObservationEvent> {
    const { migObservationEvents } = await import("@shared/schema");
    const [row] = await db.insert(migObservationEvents).values(data).onConflictDoNothing().returning();
    if (row) return row;
    const [existing] = await db.select().from(migObservationEvents).where(and(eq(migObservationEvents.tenantId, data.tenantId), eq(migObservationEvents.sourceId, data.sourceId), eq(migObservationEvents.idempotencyKey, data.idempotencyKey)));
    if (!existing) throw new Error("MIG_OBSERVATION_IDEMPOTENCY_READ_FAILED");
    return existing;
  }

async getMigObservationCorrelationForEvent(tenantId: string, observationEventId: string): Promise<import("@shared/schema").MigObservationCorrelation | undefined> {
    const { migObservationCorrelations } = await import("@shared/schema"); const [row] = await db.select().from(migObservationCorrelations).where(and(eq(migObservationCorrelations.tenantId, tenantId), eq(migObservationCorrelations.observationEventId, observationEventId))); return row;
  }

async getMigObservedJourneyVersionBySourceEvent(tenantId: string, sourceObservationEventId: string): Promise<import("@shared/schema").MigObservedJourneyVersion | undefined> {
    const { migObservedJourneyVersions } = await import("@shared/schema"); const [row] = await db.select().from(migObservedJourneyVersions).where(and(eq(migObservedJourneyVersions.tenantId, tenantId), eq(migObservedJourneyVersions.sourceObservationEventId, sourceObservationEventId))); return row;
  }

async appendMigObservationCorrelation(data: import("@shared/schema").InsertMigObservationCorrelation): Promise<import("@shared/schema").MigObservationCorrelation> {
    const { migObservationCorrelations } = await import("@shared/schema"); const [row] = await db.insert(migObservationCorrelations).values(data).onConflictDoNothing().returning();
    if (row) return row; const [existing] = await db.select().from(migObservationCorrelations).where(eq(migObservationCorrelations.correlationId, data.correlationId)); return existing;
  }

async getLatestMigObservedJourneyVersion(tenantId: string, observedJourneyId: string): Promise<import("@shared/schema").MigObservedJourneyVersion | undefined> {
    const { migObservedJourneyVersions } = await import("@shared/schema"); const [row] = await db.select().from(migObservedJourneyVersions).where(and(eq(migObservedJourneyVersions.tenantId, tenantId), eq(migObservedJourneyVersions.observedJourneyId, observedJourneyId))).orderBy(desc(migObservedJourneyVersions.version)); return row;
  }

async appendMigObservedJourneyVersion(data: import("@shared/schema").InsertMigObservedJourneyVersion): Promise<import("@shared/schema").MigObservedJourneyVersion> {
    const { migObservedJourneyVersions } = await import("@shared/schema");
    return db.transaction(async tx => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`${data.tenantId}|${data.observedJourneyId}`}))`);
      const [prior] = await tx.select().from(migObservedJourneyVersions).where(and(
        eq(migObservedJourneyVersions.tenantId, data.tenantId), eq(migObservedJourneyVersions.observedJourneyId, data.observedJourneyId),
      )).orderBy(desc(migObservedJourneyVersions.version));
      if ((prior?.version ?? 0) + 1 !== data.version ||
        (prior?.journeyVersionId ?? null) !== (data.supersedesJourneyVersionId ?? null)) {
        throw new Error("MIG_OBSERVATION_VERSION_LINEAGE_INVALID");
      }
      const [row] = await tx.insert(migObservedJourneyVersions).values(data).returning(); return row;
    });
  }

async getMigObservedJourneyVersion(tenantId: string, journeyVersionId: string): Promise<import("@shared/schema").MigObservedJourneyVersion | undefined> {
    const { migObservedJourneyVersions } = await import("@shared/schema"); const [row] = await db.select().from(migObservedJourneyVersions).where(and(eq(migObservedJourneyVersions.tenantId, tenantId), eq(migObservedJourneyVersions.journeyVersionId, journeyVersionId))); return row;
  }

async listMigObservationEventsByIds(tenantId: string, observationEventIds: string[]): Promise<import("@shared/schema").MigObservationEvent[]> {
    const { migObservationEvents } = await import("@shared/schema"); return observationEventIds.length ? db.select().from(migObservationEvents).where(and(eq(migObservationEvents.tenantId, tenantId), inArray(migObservationEvents.observationEventId, observationEventIds))) : [];
  }

async listMigObservationFactualEdgesByIds(tenantId: string, factualEdgeIds: string[]): Promise<import("@shared/schema").MigObservationFactualEdge[]> {
    const { migObservationFactualEdges } = await import("@shared/schema");
    return factualEdgeIds.length ? db.select().from(migObservationFactualEdges).where(and(
      eq(migObservationFactualEdges.tenantId, tenantId), inArray(migObservationFactualEdges.factualEdgeId, factualEdgeIds),
    )) : [];
  }

async withMigObservationEvaluationLock<T>(tenantId: string, journeyVersionId: string, requestId: string, work: () => Promise<T>): Promise<T> {
    return db.transaction(async tx => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`${tenantId}|${journeyVersionId}|${requestId}`}))`);
      return work();
    });
  }

async getMigObservationProofForDecision(tenantId: string, observationStructuralDecisionId: string): Promise<import("@shared/schema").MigObservationProofReference | undefined> {
    const { migObservationProofReferences } = await import("@shared/schema"); const [row] = await db.select().from(migObservationProofReferences).where(and(eq(migObservationProofReferences.tenantId, tenantId), eq(migObservationProofReferences.observationStructuralDecisionId, observationStructuralDecisionId))); return row;
  }

async appendMigObservationProofReference(data: import("@shared/schema").InsertMigObservationProofReference): Promise<import("@shared/schema").MigObservationProofReference> {
    const { migObservationProofReferences } = await import("@shared/schema"); const [row] = await db.insert(migObservationProofReferences).values(data).onConflictDoNothing().returning();
    if (row) return row; const [existing] = await db.select().from(migObservationProofReferences).where(and(eq(migObservationProofReferences.tenantId, data.tenantId), eq(migObservationProofReferences.proofRef, data.proofRef)));
    if (!existing) throw new Error("MIG_OBSERVATION_IDEMPOTENCY_READ_FAILED"); return existing;
  }

async getMigObservationFindingForDecision(tenantId: string, observationStructuralDecisionId: string): Promise<import("@shared/schema").MigObservationFinding | undefined> {
    const { migObservationFindings } = await import("@shared/schema"); const [row] = await db.select().from(migObservationFindings).where(and(eq(migObservationFindings.tenantId, tenantId), eq(migObservationFindings.structuralDecisionRef, observationStructuralDecisionId))); return row;
  }

async appendMigObservationFinding(data: import("@shared/schema").InsertMigObservationFinding): Promise<import("@shared/schema").MigObservationFinding> {
    const { migObservationFindings } = await import("@shared/schema"); const [row] = await db.insert(migObservationFindings).values(data).onConflictDoNothing().returning();
    if (row) return row; const [existing] = await db.select().from(migObservationFindings).where(and(eq(migObservationFindings.tenantId, data.tenantId), eq(migObservationFindings.findingId, data.findingId))); if (!existing) throw new Error("MIG_OBSERVATION_IDEMPOTENCY_READ_FAILED"); return existing;
  }

async getMigObservationStructuralDecisionByRequest(tenantId: string, journeyVersionId: string, canonicalRequestRef: string): Promise<import("@shared/schema").MigObservationStructuralDecision | undefined> {
    const { migObservationStructuralDecisions } = await import("@shared/schema"); const [row] = await db.select().from(migObservationStructuralDecisions).where(and(eq(migObservationStructuralDecisions.tenantId, tenantId), eq(migObservationStructuralDecisions.journeyVersionId, journeyVersionId), eq(migObservationStructuralDecisions.canonicalRequestRef, canonicalRequestRef))); return row;
  }

async appendMigObservationStructuralDecision(data: import("@shared/schema").InsertMigObservationStructuralDecision): Promise<import("@shared/schema").MigObservationStructuralDecision> {
    const { migObservationStructuralDecisions } = await import("@shared/schema"); const [row] = await db.insert(migObservationStructuralDecisions).values(data).onConflictDoNothing().returning();
    if (row) return row; const [existing] = await db.select().from(migObservationStructuralDecisions).where(and(eq(migObservationStructuralDecisions.tenantId, data.tenantId), eq(migObservationStructuralDecisions.journeyVersionId, data.journeyVersionId), eq(migObservationStructuralDecisions.canonicalRequestRef, data.canonicalRequestRef)));
    if (!existing) throw new Error("MIG_OBSERVATION_IDEMPOTENCY_READ_FAILED"); return existing;
  }

async appendMigObservationCustomerOutcome(data: import("@shared/schema").InsertMigObservationCustomerOutcome): Promise<import("@shared/schema").MigObservationCustomerOutcome> {
    const { migObservationCustomerOutcomes } = await import("@shared/schema"); const [row] = await db.insert(migObservationCustomerOutcomes).values(data).onConflictDoNothing().returning();
    if (row) return row; const [existing] = await db.select().from(migObservationCustomerOutcomes).where(and(eq(migObservationCustomerOutcomes.tenantId, data.tenantId), eq(migObservationCustomerOutcomes.outcomeId, data.outcomeId)));
    if (!existing) throw new Error("MIG_OBSERVATION_IDEMPOTENCY_READ_FAILED"); return existing;
  }

async listMigClients(tenantId: string): Promise<import("@shared/schema").MigClient[]> {
    const { migClients } = await import("@shared/schema");
    return db.select().from(migClients).where(eq(migClients.tenantId, tenantId));
  }

async getMigConnectionRoles(tenantId: string): Promise<Array<{ key: string; label: string }>> {
    return db.select({ key: tenantRoles.key, label: tenantRoles.label }).from(tenantRoles)
      .where(eq(tenantRoles.tenantId, tenantId)).orderBy(tenantRoles.id);
  }

async getActiveMigClientByPrincipal(tenantId: string, principalId: string): Promise<import("@shared/schema").MigClient | undefined> {
    const { migClients } = await import("@shared/schema");
    const rows = await db.select().from(migClients).where(and(
      eq(migClients.tenantId, tenantId), eq(migClients.principalId, principalId), eq(migClients.status, "active"),
    )).limit(2);
    return rows.length === 1 ? rows[0] : undefined;
  }

async replaceMigConnectionPermissions(input: { tenantId: string; actorId: string; candidateId: string; expectedEntitlementId: string; intentIds: string[]; assignedRoles: string[] }): Promise<void> {
    const { randomUUID } = await import("node:crypto");
    const { migRegistryCandidates: candidates, migPrincipalEntitlements: entitlements,
      migClients: clients, migCredentialBindings: bindings, migPrincipals: principals,
      migTenantAuthorizationPolicies: policies, migTenantAuthorityConfigs: configs,
      tenantRoles: roles, migAuditLog: audit } = await import("@shared/schema");
    const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
    const contains = (values: unknown, id: string) => strings(values).some(value => value === "*" || value === id);
    await db.transaction(async tx => {
      await tx.execute(sql`SET LOCAL lock_timeout = '5s'`);
      await tx.execute(sql`SET LOCAL statement_timeout = '15s'`);
      const [candidate] = await tx.select().from(candidates).where(and(eq(candidates.tenantId, input.tenantId),
        eq(candidates.candidateId, input.candidateId))).for("update");
      if (!candidate || candidate.clientClass !== "MCP" || !candidate.principalId ||
          !["registered", "trusted"].includes(candidate.state)) throw new Error("MIG_CONNECTION_PERMISSIONS_CONFLICT");
      const [principal] = await tx.select().from(principals).where(and(eq(principals.tenantId, input.tenantId),
        eq(principals.principalId, candidate.principalId))).for("update");
      const [active] = await tx.select().from(entitlements).where(and(eq(entitlements.tenantId, input.tenantId),
        eq(entitlements.principalId, candidate.principalId), eq(entitlements.status, "active"))).for("update");
      if (principal?.status !== "active" || principal.subjectRef?.startsWith("host-operator:") ||
          !active || active.entitlementId !== input.expectedEntitlementId) throw new Error("MIG_CONNECTION_PERMISSIONS_CONFLICT");
      const activeClients = await tx.select().from(clients).where(and(eq(clients.tenantId, input.tenantId),
        eq(clients.componentId, candidate.componentId), eq(clients.status, "active"))).for("update");
      if (activeClients.length !== 1 || activeClients[0].principalId !== candidate.principalId) throw new Error("MIG_CONNECTION_PERMISSIONS_CONFLICT");
      const client = activeClients[0];
      const siblings = await tx.select({ id: clients.id }).from(clients).where(and(eq(clients.tenantId, input.tenantId),
        eq(clients.principalId, candidate.principalId), eq(clients.status, "active"))).for("update");
      if (siblings.length !== 1) throw new Error("MIG_CONNECTION_SHARED_PRINCIPAL_NOT_EDITABLE");
      const [binding] = await tx.select().from(bindings).where(and(eq(bindings.tenantId, input.tenantId),
        eq(bindings.credentialRef, `mig-key:${client.credentialHash}`), eq(bindings.status, "active"))).for("update");
      const [policy] = await tx.select().from(policies).where(and(eq(policies.tenantId, input.tenantId),
        eq(policies.status, "active"))).orderBy(desc(policies.createdAt)).for("share");
      const [config] = await tx.select().from(configs).where(and(eq(configs.tenantId, input.tenantId),
        eq(configs.status, "active"))).orderBy(desc(configs.createdAt), desc(configs.id)).for("share");
      if (!binding || binding.principalId !== candidate.principalId || binding.expiresAt && binding.expiresAt <= new Date() ||
          !policy || config?.authorityProvider !== "mig_native" || config.executionFabric !== "mig_managed" ||
          config.deploymentMode !== "full_control_plane") throw new Error("MIG_CONNECTION_PERMISSIONS_NOT_EDITABLE");
      const offered = (candidate.target as any)?.credential_authority?.assigned?.allowed_intents;
      if (input.intentIds.some(id => ![active.intentIds, binding.allowedIntents, policy.intentIds, offered]
        .every(ceiling => contains(ceiling, id)))) throw new Error("MIG_CONNECTION_PERMISSIONS_OUTSIDE_CEILING");
      const catalog = await tx.select().from(roles).where(eq(roles.tenantId, input.tenantId)).for("share");
      if (input.assignedRoles.some(role => !catalog.some(option => option.key === role) && !strings(active.assignedRoles).includes(role))) {
        throw new Error("MIG_CONNECTION_PERMISSIONS_OUTSIDE_CEILING");
      }
      if (Array.isArray(policy.staticSodConflicts) && policy.staticSodConflicts.some(pair =>
        Array.isArray(pair) && pair.length === 2 && pair.every(role => input.assignedRoles.includes(role)))) {
        throw new Error("MIG_STATIC_SOD_ASSIGNMENT_CONFLICT");
      }
      const successorId = `mig_entitlement_${randomUUID()}`;
      await tx.update(entitlements).set({ status: "superseded" }).where(eq(entitlements.id, active.id));
      await tx.insert(entitlements).values({
        entitlementId: successorId, tenantId: input.tenantId, principalId: candidate.principalId,
        capabilityIds: active.capabilityIds, domainIds: active.domainIds, resourceScopes: active.resourceScopes,
        intentIds: input.intentIds, assignedRoles: input.assignedRoles, status: "active",
      });
      await tx.insert(audit).values({
        eventId: `mig_permissions_${randomUUID()}`, eventType: "mcp.permissions_updated", decision: "allow",
        tenantId: input.tenantId, agentId: input.actorId, policyDecision: "native_scoped_successor",
        reason: JSON.stringify({ candidate_id: input.candidateId, previous_entitlement_id: active.entitlementId,
          entitlement_id: successorId, allowed_intents: input.intentIds, assigned_roles: input.assignedRoles }),
      });
    });
  }

async listMigToolOverrides(mcpServerId: string, tenantId: string): Promise<import("@shared/schema").MigToolOverride[]> {
    const { migToolOverrides } = await import("@shared/schema");
    return db.select().from(migToolOverrides)
      .where(and(eq(migToolOverrides.mcpServerId, mcpServerId), eq(migToolOverrides.tenantId, tenantId)));
  }

async createMs5Report(data: import("@shared/schema").InsertMigSecurityReport): Promise<import("@shared/schema").MigSecurityReport> {
    const { migSecurityReports } = await import("@shared/schema");
    const [row] = await db.insert(migSecurityReports).values(data).returning();
    return row;
  }

async createMs5Findings(data: import("@shared/schema").InsertMigSecurityFinding[]): Promise<import("@shared/schema").MigSecurityFinding[]> {
    if (data.length === 0) return [];
    const { migSecurityFindings } = await import("@shared/schema");
    return db.insert(migSecurityFindings).values(data).returning();
  }

async upsertMigGeneratedTests(mcpServerId: string, tenantId: string, tests: import("@shared/schema").InsertMigGeneratedTest[]): Promise<void> {
    if (tests.length === 0) return;
    const { migGeneratedTests } = await import("@shared/schema");
    await db.delete(migGeneratedTests).where(and(
      eq(migGeneratedTests.mcpServerId, mcpServerId),
      eq(migGeneratedTests.tenantId, tenantId),
    ));
    await db.insert(migGeneratedTests).values(tests);
  }

async createMigPatch(data: import("@shared/schema").InsertMigPatch): Promise<import("@shared/schema").MigPatch> {
    const { migPatches } = await import("@shared/schema");
    const [row] = await db.insert(migPatches).values(data).returning();
    return row;
  }

async getLatestMs5Report(mcpServerId: string, tenantId: string): Promise<import("@shared/schema").MigSecurityReport | undefined> {
    const { migSecurityReports } = await import("@shared/schema");
    const [row] = await db.select().from(migSecurityReports)
      .where(and(eq(migSecurityReports.mcpServerId, mcpServerId), eq(migSecurityReports.tenantId, tenantId)))
      .orderBy(desc(migSecurityReports.createdAt))
      .limit(1);
    return row;
  }

async listMs5Reports(mcpServerId: string, tenantId: string, limit = 20, offset = 0): Promise<import("@shared/schema").MigSecurityReport[]> {
    const { migSecurityReports } = await import("@shared/schema");
    return db.select().from(migSecurityReports)
      .where(and(eq(migSecurityReports.mcpServerId, mcpServerId), eq(migSecurityReports.tenantId, tenantId)))
      .orderBy(desc(migSecurityReports.createdAt))
      .limit(limit)
      .offset(offset);
  }

async listMs5Findings(mcpServerId: string, tenantId: string, filters?: { severity?: string; layer?: string; acknowledged?: boolean }): Promise<import("@shared/schema").MigSecurityFinding[]> {
    const { migSecurityFindings } = await import("@shared/schema");
    const conditions: any[] = [eq(migSecurityFindings.mcpServerId, mcpServerId), eq(migSecurityFindings.tenantId, tenantId)];
    if (filters?.severity) conditions.push(eq(migSecurityFindings.severity, filters.severity));
    if (filters?.layer) conditions.push(eq(migSecurityFindings.layer, filters.layer));
    if (filters?.acknowledged !== undefined) conditions.push(eq(migSecurityFindings.acknowledged, filters.acknowledged));
    return db.select().from(migSecurityFindings)
      .where(and(...conditions as [any, ...any[]]))
      .orderBy(desc(migSecurityFindings.createdAt));
  }

async acknowledgeMs5Finding(id: number, acknowledgedBy: string, tenantId: string, mcpServerId: string): Promise<import("@shared/schema").MigSecurityFinding | undefined> {
    const { migSecurityFindings } = await import("@shared/schema");
    const [row] = await db.update(migSecurityFindings)
      .set({ acknowledged: true, acknowledgedAt: new Date(), acknowledgedBy })
      .where(and(
        eq(migSecurityFindings.id, id),
        eq(migSecurityFindings.tenantId, tenantId),
        eq(migSecurityFindings.mcpServerId, mcpServerId),
      ))
      .returning();
    return row;
  }

async getMigPatch(id: number, tenantId: string): Promise<import("@shared/schema").MigPatch | undefined> {
    const { migPatches } = await import("@shared/schema");
    const [row] = await db.select().from(migPatches)
      .where(and(eq(migPatches.id, id), eq(migPatches.tenantId, tenantId)));
    return row;
  }

async createMigToolOverride(data: import("@shared/schema").InsertMigToolOverride): Promise<import("@shared/schema").MigToolOverride> {
    const { migToolOverrides } = await import("@shared/schema");
    const [row] = await db.insert(migToolOverrides).values(data).returning();
    return row;
  }

async updateMigPatchStatus(id: number, status: string, tenantId: string, reviewedAt?: Date, mergedAt?: Date): Promise<import("@shared/schema").MigPatch | undefined> {
    const { migPatches } = await import("@shared/schema");
    const updates: Record<string, unknown> = { status };
    if (reviewedAt) updates.reviewedAt = reviewedAt;
    if (mergedAt) updates.mergedAt = mergedAt;
    const [row] = await db.update(migPatches)
      .set(updates)
      .where(and(eq(migPatches.id, id), eq(migPatches.tenantId, tenantId)))
      .returning();
    return row;
  }

async listMigGeneratedTests(mcpServerId: string, capabilityName: string, tenantId: string): Promise<import("@shared/schema").MigGeneratedTest[]> {
    const { migGeneratedTests } = await import("@shared/schema");
    return db.select().from(migGeneratedTests)
      .where(and(
        eq(migGeneratedTests.mcpServerId, mcpServerId),
        eq(migGeneratedTests.capabilityName, capabilityName),
        eq(migGeneratedTests.tenantId, tenantId),
      ))
      .orderBy(desc(migGeneratedTests.generatedAt));
  }

async createMigPatchValidation(data: import("@shared/schema").InsertMigPatchValidation): Promise<import("@shared/schema").MigPatchValidation> {
    const { migPatchValidations } = await import("@shared/schema");
    const [row] = await db.insert(migPatchValidations).values(data).returning();
    return row;
  }

async getMigObservationProjection(tenantId: string, observedJourneyId: string): Promise<Record<string, unknown>> {
    const { migObservedJourneyVersions, migObservationFactualEdges, migObservationFindings, migObservationStructuralDecisions, migObservationProofReferences, migObservationCustomerOutcomes } = await import("@shared/schema");
    const versions = await this.listMigObservedJourneyVersions(tenantId, observedJourneyId);
    const ids = versions.map(v => v.journeyVersionId);
    if (!ids.length) return { versions: [], edges: [], findings: [], decisions: [], proofs: [], outcomes: [] };
    const [edges, findings, decisions, outcomes] = await Promise.all([
      db.select().from(migObservationFactualEdges).where(and(eq(migObservationFactualEdges.tenantId, tenantId), inArray(migObservationFactualEdges.journeyVersionId, ids))),
      db.select().from(migObservationFindings).where(and(eq(migObservationFindings.tenantId, tenantId), inArray(migObservationFindings.journeyVersionId, ids))),
      db.select().from(migObservationStructuralDecisions).where(and(eq(migObservationStructuralDecisions.tenantId, tenantId), inArray(migObservationStructuralDecisions.journeyVersionId, ids))),
      db.select().from(migObservationCustomerOutcomes).where(and(eq(migObservationCustomerOutcomes.tenantId, tenantId), inArray(migObservationCustomerOutcomes.journeyVersionId, ids))),
    ]);
    const decisionIds = decisions.map(d => d.observationStructuralDecisionId);
    const proofs = decisionIds.length ? await db.select().from(migObservationProofReferences).where(and(eq(migObservationProofReferences.tenantId, tenantId), inArray(migObservationProofReferences.observationStructuralDecisionId, decisionIds))) : [];
    return { versions, edges, findings, decisions, proofs, outcomes };
  }

async getMigObservationExperienceProjection(tenantId: string): Promise<Record<string, unknown>> {
    const {
      migObservationEvents, migObservationCorrelations, migObservedJourneyVersions,
      migObservationFactualEdges, migObservationFindings, migObservationStructuralDecisions,
      migObservationProofReferences, migObservationCustomerOutcomes,
    } = await import("@shared/schema");
    const [events, correlations, versions, edges, findings, decisions, proofs, outcomes] = await Promise.all([
      db.select().from(migObservationEvents).where(eq(migObservationEvents.tenantId, tenantId)),
      db.select().from(migObservationCorrelations).where(eq(migObservationCorrelations.tenantId, tenantId)),
      db.select().from(migObservedJourneyVersions).where(eq(migObservedJourneyVersions.tenantId, tenantId)),
      db.select().from(migObservationFactualEdges).where(eq(migObservationFactualEdges.tenantId, tenantId)),
      db.select().from(migObservationFindings).where(eq(migObservationFindings.tenantId, tenantId)),
      db.select().from(migObservationStructuralDecisions).where(eq(migObservationStructuralDecisions.tenantId, tenantId)),
      db.select().from(migObservationProofReferences).where(eq(migObservationProofReferences.tenantId, tenantId)),
      db.select().from(migObservationCustomerOutcomes).where(eq(migObservationCustomerOutcomes.tenantId, tenantId)),
    ]);
    const latest = new Map<string, typeof versions[number]>();
    for (const version of versions) {
      const prior = latest.get(version.observedJourneyId);
      if (!prior || version.version > prior.version) latest.set(version.observedJourneyId, version);
    }
    const eventById = new Map(events.map(event => [event.observationEventId, event]));
    const proofDecisionIds = new Set(proofs.map(proof => proof.observationStructuralDecisionId));
    const journeys = [...latest.values()].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).map(version => {
      const snapshot = version.snapshot as any;
      const journeyFindings = findings.filter(finding => finding.journeyVersionId === version.journeyVersionId);
      const versionDecisions = decisions.filter(item => item.journeyVersionId === version.journeyVersionId)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || b.id - a.id);
      const eligibleDecision = versionDecisions.find(item =>
        proofDecisionIds.has(item.observationStructuralDecisionId) &&
        journeyFindings.some(finding => finding.structuralDecisionRef === item.observationStructuralDecisionId));
      const hasIncompleteEvaluation = versionDecisions.length > 0 && !eligibleDecision;
      const journeyEdges = edges.filter(edge => (snapshot.factual_edge_refs ?? []).includes(edge.factualEdgeId));
      const journeyEvents = (snapshot.event_refs ?? []).map((id: string) => eventById.get(id)).filter(Boolean);
      const evidenceUnavailable = !["VERIFIED", "ATTESTED"].includes(snapshot.evidence_quality) ||
        (snapshot.factual_edge_refs ?? []).some((id: string) => !journeyEdges.some(edge => edge.factualEdgeId === id));
      const wouldHaveStopped = eligibleDecision &&
        ["BLOCK", "REQUIRE_APPROVAL"].includes(eligibleDecision.enforcement);
      const status = evidenceUnavailable || hasIncompleteEvaluation ? "insufficient_evidence" :
        wouldHaveStopped ? "would_have_blocked" :
        eligibleDecision ? "governed" : "observed";
      return {
        journey_id: version.observedJourneyId, journey_version_id: version.journeyVersionId,
        origin: journeyEvents[0]?.sourceKind ?? "Unavailable — source not supplied",
        intent: "Unavailable — observation does not establish intent",
        agent: "Unavailable — observation does not establish identity",
        mcp_path: snapshot.mcp_refs ?? [], accumulated_capabilities: snapshot.capabilities ?? [],
        resources: snapshot.resource_refs ?? [], evidence_quality: snapshot.evidence_quality ?? "UNKNOWN",
        translated_structural_state: eligibleDecision?.reason ?? (evidenceUnavailable || hasIncompleteEvaluation ? "Structural interpretation withheld" : "Not yet evaluated"),
        temperature: wouldHaveStopped ? "Elevated" : eligibleDecision ? "Reviewed" : "Unknown",
        status, correlation_status: snapshot.correlation_status,
        factual_graph: {
          nodes: [...new Set(journeyEdges.flatMap(row => {
            const edge = row.edge as any; return [edge.from_ref, edge.to_ref];
          }))].map(id => ({ id, evidence_class: "observed_fact" })),
          edges: journeyEdges.map(row => ({ id: row.factualEdgeId, ...(row.edge as object), evidence_class: "observed_fact" })),
        },
        consequence_overlay: eligibleDecision ? {
          condition_ref: eligibleDecision.observationStructuralDecisionId,
          state: wouldHaveStopped ? "compositionally_consequential" : "reviewed",
          explanation: eligibleDecision.reason, would_have_blocked: Boolean(wouldHaveStopped),
          proof_state: "available",
        } : { condition_ref: null, state: evidenceUnavailable || hasIncompleteEvaluation ? "withheld" : "not_evaluated",
          explanation: evidenceUnavailable || hasIncompleteEvaluation ? "Evidence or decision proof is insufficient for structural interpretation." : "No structural evaluation has been recorded.",
          would_have_blocked: "UNKNOWN", proof_state: "unavailable" },
        feedback: outcomes.filter(outcome => outcome.journeyVersionId === version.journeyVersionId),
        created_at: version.createdAt,
      };
    });
    const ids = (predicate: (journey: any) => boolean) => journeys.filter(predicate).map((journey: any) => journey.journey_id);
    const uniqueAgents = new Set(events.map(event => (event.envelope as any)?.agent_ref).filter(Boolean));
    const uniqueMcps = new Set(journeys.flatMap((journey: any) => journey.mcp_path));
    const uniqueCapabilities = new Set(journeys.flatMap((journey: any) => journey.accumulated_capabilities.map((cap: any) => cap.capability_id)));
    const metric = (value: number, journeyIds: string[]) => ({ value, journey_ids: journeyIds });
    return {
      operating_mode: "observe",
      mode_explanation: "Activity is visible for review. MIG does not affect external execution in Observe mode.",
      evidence_freshness: events.length ? "available" : "unknown",
      summary: {
        agents: metric(uniqueAgents.size, ids(journey => {
          const version = latest.get(journey.journey_id);
          const snapshot = version?.snapshot as any;
          return (snapshot?.event_refs ?? []).some((id: string) => Boolean((eventById.get(id)?.envelope as any)?.agent_ref));
        })),
        mcps: metric(uniqueMcps.size, ids(journey => journey.mcp_path.length > 0)),
        capabilities: metric(uniqueCapabilities.size, ids(journey => journey.accumulated_capabilities.length > 0)),
        journeys: metric(journeys.length, journeys.map((journey: any) => journey.journey_id)),
        cross_mcp_journeys: metric(ids(journey => journey.mcp_path.length > 1).length, ids(journey => journey.mcp_path.length > 1)),
        consequential_paths: metric(ids(journey => journey.consequence_overlay.state === "compositionally_consequential").length, ids(journey => journey.consequence_overlay.state === "compositionally_consequential")),
        would_have_blocked: metric(ids(journey => journey.status === "would_have_blocked").length, ids(journey => journey.status === "would_have_blocked")),
        insufficient_evidence: metric(
          ids(journey => journey.status === "insufficient_evidence").length + correlations.filter(row => row.status !== "CORRELATED").length,
          ids(journey => journey.status === "insufficient_evidence"),
        ),
      },
      journeys,
      uncorrelated_observations: correlations.filter(row => row.status !== "CORRELATED").map(row => ({
        observation_event_id: row.observationEventId, correlation_status: row.status,
      })),
    };
  }

async listMigAuthoritySnapshots(
    tenantId: string,
    options: { limit?: number; provider?: string; providerTenantRef?: string | null } = {},
  ): Promise<import("@shared/schema").MigAuthoritySnapshot[]> {
    const { migAuthoritySnapshots } = await import("@shared/schema");
    const predicates = [eq(migAuthoritySnapshots.tenantId, tenantId)];
    if (options.provider) predicates.push(eq(migAuthoritySnapshots.provider, options.provider));
    if (options.providerTenantRef !== undefined && options.providerTenantRef !== null) {
      predicates.push(eq(migAuthoritySnapshots.providerTenantRef, options.providerTenantRef));
    }
    return db.select().from(migAuthoritySnapshots)
      .where(and(...predicates))
      .orderBy(desc(migAuthoritySnapshots.observedAt), desc(migAuthoritySnapshots.id))
      .limit(Math.max(1, Math.min(options.limit ?? 100, 1000)));
  }

async listMigAuthorizationManifests(filters: { tenantId: string; requestCorrelationId?: string; limit?: number }): Promise<import("@shared/schema").MigAuthorizationManifest[]> {
    const { migAuthorizationManifests } = await import("@shared/schema");
    const { desc, and: andOp } = await import("drizzle-orm");
    const conditions = [eq(migAuthorizationManifests.tenantId, filters.tenantId)];
    if (filters.requestCorrelationId) conditions.push(eq(migAuthorizationManifests.requestCorrelationId, filters.requestCorrelationId));
    return db.select().from(migAuthorizationManifests)
      .where(andOp(...conditions))
      .orderBy(desc(migAuthorizationManifests.createdAt))
      .limit(filters.limit ?? 200);
  }

async listMigJourneys(tenantId: string, limit = 100): Promise<import("@shared/schema").MigJourney[]> {
    const { migJourneys } = await import("@shared/schema");
    return db.select().from(migJourneys)
      .where(eq(migJourneys.tenantId, tenantId))
      .orderBy(desc(migJourneys.createdAt), desc(migJourneys.id))
      .limit(Math.max(1, Math.min(limit, 500)));
  }

async createMigTenantAuthorityConfig(data: import("@shared/schema").InsertMigTenantAuthorityConfig): Promise<import("@shared/schema").MigTenantAuthorityConfig> {
    const maximumAge = data.maximumSnapshotAgeSeconds ?? 300;
    if (!Number.isInteger(maximumAge) || maximumAge <= 0 || maximumAge > 86_400) {
      throw new Error("MIG_AUTHORITY_SNAPSHOT_AGE_INVALID");
    }
    const valid =
      data.deploymentMode === "full_control_plane" && data.authorityProvider === "mig_native" && data.executionFabric === "mig_managed" ||
      data.deploymentMode === "enterprise_intelligence_plane" && data.authorityProvider === "microsoft_entra" &&
        (data.executionFabric === "mig_managed" || data.executionFabric === "enterprise_managed");
    if (!valid) throw new Error("MIG_AUTHORITY_CONFIGURATION_UNSUPPORTED");
    if (data.authorityProvider === "microsoft_entra" && !data.providerTenantRef) {
      throw new Error("MIG_AUTHORITY_PROVIDER_TENANT_REQUIRED");
    }
    const { migTenantAuthorityConfigs } = await import("@shared/schema");
    const [row] = await db.insert(migTenantAuthorityConfigs).values(data).returning();
    return row;
  }

async getMcpApiKeyById(id: number, tenantId: string): Promise<import("@shared/schema").McpApiKey | undefined> {
    const { mcpApiKeys } = await import("@shared/schema");
    const [row] = await db
      .select()
      .from(mcpApiKeys)
      .where(and(eq(mcpApiKeys.id, id), eq(mcpApiKeys.tenantId, tenantId)));
    return row;
  }

async updateMcpApiKeyEnterprise(id: number, tenantId: string, data: Partial<Pick<import("@shared/schema").McpApiKey, "displayName" | "principalId" | "migAgentId" | "allowedDomains" | "allowedIntents" | "allowedTools" | "preset" | "semanticScopes" | "effectiveScopes" | "resourceConstraints" | "environmentConstraints" | "networkConstraints" | "expiresAt" | "reviewRequired" | "reviewState">>): Promise<import("@shared/schema").McpApiKey | undefined> {
    const { mcpApiKeys } = await import("@shared/schema");
    const [row] = await db.update(mcpApiKeys).set(data).where(and(eq(mcpApiKeys.id, id), eq(mcpApiKeys.tenantId, tenantId))).returning();
    return row;
  }

async listMigTickets(agentId?: string): Promise<import("@shared/schema").MigTicket[]> {
    const { migTickets } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    const query = db.select().from(migTickets);
    if (agentId) {
      return query.where(eq(migTickets.agentId, agentId)).orderBy(desc(migTickets.issuedAt));
    }
    return query.orderBy(desc(migTickets.issuedAt));
  }

async listMcpApiKeys(tenantId: string): Promise<import("@shared/schema").McpApiKey[]> {
    const { mcpApiKeys } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    return db
      .select()
      .from(mcpApiKeys)
      .where(eq(mcpApiKeys.tenantId, tenantId))
      .orderBy(desc(mcpApiKeys.createdAt));
  }

async getOrganization(id: string): Promise<Organization | undefined> { return (await ownerCall<any[]>("enterprise.listOrganizations", [])).find(org => org.id === id); }

async listMigRegistryHistory(tenantId: string, candidateId: string): Promise<import("@shared/schema").MigRegistryHistory[]> {
    const { migRegistryHistory } = await import("@shared/schema");
    const { asc } = await import("drizzle-orm");
    return db.select().from(migRegistryHistory).where(and(eq(migRegistryHistory.tenantId, tenantId), eq(migRegistryHistory.candidateId, candidateId))).orderBy(asc(migRegistryHistory.createdAt), asc(migRegistryHistory.id));
  }

async listAllMigGeneratedTests(mcpServerId: string, tenantId: string): Promise<import("@shared/schema").MigGeneratedTest[]> {
    const { migGeneratedTests } = await import("@shared/schema");
    return db.select().from(migGeneratedTests)
      .where(and(
        eq(migGeneratedTests.mcpServerId, mcpServerId),
        eq(migGeneratedTests.tenantId, tenantId),
      ))
      .orderBy(desc(migGeneratedTests.generatedAt));
  }

async listMigPatches(mcpServerId: string, tenantId: string, status?: string): Promise<import("@shared/schema").MigPatch[]> {
    const { migPatches } = await import("@shared/schema");
    const conditions: any[] = [eq(migPatches.mcpServerId, mcpServerId), eq(migPatches.tenantId, tenantId)];
    if (status) conditions.push(eq(migPatches.status, status));
    return db.select().from(migPatches)
      .where(and(...conditions as [any, ...any[]]))
      .orderBy(desc(migPatches.generatedAt));
  }

async getMigPatchValidation(patchId: number, tenantId: string): Promise<import("@shared/schema").MigPatchValidation | undefined> {
    const { migPatchValidations } = await import("@shared/schema");
    const [row] = await db.select().from(migPatchValidations)
      .where(and(eq(migPatchValidations.patchId, patchId), eq(migPatchValidations.tenantId, tenantId)))
      .orderBy(desc(migPatchValidations.createdAt))
      .limit(1);
    return row;
  }

async listRecentMerges(mcpServerId: string, tenantId: string, limit = 20): Promise<{ patch: import("@shared/schema").MigPatch; validation: import("@shared/schema").MigPatchValidation | null }[]> {
    const { migPatches, migPatchValidations } = await import("@shared/schema");
    const patches = await db.select().from(migPatches)
      .where(and(
        eq(migPatches.mcpServerId, mcpServerId),
        eq(migPatches.tenantId, tenantId),
        eq(migPatches.status, "MERGED"),
      ))
      .orderBy(desc(migPatches.mergedAt))
      .limit(limit);
    const results: { patch: import("@shared/schema").MigPatch; validation: import("@shared/schema").MigPatchValidation | null }[] = [];
    for (const patch of patches) {
      const [validation] = await db.select().from(migPatchValidations)
        .where(and(eq(migPatchValidations.patchId, patch.id), eq(migPatchValidations.tenantId, tenantId)))
        .orderBy(desc(migPatchValidations.createdAt))
        .limit(1);
      results.push({ patch, validation: validation ?? null });
    }
    return results;
  }

async getAllOrganizations(): Promise<Organization[]> { return ownerCall("enterprise.listOrganizations", []); }

async createMcpApiKey(
    tenantId: string,
    displayName: string,
    keyHash: string,
    keyPrefix: string,
    classification: import("@shared/schema").McpKeyClassification,
    createdBy?: string,
    allowedTools?: string[] | null,
    enterprise?: Partial<Pick<import("@shared/schema").McpApiKey, "principalId" | "migAgentId" | "allowedDomains" | "allowedIntents" | "preset" | "semanticScopes" | "effectiveScopes" | "resourceConstraints" | "environmentConstraints" | "networkConstraints" | "expiresAt" | "reviewRequired" | "reviewState">>,
  ): Promise<import("@shared/schema").McpApiKey> {
    const { mcpApiKeys } = await import("@shared/schema");
    const [row] = await db
      .insert(mcpApiKeys)
      .values({
        tenantId,
        displayName,
        keyHash,
        keyPrefix,
        classification,
        createdBy: createdBy ?? null,
        status: "active",
        allowedTools: allowedTools && allowedTools.length > 0 ? allowedTools : null,
        ...enterprise,
      })
      .returning();
    return row;
  }

async setMcpApiKeyStatus(id: number, tenantId: string, status: import("@shared/schema").McpKeyStatus, expiresAt?: Date | null): Promise<import("@shared/schema").McpApiKey | undefined> {
    const { mcpApiKeys } = await import("@shared/schema");
    const [row] = await db.update(mcpApiKeys).set({
      status,
      expiresAt: expiresAt === undefined ? undefined : expiresAt,
      revokedAt: status === "revoked" ? new Date() : null,
    }).where(and(eq(mcpApiKeys.id, id), eq(mcpApiKeys.tenantId, tenantId))).returning();
    return row;
  }

async recordMcpKeyAuditEvent(record: import("@shared/schema").InsertMcpKeyAuditLog): Promise<import("@shared/schema").McpKeyAuditLogRow> {
    const { mcpKeyAuditLog } = await import("@shared/schema");
    const [row] = await db.insert(mcpKeyAuditLog).values(record).returning();
    return row;
  }

async rotateMcpApiKey(
    id: number,
    tenantId: string,
    gracePeriodDays: number,
    newKeyHash: string,
    newKeyPrefix: string,
    createdBy?: string,
  ): Promise<{ oldKey: import("@shared/schema").McpApiKey; newKey: import("@shared/schema").McpApiKey } | undefined> {
    const { mcpApiKeys } = await import("@shared/schema");

    const [oldKey] = await db
      .select()
      .from(mcpApiKeys)
      .where(and(eq(mcpApiKeys.id, id), eq(mcpApiKeys.tenantId, tenantId)));
    if (!oldKey || oldKey.status !== "active") {
      return undefined;
    }

    const [newKey] = await db
      .insert(mcpApiKeys)
      .values({
        tenantId,
        displayName: oldKey.displayName,
        keyHash: newKeyHash,
        keyPrefix: newKeyPrefix,
        classification: oldKey.classification,
        createdBy: createdBy ?? oldKey.createdBy ?? null,
        status: "active",
        allowedTools: oldKey.allowedTools ?? null,
        allowedIntents: oldKey.allowedIntents ?? null,
        principalId: oldKey.principalId ?? null,
        allowedDomains: oldKey.allowedDomains ?? null,
        semanticScopes: oldKey.semanticScopes,
        effectiveScopes: oldKey.effectiveScopes,
        preset: oldKey.preset ?? null,
        resourceConstraints: oldKey.resourceConstraints,
        environmentConstraints: oldKey.environmentConstraints,
        networkConstraints: oldKey.networkConstraints,
        reviewRequired: oldKey.reviewRequired,
        reviewState: oldKey.reviewState,
        expiresAt: oldKey.expiresAt,
        rotatedFromId: oldKey.id,
      })
      .returning();

    const graceExpiry = new Date(Date.now() + Math.max(0, gracePeriodDays) * 24 * 60 * 60 * 1000);
    const expiresAt = oldKey.expiresAt && oldKey.expiresAt.getTime() < graceExpiry.getTime() ? oldKey.expiresAt : graceExpiry;
    const [updatedOldKey] = await db
      .update(mcpApiKeys)
      .set({ status: "pending_revocation", expiresAt, rotatedToId: newKey.id })
      .where(and(eq(mcpApiKeys.id, oldKey.id), eq(mcpApiKeys.tenantId, tenantId)))
      .returning();

    return { oldKey: updatedOldKey, newKey };
  }

async updateMcpApiKeyIntents(id: number, tenantId: string, intents: string[]): Promise<import("@shared/schema").McpApiKey | undefined> {
    const { mcpApiKeys } = await import("@shared/schema");
    const [row] = await db
      .update(mcpApiKeys)
      .set({ allowedIntents: intents.length > 0 ? intents : null })
      .where(and(eq(mcpApiKeys.id, id), eq(mcpApiKeys.tenantId, tenantId)))
      .returning();
    return row;
  }

async revokeMcpApiKey(id: number, tenantId: string): Promise<import("@shared/schema").McpApiKey | undefined> {
    const { mcpApiKeys } = await import("@shared/schema");
    const [row] = await db
      .update(mcpApiKeys)
      .set({ status: "revoked", revokedAt: new Date() })
      .where(and(eq(mcpApiKeys.id, id), eq(mcpApiKeys.tenantId, tenantId)))
      .returning();
    return row;
  }

async listMcpToolInvocations(tenantId: string, limit = 200, adamOutcomeFilter?: string | null, apiKeyId?: number | null): Promise<import("@shared/schema").McpToolInvocation[]> {
    const { mcpToolInvocations } = await import("@shared/schema");
    const { desc, and } = await import("drizzle-orm");
    const conditions: ReturnType<typeof eq>[] = [eq(mcpToolInvocations.tenantId, tenantId)];
    if (adamOutcomeFilter) conditions.push(eq(mcpToolInvocations.adamOutcome, adamOutcomeFilter));
    if (apiKeyId != null) conditions.push(eq(mcpToolInvocations.apiKeyId, apiKeyId));
    return db
      .select()
      .from(mcpToolInvocations)
      .where(conditions.length === 1 ? conditions[0] : and(...conditions))
      .orderBy(desc(mcpToolInvocations.createdAt))
      .limit(limit);
  }

async getMcpBripeOutputManifest(
    opts: import("../shared/protocol/server/mcp/bripe-output-manifest-query").McpOutputManifestQueryOptions,
  ): Promise<import("../shared/protocol/server/mcp/bripe-output-manifest-query").McpOutputManifestEntry[]> {
    const { buildMcpOutputManifestQuery } = await import("./mcp/bripe-output-manifest-query");
    return buildMcpOutputManifestQuery(opts);
  }

async sweepExpiredMcpApiKeys(): Promise<number> {
    const { mcpApiKeys } = await import("@shared/schema");
    const rows = await db
      .update(mcpApiKeys)
      .set({ status: "revoked", revokedAt: new Date() })
      .where(and(eq(mcpApiKeys.status, "pending_revocation"), lte(mcpApiKeys.expiresAt, new Date())))
      .returning({ id: mcpApiKeys.id, tenantId: mcpApiKeys.tenantId });

    for (const row of rows) {
      await this.recordMcpKeyAuditEvent({
        tenantId: row.tenantId,
        apiKeyId: row.id,
        action: "auto_revoked",
        detail: "Rotation grace period elapsed",
      });
    }
    return rows.length;
  }

async listMcpKeyAuditLog(tenantId: string, limit = 200): Promise<import("@shared/schema").McpKeyAuditLogRow[]> {
    const { mcpKeyAuditLog } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    return db
      .select()
      .from(mcpKeyAuditLog)
      .where(eq(mcpKeyAuditLog.tenantId, tenantId))
      .orderBy(desc(mcpKeyAuditLog.createdAt))
      .limit(limit);
  }

async listEntraTenantMappings(): Promise<import("@shared/schema").EntraTenantMapping[]> {
    const { entraTenantMappings } = await import("@shared/schema");
    const { asc } = await import("drizzle-orm");
    return db.select().from(entraTenantMappings).orderBy(asc(entraTenantMappings.createdAt));
  }

async upsertEntraTenantMapping(
    entraTenantId: string,
    bcentriskTenantId: string,
    displayLabel?: string,
    createdBy?: string,
  ): Promise<import("@shared/schema").EntraTenantMapping> {
    const { entraTenantMappings } = await import("@shared/schema");
    const now = new Date();
    const [row] = await db
      .insert(entraTenantMappings)
      .values({ entraTenantId, bcentriskTenantId, displayLabel: displayLabel ?? null, createdBy: createdBy ?? null, updatedAt: now })
      .onConflictDoUpdate({
        target: entraTenantMappings.entraTenantId,
        set: { bcentriskTenantId, displayLabel: displayLabel ?? null, updatedAt: now },
      })
      .returning();
    return row;
  }

async deleteEntraTenantMapping(id: number): Promise<boolean> {
    const { entraTenantMappings } = await import("@shared/schema");
    const rows = await db.delete(entraTenantMappings).where(eq(entraTenantMappings.id, id)).returning({ id: entraTenantMappings.id });
    return rows.length > 0;
  }

private async setMigClientAuthorityStatus(tenantId: string, componentId: string, status: "revoked" | "suspended", principalId?: string) {
    const { migClients, migCredentialBindings } = await import("@shared/schema");
    return db.transaction(async tx => {
      const revokedAt = new Date();
      const rows = await tx.update(migClients).set({ status, ...(status === "revoked" ? { revokedAt } : {}) }).where(and(
        eq(migClients.tenantId, tenantId), eq(migClients.componentId, componentId),
        status === "revoked" ? inArray(migClients.status, ["active", "suspended"]) : eq(migClients.status, "active"),
        ...(principalId ? [eq(migClients.principalId, principalId)] : []),
      )).returning();
      if (rows.length) await tx.update(migCredentialBindings)
        .set({ status, ...(status === "revoked" ? { revokedAt } : {}) })
        .where(and(eq(migCredentialBindings.tenantId, tenantId),
          inArray(migCredentialBindings.credentialRef, rows.map(row => `mig-key:${row.credentialHash}`)),
          ...(principalId ? [eq(migCredentialBindings.principalId, principalId)] : [])));
      return rows[0];
    });
  }

async listMigObservedJourneyVersions(tenantId: string, observedJourneyId: string): Promise<import("@shared/schema").MigObservedJourneyVersion[]> {
    const { migObservedJourneyVersions } = await import("@shared/schema");
    return db.select().from(migObservedJourneyVersions)
      .where(and(eq(migObservedJourneyVersions.tenantId, tenantId), eq(migObservedJourneyVersions.observedJourneyId, observedJourneyId)))
      .orderBy(migObservedJourneyVersions.version);
  }

async getEntraTenantMappingMap(): Promise<Record<string, string>> {
    const rows = await this.listEntraTenantMappings();
    const result: Record<string, string> = {};
    for (const row of rows) {
      result[row.entraTenantId] = row.bcentriskTenantId;
    }
    return result;
  }

async createMcpContractInvocationReference(data: import("@shared/schema").InsertMcpContractInvocationReference): Promise<import("@shared/schema").McpContractInvocationReference> {
    const { mcpContractInvocationReferences } = await import("@shared/schema");
    const [row] = await db.insert(mcpContractInvocationReferences).values(data).returning();
    return row;
  }

async getMcpContractAuthRelationship(relationshipId: string): Promise<import("@shared/schema").McpContractAuthRelationship | undefined> {
    const { mcpContractAuthRelationships } = await import("@shared/schema");
    const [row] = await db.select().from(mcpContractAuthRelationships).where(eq(mcpContractAuthRelationships.relationshipId, relationshipId));
    return row;
  }

async updateMcpCapabilityContract(contractId: string, patch: Partial<import("@shared/schema").InsertMcpCapabilityContract> & { status?: string; acceptedByClient?: Date | null; acceptedByServer?: Date | null }): Promise<import("@shared/schema").McpCapabilityContract | undefined> {
    const { mcpCapabilityContracts } = await import("@shared/schema");
    const [row] = await db.update(mcpCapabilityContracts).set({ ...patch, updatedAt: new Date() }).where(eq(mcpCapabilityContracts.contractId, contractId)).returning();
    return row;
  }

async getMcpCapabilityContract(contractId: string): Promise<import("@shared/schema").McpCapabilityContract | undefined> {
    const { mcpCapabilityContracts } = await import("@shared/schema");
    const [row] = await db.select().from(mcpCapabilityContracts).where(eq(mcpCapabilityContracts.contractId, contractId));
    return row;
  }

async checkMcpContractNonceUsed(nonce: string, contractId: string): Promise<boolean> {
    const { mcpContractInvocationReferences } = await import("@shared/schema");
    const { and } = await import("drizzle-orm");
    const rows = await db
      .select({ id: mcpContractInvocationReferences.id })
      .from(mcpContractInvocationReferences)
      .where(and(
        eq(mcpContractInvocationReferences.nonce, nonce),
        eq(mcpContractInvocationReferences.contractId, contractId)
      ))
      .limit(1);
    return rows.length > 0;
  }

async listMcpCapabilityContractsByClient(clientId: string, tenantId: string): Promise<import("@shared/schema").McpCapabilityContract[]> {
    const { mcpCapabilityContracts } = await import("@shared/schema");
    const { desc } = await import("drizzle-orm");
    return db.select().from(mcpCapabilityContracts).where(and(eq(mcpCapabilityContracts.clientId, clientId), eq(mcpCapabilityContracts.tenantId, tenantId), eq(mcpCapabilityContracts.status, "active"))).orderBy(desc(mcpCapabilityContracts.createdAt));
  }

async touchMcpApiKeyLastUsed(id: number): Promise<void> {
    const { mcpApiKeys } = await import("@shared/schema");
    await db
      .update(mcpApiKeys)
      .set({ lastUsedAt: new Date() })
      .where(eq(mcpApiKeys.id, id));
  }

async recordMcpToolInvocation(record: import("@shared/schema").InsertMcpToolInvocation): Promise<import("@shared/schema").McpToolInvocation> {
    const { mcpToolInvocations } = await import("@shared/schema");
    const [row] = await db.insert(mcpToolInvocations).values(record).returning();
    return row;
  }
}

export const storage = new DatabaseStorage(process.env.MIG_TENANT_ID ?? "");
export const createScopedStorage = (tenantId: string) => new DatabaseStorage(tenantId);
export { DEFAULT_TENANT_ID } from '@shared/schema';
export type IStorage = DatabaseStorage;
