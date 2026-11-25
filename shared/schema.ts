import { sql } from "drizzle-orm";

import { pgTable, text, varchar, serial, integer, timestamp, jsonb, boolean, real, uniqueIndex, index, primaryKey, check } from "drizzle-orm/pg-core";

import { createInsertSchema } from "drizzle-zod";

import { z } from "zod";

export const DEFAULT_TENANT_ID = "1001";

export const organizations = pgTable("organizations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  industry: text("industry"),
  activeFrameworks: jsonb("active_frameworks").notNull().default(sql`'[]'::jsonb`),
  profile: jsonb("profile").default(sql`'{}'::jsonb`),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export type Organization = typeof organizations.$inferSelect;

export const tenantRoles = pgTable("tenant_roles", {
  id: serial("id").primaryKey(),
  key: text("key").notNull(),
  label: text("label").notNull(),
  title: text("title").notNull(),
  icon: text("icon"),
  isSystem: boolean("is_system").notNull().default(false),
  tenantId: text("tenant_id").notNull().default(DEFAULT_TENANT_ID),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const workflowNotifications = pgTable("workflow_notifications", {
  id: serial("id").primaryKey(),
  workflowItemId: integer("workflow_item_id"),
  recipientId: text("recipient_id"),
  recipientName: text("recipient_name"),
  channel: text("channel").notNull().default("internal"),
  eventType: text("event_type").notNull(),
  message: text("message").notNull(),
  isRead: boolean("is_read").notNull().default(false),
  tenantId: text("tenant_id").notNull().default(DEFAULT_TENANT_ID),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (t) => ({
  governedDeliveryUnique: uniqueIndex("workflow_notifications_governed_delivery_uq")
    .on(t.tenantId, t.eventType, t.message)
    .where(sql`${t.channel} = 'governed_operator'`),
}));

export const MCP_KEY_CLASSIFICATIONS = ["read_only", "execution", "admin"] as const;

export type McpKeyClassification = typeof MCP_KEY_CLASSIFICATIONS[number];

export const MCP_KEY_STATUSES = ["active", "pending_revocation", "disabled", "review_required", "expired", "revoked"] as const;

export type McpKeyStatus = typeof MCP_KEY_STATUSES[number];

export const mcpApiKeys = pgTable("mcp_api_keys", {
  id: serial("id").primaryKey(),
  tenantId: varchar("tenant_id").notNull(),
  displayName: text("display_name").notNull(),
  keyHash: text("key_hash").notNull(),
  keyPrefix: varchar("key_prefix", { length: 12 }).notNull(),
  classification: varchar("classification", { length: 16 }).notNull().default("read_only"),
  status: varchar("status", { length: 24 }).notNull().default("active"),
  /**
   * Optional per-key tool allow-list. null/undefined means "all tools at or
   * below `classification`" (backward-compatible default). When present, a
   * tool must appear in this list AND pass the classification ceiling.
   */
  allowedTools: text("allowed_tools").array(),
  /**
   * Optional per-key MIG intent allow-list. null/undefined means no intent
   * restrictions beyond the key's classification ceiling. When present, the
   * key may only be used for the listed intent IDs.
   */
  allowedIntents: text("allowed_intents").array(),
  /** Canonical MIG subject; raw user/header identities are never authoritative. */
  principalId: varchar("principal_id"),
  /** Durable MIG client binding. Every usable MCP credential resolves this exact identity. */
  migAgentId: varchar("mig_agent_id"),
  /** Semantic restrictions resolved by the canonical MIG policy evaluator. */
  allowedDomains: text("allowed_domains").array(),
  semanticScopes: jsonb("semantic_scopes").notNull().default(sql`'[]'::jsonb`),
  effectiveScopes: jsonb("effective_scopes").notNull().default(sql`'[]'::jsonb`),
  preset: varchar("preset", { length: 32 }),
  resourceConstraints: jsonb("resource_constraints").notNull().default(sql`'{}'::jsonb`),
  environmentConstraints: jsonb("environment_constraints").notNull().default(sql`'{}'::jsonb`),
  networkConstraints: jsonb("network_constraints").notNull().default(sql`'{}'::jsonb`),
  reviewRequired: boolean("review_required").notNull().default(false),
  reviewState: varchar("review_state", { length: 24 }).notNull().default("approved"),
  reviewedAt: timestamp("reviewed_at"),
  reviewedBy: varchar("reviewed_by"),
  lastUsedAt: timestamp("last_used_at"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  revokedAt: timestamp("revoked_at"),
  /** Set only while status = "pending_revocation": when the sweep auto-revokes this key. */
  expiresAt: timestamp("expires_at"),
  /** Rotation lineage — self-referencing ids, not FKs (kept nullable/loose like the rest of this table). */
  rotatedFromId: integer("rotated_from_id"),
  rotatedToId: integer("rotated_to_id"),
});

export type McpApiKey = typeof mcpApiKeys.$inferSelect;

export const mcpKeyAuditLog = pgTable("mcp_key_audit_log", {
  id: serial("id").primaryKey(),
  tenantId: varchar("tenant_id").notNull(),
  apiKeyId: integer("api_key_id").notNull(),
  action: varchar("action", { length: 24 }).notNull(),
  /** For rotated_out/rotated_in: the counterpart key id in the rotation pair. */
  relatedKeyId: integer("related_key_id"),
  actorUserId: varchar("actor_user_id"),
  detail: text("detail"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMcpKeyAuditLogSchema = createInsertSchema(mcpKeyAuditLog).omit({
  id: true,
  createdAt: true,
});

export type McpKeyAuditLogRow = typeof mcpKeyAuditLog.$inferSelect;

export type InsertMcpKeyAuditLog = z.infer<typeof insertMcpKeyAuditLogSchema>;

export const mcpToolInvocations = pgTable("mcp_tool_invocations", {
  id: serial("id").primaryKey(),
  requestId: varchar("request_id").notNull(),
  toolName: text("tool_name").notNull(),
  toolClassification: varchar("tool_classification", { length: 16 }).notNull(),
  tenantId: varchar("tenant_id").notNull(),
  apiKeyId: integer("api_key_id"),
  capabilityId: text("capability_id"),
  domainId: text("domain_id"),
  packageId: text("package_id"),
  canonicalService: text("canonical_service").notNull(),
  inputHash: text("input_hash").notNull(),
  outputHash: text("output_hash"),
  manifestId: text("manifest_id"),
  decisionId: text("decision_id"),
  delegationJti: text("delegation_jti"),
  authorizationPolicyVersion: text("authorization_policy_version"),
  migClientId: varchar("mig_client_id"),
  migPrincipalId: varchar("mig_principal_id"),
  journeyId: varchar("journey_id"),
  parentCallId: varchar("parent_call_id"),
  originUserId: varchar("origin_user_id"),
  originAgentId: varchar("origin_agent_id"),
  rootIntentId: varchar("root_intent_id"),
  currentIntentId: varchar("current_intent_id"),
  compoundedIntentIds: jsonb("compounded_intent_ids").$type<string[]>(),
  graphCallIds: jsonb("graph_call_ids").$type<string[]>(),
  resourceRef: text("resource_ref"),
  resourceVersion: text("resource_version"),
  outcome: varchar("outcome", { length: 16 }),
  status: varchar("status", { length: 16 }).notNull(),
  errorCode: text("error_code"),
  durationMs: integer("duration_ms"),
  ttbDays: integer("ttb_days"),
  ttfDays: integer("ttf_days"),
  propagationScore: real("propagation_score"),
  /** Complete MCP tool result for operator audit. Never includes transport auth headers. */
  fullOutputJson: jsonb("full_output_json"),
  /** Complete validated MCP tool request for operator audit. Never includes transport auth headers. */
  inputPayload: jsonb("input_payload"),
  /** ADAM Output Authorization Gate outcome for run_bripe_decision calls. */
  adamOutcome: varchar("adam_outcome", { length: 30 }),
  /** Proof manifest ID emitted by the ADAM gate (for audit trail linkage). */
  adamProofManifestId: text("adam_proof_manifest_id"),
  /** Human-readable reason for BLOCKED or QUALIFIED outcomes. null when AUTHORIZED. */
  adamDowngradeReason: text("adam_downgrade_reason"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMcpToolInvocationSchema = createInsertSchema(mcpToolInvocations).omit({
  id: true,
  createdAt: true,
});

export type McpToolInvocation = typeof mcpToolInvocations.$inferSelect;

export type InsertMcpToolInvocation = z.infer<typeof insertMcpToolInvocationSchema>;

export const MIG_TRUST_LEVELS = ["standard", "elevated", "privileged"] as const;

export type MigTrustLevel = typeof MIG_TRUST_LEVELS[number];

export const MIG_RISK_ZONES = ["low", "medium", "high", "critical"] as const;

export type MigRiskZone = typeof MIG_RISK_ZONES[number];

export const MIG_AGENT_STATUSES = ["active", "suspended", "revoked"] as const;

export type MigAgentStatus = typeof MIG_AGENT_STATUSES[number];

export const MIG_AGENT_LIFECYCLE_STATES = ["discovery", "reviewing", "locked", "active"] as const;

export type MigAgentLifecycleState = typeof MIG_AGENT_LIFECYCLE_STATES[number];

export const migRemoteAgents = pgTable("mig_remote_agents", {
  id: serial("id").primaryKey(),
  agentId: varchar("agent_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(),
  agentType: varchar("agent_type", { length: 32 }).notNull().default("external_mcp_client"),
  // Optional during migration: legacy agents retain their existing ticket
  // contract while newly governed agents bind to a stable principal.
  principalId: varchar("principal_id"),
  displayName: text("display_name").notNull(),
  trustLevel: varchar("trust_level", { length: 16 }).notNull().default("standard"),
  allowedIntentLibraries: jsonb("allowed_intent_libraries").notNull().default(sql`'[]'::jsonb`),
  allowedIntents: jsonb("allowed_intents").notNull().default(sql`'[]'::jsonb`),
  allowedDomains: jsonb("allowed_domains").notNull().default(sql`'[]'::jsonb`),
  allowedPackages: jsonb("allowed_packages").notNull().default(sql`'[]'::jsonb`),
  allowedRiskZones: jsonb("allowed_risk_zones").notNull().default(sql`'["low"]'::jsonb`),
  maxCapabilityClassification: varchar("max_capability_classification", { length: 16 }).notNull().default("read_only"),
  requiresHumanApproval: boolean("requires_human_approval").notNull().default(false),
  oauthClientId: varchar("oauth_client_id"),
  jwksUrl: varchar("jwks_url"),
  ticketSecret: text("ticket_secret").notNull(),
  status: varchar("status", { length: 16 }).notNull().default("active"),
  lifecycleState: varchar("lifecycle_state", { length: 16 }).notNull().default("active"),
  /**
   * Admin-granted exception to the default safe-discovery sandbox rules
   * (see server/mig/mig-discovery.ts checkDiscoverySafety). Off by default —
   * a discovery-mode agent may only exercise read_only/low-risk tools until
   * an admin explicitly flips this for a specific agent that needs to
   * exercise higher-risk tools while its scope is still being learned.
   */
  discoveryExceptionGranted: boolean("discovery_exception_granted").notNull().default(false),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  lastSeenAt: timestamp("last_seen_at"),
  revokedAt: timestamp("revoked_at"),
});

export const insertMigRemoteAgentSchema = createInsertSchema(migRemoteAgents).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastSeenAt: true,
  revokedAt: true,
});

export type MigRemoteAgent = typeof migRemoteAgents.$inferSelect;

export type InsertMigRemoteAgent = z.infer<typeof insertMigRemoteAgentSchema>;

export const migIntentLibraries = pgTable("mig_intent_libraries", {
  id: serial("id").primaryKey(),
  libraryId: varchar("library_id").notNull().unique(),
  name: text("name").notNull(),
  version: varchar("version", { length: 32 }).notNull().default("1.0.0"),
  status: varchar("status", { length: 16 }).notNull().default("draft"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigIntentLibrarySchema = createInsertSchema(migIntentLibraries).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type MigIntentLibrary = typeof migIntentLibraries.$inferSelect;

export type InsertMigIntentLibrary = z.infer<typeof insertMigIntentLibrarySchema>;

export const migIntentDefinitions = pgTable("mig_intent_definitions", {
  id: serial("id").primaryKey(),
  intentId: varchar("intent_id").notNull().unique(),
  libraryId: varchar("library_id").notNull(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  allowedCapabilityIds: jsonb("allowed_capability_ids").notNull().default(sql`'[]'::jsonb`),
  deniedCapabilityIds: jsonb("denied_capability_ids").notNull().default(sql`'[]'::jsonb`),
  allowedToolNames: jsonb("allowed_tool_names").notNull().default(sql`'[]'::jsonb`),
  deniedToolNames: jsonb("denied_tool_names").notNull().default(sql`'[]'::jsonb`),
  domainScope: jsonb("domain_scope").notNull().default(sql`'[]'::jsonb`),
  packageScope: jsonb("package_scope").notNull().default(sql`'[]'::jsonb`),
  riskZone: varchar("risk_zone", { length: 16 }).notNull().default("low"),
  payloadClasses: jsonb("payload_classes").notNull().default(sql`'[]'::jsonb`),
  requiresHumanApproval: boolean("requires_human_approval").notNull().default(false),
  requiresEvidence: boolean("requires_evidence").notNull().default(false),
  requiresManifest: boolean("requires_manifest").notNull().default(true),
  status: varchar("status", { length: 16 }).notNull().default("draft"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigIntentDefinitionSchema = createInsertSchema(migIntentDefinitions).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type MigIntentDefinition = typeof migIntentDefinitions.$inferSelect;

export type InsertMigIntentDefinition = z.infer<typeof insertMigIntentDefinitionSchema>;

export const migTickets = pgTable("mig_tickets", {
  id: serial("id").primaryKey(),
  jti: varchar("jti").notNull().unique(),
  agentId: varchar("agent_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  intentLibraryId: varchar("intent_library_id").notNull(),
  intentId: varchar("intent_id").notNull(),
  riskZone: varchar("risk_zone", { length: 16 }).notNull(),
  sessionId: varchar("session_id").notNull(),
  issuedAt: timestamp("issued_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  revoked: boolean("revoked").notNull().default(false),
  revokedAt: timestamp("revoked_at"),
  revokedReason: text("revoked_reason"),
});

export const insertMigTicketSchema = createInsertSchema(migTickets).omit({
  id: true,
  issuedAt: true,
  revoked: true,
  revokedAt: true,
  revokedReason: true,
});

export type MigTicket = typeof migTickets.$inferSelect;

export type InsertMigTicket = z.infer<typeof insertMigTicketSchema>;

export const migCapabilityManifests = pgTable("mig_capability_manifests", {
  id: serial("id").primaryKey(),
  manifestId: varchar("manifest_id").notNull().unique(),
  ticketJti: varchar("ticket_jti").notNull(),
  agentId: varchar("agent_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  sessionId: varchar("session_id").notNull(),
  intentId: varchar("intent_id").notNull(),
  riskZone: varchar("risk_zone", { length: 16 }).notNull(),
  allowedCapabilities: jsonb("allowed_capabilities").notNull().default(sql`'[]'::jsonb`),
  suppressedCapabilities: jsonb("suppressed_capabilities").notNull().default(sql`'[]'::jsonb`),
  allowedMcpTools: jsonb("allowed_mcp_tools").notNull().default(sql`'[]'::jsonb`),
  deniedMcpTools: jsonb("denied_mcp_tools").notNull().default(sql`'[]'::jsonb`),
  manifestHash: varchar("manifest_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  revoked: boolean("revoked").notNull().default(false),
  revokedReason: text("revoked_reason"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigCapabilityManifestSchema = createInsertSchema(migCapabilityManifests).omit({
  id: true,
  createdAt: true,
  revoked: true,
  revokedReason: true,
});

export type MigCapabilityManifest = typeof migCapabilityManifests.$inferSelect;

export type InsertMigCapabilityManifest = z.infer<typeof insertMigCapabilityManifestSchema>;

export const migAuditLog = pgTable("mig_audit_log", {
  id: serial("id").primaryKey(),
  eventId: varchar("event_id").notNull().unique(),
  eventType: varchar("event_type", { length: 32 }).notNull(),
  decision: varchar("decision", { length: 16 }).notNull(),
  ticketJti: varchar("ticket_jti"),
  manifestId: varchar("manifest_id"),
  agentId: varchar("agent_id"),
  tenantId: varchar("tenant_id"),
  sessionId: varchar("session_id"),
  intentId: varchar("intent_id"),
  riskZone: varchar("risk_zone", { length: 16 }),
  toolName: varchar("tool_name"),
  capabilityId: varchar("capability_id"),
  policyDecision: text("policy_decision").notNull(),
  transitionProofId: varchar("transition_proof_id"),
  inputHash: text("input_hash"),
  outputHash: text("output_hash"),
  reason: text("reason"),
  authenticatedPrincipalId: varchar("authenticated_principal_id"),
  journeyId: varchar("journey_id"),
  parentCallId: varchar("parent_call_id"),
  originUserId: varchar("origin_user_id"),
  originAgentId: varchar("origin_agent_id"),
  rootIntentId: varchar("root_intent_id"),
  compoundedIntentIds: jsonb("compounded_intent_ids").$type<string[]>(),
  graphCallIds: jsonb("graph_call_ids").$type<string[]>(),
  resourceRef: text("resource_ref"),
  outcome: varchar("outcome", { length: 16 }),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigAuditLogSchema = createInsertSchema(migAuditLog).omit({
  id: true,
  createdAt: true,
});

export type MigAuditLog = typeof migAuditLog.$inferSelect;

export type InsertMigAuditLog = z.infer<typeof insertMigAuditLogSchema>;

export const MIG_CLIENT_CLASSES = ["AGENT", "MCP"] as const;

export type MigClientClass = typeof MIG_CLIENT_CLASSES[number];

export const migClients = pgTable("mig_clients", {
  id: serial("id").primaryKey(),
  componentId: varchar("component_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  principalId: varchar("principal_id").notNull(),
  clientClass: varchar("client_class", { length: 8 }).notNull(),
  originUserId: varchar("origin_user_id"),
  credentialHash: text("credential_hash").notNull().unique(),
  credentialPrefix: varchar("credential_prefix", { length: 16 }).notNull(),
  status: varchar("status", { length: 16 }).notNull().default("active"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  revokedAt: timestamp("revoked_at"),
});

export type MigClient = typeof migClients.$inferSelect;

export type InsertMigClient = typeof migClients.$inferInsert;

export const MIG_REGISTRY_ENTRY_ADAPTERS = ["manual", "proximity", "approved_network", "api"] as const;

export const migJourneys = pgTable("mig_journeys", {
  id: serial("id").primaryKey(),
  journeyId: varchar("journey_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(),
  originUserId: varchar("origin_user_id").notNull(),
  originAgentId: varchar("origin_agent_id").notNull(),
  rootIntentId: varchar("root_intent_id").notNull(),
  rootIntent: text("root_intent").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export type MigJourney = typeof migJourneys.$inferSelect;

export type InsertMigJourney = typeof migJourneys.$inferInsert;

export const migJourneyCalls = pgTable("mig_journey_calls", {
  id: serial("id").primaryKey(),
  callId: varchar("call_id").notNull().unique(),
  journeyId: varchar("journey_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  parentCallId: varchar("parent_call_id"),
  sequence: integer("sequence").notNull(),
  currentIntentId: varchar("current_intent_id").notNull(),
  currentIntent: text("current_intent").notNull(),
  callerComponentId: varchar("caller_component_id").notNull(),
  callerClass: varchar("caller_class", { length: 8 }).notNull(),
  targetComponentId: varchar("target_component_id").notNull(),
  inputHash: text("input_hash").notNull(),
  authorizationManifestId: varchar("authorization_manifest_id"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export type MigJourneyCall = typeof migJourneyCalls.$inferSelect;

export type InsertMigJourneyCall = typeof migJourneyCalls.$inferInsert;

export const migJourneyIntentTransitions = pgTable("mig_journey_intent_transitions", {
  id: serial("id").primaryKey(),
  transitionId: varchar("transition_id").notNull().unique(),
  journeyId: varchar("journey_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  parentCallId: varchar("parent_call_id").notNull(),
  sourceIntentId: varchar("source_intent_id").notNull(),
  targetIntentId: varchar("target_intent_id").notNull(),
  authorityDelta: jsonb("authority_delta").notNull(),
  approverPrincipalId: varchar("approver_principal_id").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export type MigJourneyIntentTransition = typeof migJourneyIntentTransitions.$inferSelect;

export type InsertMigJourneyIntentTransition = typeof migJourneyIntentTransitions.$inferInsert;

export const migJourneyIntentTransitionRevocations = pgTable("mig_journey_intent_transition_revocations", {
  id: serial("id").primaryKey(),
  revocationId: varchar("revocation_id").notNull().unique(),
  transitionId: varchar("transition_id").notNull().unique(),
  journeyId: varchar("journey_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  parentCallId: varchar("parent_call_id").notNull(),
  revokedByPrincipalId: varchar("revoked_by_principal_id").notNull(),
  reason: text("reason").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const migJourneyOutcomes = pgTable("mig_journey_outcomes", {
  id: serial("id").primaryKey(),
  outcomeId: varchar("outcome_id").notNull().unique(),
  callId: varchar("call_id").notNull(),
  journeyId: varchar("journey_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  outcome: varchar("outcome", { length: 16 }).notNull(),
  reason: text("reason").notNull(),
  resultHash: text("result_hash"),
  resultRef: varchar("result_ref"),
  authorizationManifestId: varchar("authorization_manifest_id"),
  // Server-computed journey authorization snapshot.  These are deliberately
  // attached to the append-only admission decision, never caller input.
  requestedAuthority: jsonb("requested_authority"),
  effectiveAuthority: jsonb("effective_authority"),
  accumulatedState: jsonb("accumulated_state"),
  structuralDecisionRef: varchar("structural_decision_ref"),
  journeyState: varchar("journey_state", { length: 16 }),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export type MigJourneyOutcome = typeof migJourneyOutcomes.$inferSelect;

export type InsertMigJourneyOutcome = typeof migJourneyOutcomes.$inferInsert;

export const migObservationEvents = pgTable("mig_observation_events", {
  id: serial("id").primaryKey(), observationEventId: varchar("observation_event_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(), sourceId: varchar("source_id").notNull(), sourceKind: varchar("source_kind").notNull(),
  evidenceRegime: varchar("evidence_regime", { length: 32 }).notNull(), evidenceQuality: varchar("evidence_quality", { length: 24 }).notNull(),
  sourceEventId: varchar("source_event_id").notNull(), idempotencyKey: varchar("idempotency_key").notNull(),
  occurredAt: timestamp("occurred_at").notNull(), envelope: jsonb("envelope").notNull(), createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, t => ({ tenantIdempotency: uniqueIndex("mig_observation_events_tenant_idempotency_unique").on(t.tenantId, t.sourceId, t.idempotencyKey) }));

export type MigObservationEvent = typeof migObservationEvents.$inferSelect;

export type InsertMigObservationEvent = typeof migObservationEvents.$inferInsert;

export const migObservationCorrelations = pgTable("mig_observation_correlations", {
  id: serial("id").primaryKey(), correlationId: varchar("correlation_id").notNull().unique(), tenantId: varchar("tenant_id").notNull(),
  observationEventId: varchar("observation_event_id").notNull(), status: varchar("status", { length: 32 }).notNull(),
  correlationKey: varchar("correlation_key"), evidence: jsonb("evidence").notNull(), createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export type MigObservationCorrelation = typeof migObservationCorrelations.$inferSelect;

export type InsertMigObservationCorrelation = typeof migObservationCorrelations.$inferInsert;

export const migObservedJourneyVersions = pgTable("mig_observed_journey_versions", {
  id: serial("id").primaryKey(), journeyVersionId: varchar("journey_version_id").notNull().unique(), observedJourneyId: varchar("observed_journey_id").notNull(),
  tenantId: varchar("tenant_id").notNull(), sourceObservationEventId: varchar("source_observation_event_id").notNull(), version: integer("version").notNull(), supersedesJourneyVersionId: varchar("supersedes_journey_version_id"),
  correlationStatus: varchar("correlation_status", { length: 32 }).notNull(), snapshot: jsonb("snapshot").notNull(), createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, t => ({ versionUnique: uniqueIndex("mig_observed_journey_versions_tenant_version_unique").on(t.tenantId, t.observedJourneyId, t.version), eventUnique: uniqueIndex("mig_observed_journey_versions_tenant_event_unique").on(t.tenantId, t.sourceObservationEventId) }));

export type MigObservedJourneyVersion = typeof migObservedJourneyVersions.$inferSelect;

export type InsertMigObservedJourneyVersion = typeof migObservedJourneyVersions.$inferInsert;

export const migObservationFactualEdges = pgTable("mig_observation_factual_edges", {
  id: serial("id").primaryKey(), factualEdgeId: varchar("factual_edge_id").notNull().unique(), tenantId: varchar("tenant_id").notNull(),
  observationEventId: varchar("observation_event_id").notNull(), journeyVersionId: varchar("journey_version_id"), edge: jsonb("edge").notNull(), createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export type MigObservationFactualEdge = typeof migObservationFactualEdges.$inferSelect;

export type InsertMigObservationFactualEdge = typeof migObservationFactualEdges.$inferInsert;

export const migObservationFindings = pgTable("mig_observation_findings", {
  id: serial("id").primaryKey(), findingId: varchar("finding_id").notNull().unique(), tenantId: varchar("tenant_id").notNull(),
  journeyVersionId: varchar("journey_version_id").notNull(), status: varchar("status", { length: 32 }).notNull(), wouldHaveDenied: varchar("would_have_denied", { length: 16 }).notNull(),
  structuralDecisionRef: varchar("structural_decision_ref"), proofRef: varchar("proof_ref"), supersedesFindingId: varchar("supersedes_finding_id"),
  evidenceRefs: jsonb("evidence_refs").notNull(), createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export type MigObservationFinding = typeof migObservationFindings.$inferSelect;

export type InsertMigObservationFinding = typeof migObservationFindings.$inferInsert;

export const migObservationCustomerOutcomes = pgTable("mig_observation_customer_outcomes", {
  id: serial("id").primaryKey(), outcomeId: varchar("outcome_id").notNull().unique(), tenantId: varchar("tenant_id").notNull(),
  journeyVersionId: varchar("journey_version_id"), outcome: text("outcome").notNull(), evidenceRefs: jsonb("evidence_refs").notNull(), createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, t => ({ tenantOutcome: uniqueIndex("mig_observation_customer_outcomes_tenant_outcome_unique").on(t.tenantId, t.outcomeId) }));

export type MigObservationCustomerOutcome = typeof migObservationCustomerOutcomes.$inferSelect;

export type InsertMigObservationCustomerOutcome = typeof migObservationCustomerOutcomes.$inferInsert;

export const migObservationStructuralDecisions = pgTable("mig_observation_structural_decisions", {
  id: serial("id").primaryKey(), observationStructuralDecisionId: varchar("observation_structural_decision_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(), journeyVersionId: varchar("journey_version_id").notNull(), canonicalDecisionId: varchar("canonical_decision_id").notNull(),
  enforcement: varchar("enforcement", { length: 24 }).notNull(), reason: text("reason").notNull(), canonicalRequestRef: varchar("canonical_request_ref").notNull(),
  canonicalRequestHash: text("canonical_request_hash").notNull(), evidenceRefs: jsonb("evidence_refs").notNull(), createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, t => ({ tenantDecision: uniqueIndex("mig_observation_structural_decisions_tenant_decision_unique").on(t.tenantId, t.canonicalDecisionId),
  tenantEvaluation: uniqueIndex("mig_observation_structural_decisions_tenant_evaluation_unique").on(t.tenantId, t.journeyVersionId, t.canonicalRequestRef) }));

export type MigObservationStructuralDecision = typeof migObservationStructuralDecisions.$inferSelect;

export type InsertMigObservationStructuralDecision = typeof migObservationStructuralDecisions.$inferInsert;

export const migObservationProofReferences = pgTable("mig_observation_proof_references", {
  id: serial("id").primaryKey(), proofReferenceId: varchar("proof_reference_id").notNull().unique(), tenantId: varchar("tenant_id").notNull(),
  observationStructuralDecisionId: varchar("observation_structural_decision_id").notNull(), proofRef: varchar("proof_ref").notNull(),
  evidenceRefs: jsonb("evidence_refs").notNull(), createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, t => ({ tenantProof: uniqueIndex("mig_observation_proof_references_tenant_proof_unique").on(t.tenantId, t.proofRef) }));

export type MigObservationProofReference = typeof migObservationProofReferences.$inferSelect;

export type InsertMigObservationProofReference = typeof migObservationProofReferences.$inferInsert;

export const MIG_PRINCIPAL_TYPES = ["human", "service", "agent", "integration"] as const;

export type MigPrincipalType = typeof MIG_PRINCIPAL_TYPES[number];

export const MIG_PRINCIPAL_STATUSES = ["active", "suspended", "revoked"] as const;

export type MigPrincipalStatus = typeof MIG_PRINCIPAL_STATUSES[number];

export const MIG_CREDENTIAL_TYPES = ["oauth_subject", "api_key", "service_identity", "mig_agent", "mig_mcp"] as const;

export type MigCredentialType = typeof MIG_CREDENTIAL_TYPES[number];

export const migPrincipals = pgTable("mig_principals", {
  id: serial("id").primaryKey(),
  principalId: varchar("principal_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  principalType: varchar("principal_type", { length: 16 }).notNull(),
  subjectRef: varchar("subject_ref").notNull(),
  displayName: text("display_name").notNull(),
  status: varchar("status", { length: 16 }).notNull().default("active"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  tenantPrincipalUnique: uniqueIndex("mig_principals_tenant_principal_unique").on(t.tenantId, t.principalId),
  tenantSubjectUnique: uniqueIndex("mig_principals_tenant_subject_unique").on(t.tenantId, t.subjectRef),
  tenantStatusIdx: index("mig_principals_tenant_status_idx").on(t.tenantId, t.status),
}));

export type MigPrincipal = typeof migPrincipals.$inferSelect;

export type InsertMigPrincipal = typeof migPrincipals.$inferInsert;

export const migCredentialBindings = pgTable("mig_credential_bindings", {
  id: serial("id").primaryKey(),
  credentialRef: varchar("credential_ref").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(),
  principalId: varchar("principal_id").notNull(),
  credentialType: varchar("credential_type", { length: 24 }).notNull(),
  /** Explicit governed provider discriminator; never inferred from credentialType. */
  providerKind: varchar("provider_kind", { length: 32 }),
  endpointRef: varchar("endpoint_ref"),
  mcpServerRef: varchar("mcp_server_ref"),
  mcpToolName: varchar("mcp_tool_name"),
  mcpCapabilityId: varchar("mcp_capability_id"),
  mcpScope: varchar("mcp_scope"),
  mcpResourceRef: varchar("mcp_resource_ref"),
  mcpIntentId: varchar("mcp_intent_id"),
  mcpTicket: text("mcp_ticket"),
  lineageId: varchar("lineage_id"),
  status: varchar("status", { length: 16 }).notNull().default("active"),
  // A semantic capability ceiling, never a raw MCP tool allow-list.
  capabilityCeiling: jsonb("capability_ceiling").notNull().default(sql`'[]'::jsonb`),
  // Credential authority is an explicit, persisted ceiling. Empty arrays deny;
  // only an explicitly persisted "*" is a wildcard.
  scopes: jsonb("scopes").notNull().default(sql`'[]'::jsonb`),
  allowedIntents: jsonb("allowed_intents").notNull().default(sql`'[]'::jsonb`),
  allowedDomains: jsonb("allowed_domains").notNull().default(sql`'[]'::jsonb`),
  allowedMcpTargets: jsonb("allowed_mcp_targets").notNull().default(sql`'[]'::jsonb`),
  allowedCapabilities: jsonb("allowed_capabilities").notNull().default(sql`'[]'::jsonb`),
  resourceScopes: jsonb("resource_scopes").notNull().default(sql`'[]'::jsonb`),
  riskZoneCeiling: varchar("risk_zone_ceiling", { length: 16 }),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  revokedAt: timestamp("revoked_at"),
});

export type MigCredentialBinding = typeof migCredentialBindings.$inferSelect;

export type InsertMigCredentialBinding = typeof migCredentialBindings.$inferInsert;

export const migPrincipalEntitlements = pgTable("mig_principal_entitlements", {
  id: serial("id").primaryKey(),
  entitlementId: varchar("entitlement_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(),
  principalId: varchar("principal_id").notNull(),
  capabilityIds: jsonb("capability_ids").notNull().default(sql`'[]'::jsonb`),
  domainIds: jsonb("domain_ids").notNull().default(sql`'[]'::jsonb`),
  intentIds: jsonb("intent_ids").notNull().default(sql`'[]'::jsonb`),
  resourceScopes: jsonb("resource_scopes").notNull().default(sql`'[]'::jsonb`),
  assignedRoles: jsonb("assigned_roles").notNull().default(sql`'[]'::jsonb`),
  status: varchar("status", { length: 16 }).notNull().default("active"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  oneActiveIdx: uniqueIndex("mig_principal_entitlements_one_active_idx")
    .on(t.tenantId, t.principalId)
    .where(sql`${t.status} = 'active'`),
}));

export type MigPrincipalEntitlement = typeof migPrincipalEntitlements.$inferSelect;

export type InsertMigPrincipalEntitlement = typeof migPrincipalEntitlements.$inferInsert;

export const migTenantAuthorizationPolicies = pgTable("mig_tenant_authorization_policies", {
  id: serial("id").primaryKey(),
  tenantId: varchar("tenant_id").notNull(),
  version: varchar("version", { length: 64 }).notNull(),
  status: varchar("status", { length: 16 }).notNull().default("active"),
  capabilityIds: jsonb("capability_ids").notNull().default(sql`'[]'::jsonb`),
  domainIds: jsonb("domain_ids").notNull().default(sql`'[]'::jsonb`),
  intentIds: jsonb("intent_ids").notNull().default(sql`'[]'::jsonb`),
  resourceScopes: jsonb("resource_scopes").notNull().default(sql`'[]'::jsonb`),
  allowedRiskZones: jsonb("allowed_risk_zones").notNull().default(sql`'[]'::jsonb`),
  allowedResourceStates: jsonb("allowed_resource_states").notNull().default(sql`'[]'::jsonb`),
  staticSodConflicts: jsonb("static_sod_conflicts").notNull().default(sql`'[]'::jsonb`),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  tenantVersionUnique: uniqueIndex("mig_tenant_authorization_policies_tenant_version_unique").on(t.tenantId, t.version),
  tenantCreatedIdx: index("mig_tenant_authorization_policies_tenant_created_idx").on(t.tenantId, t.createdAt),
}));

export type MigTenantAuthorizationPolicyRecord = typeof migTenantAuthorizationPolicies.$inferSelect;

export type InsertMigTenantAuthorizationPolicy = typeof migTenantAuthorizationPolicies.$inferInsert;

export const migAuthorizationManifests = pgTable("mig_authorization_manifests", {
  id: serial("id").primaryKey(),
  authorizationManifestId: varchar("authorization_manifest_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(),
  actorPrincipalId: varchar("actor_principal_id"),
  clientPrincipalId: varchar("client_principal_id"),
  executorPrincipalId: varchar("executor_principal_id"),
  credentialRef: varchar("credential_ref"),
  intentId: varchar("intent_id"),
  capabilityId: varchar("capability_id"),
  semanticAction: varchar("semantic_action"),
  domainId: varchar("domain_id"),
  resourceRef: varchar("resource_ref"),
  resourceVersion: varchar("resource_version"),
  policyVersion: varchar("policy_version").notNull(),
  decision: varchar("decision", { length: 16 }).notNull(),
  reason: varchar("reason").notNull(),
  effectivePermissions: jsonb("effective_permissions").notNull().default(sql`'[]'::jsonb`),
  sodResult: jsonb("sod_result").notNull().default(sql`'{}'::jsonb`),
  requestCorrelationId: varchar("request_correlation_id"),
  delegationRef: varchar("delegation_ref"),
  authorityProvider: varchar("authority_provider", { length: 32 }),
  authorityRef: varchar("authority_ref"),
  authoritySnapshotId: varchar("authority_snapshot_id"),
  authorityEvidence: jsonb("authority_evidence").notNull().default(sql`'[]'::jsonb`),
  authorityObservedAt: timestamp("authority_observed_at"),
  authorityExpiresAt: timestamp("authority_expires_at"),
  effectiveRiskZoneCeiling: varchar("effective_risk_zone_ceiling", { length: 16 }),
  beforeHash: text("before_hash"),
  afterHash: text("after_hash"),
  manifestHash: text("manifest_hash").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  tenantCreatedIdx: index("mig_authorization_manifests_tenant_created_idx").on(t.tenantId, t.createdAt),
  correlationIdx: index("mig_authorization_manifests_correlation_idx").on(t.requestCorrelationId),
}));

export type MigAuthorizationManifest = typeof migAuthorizationManifests.$inferSelect;

export type InsertMigAuthorizationManifest = typeof migAuthorizationManifests.$inferInsert;

export const migDiscoveryEvents = pgTable("mig_discovery_events", {
  id: serial("id").primaryKey(),
  eventId: varchar("event_id").notNull().unique(),
  agentId: varchar("agent_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  sessionId: varchar("session_id"),
  requestKind: varchar("request_kind", { length: 16 }).notNull(), // "discover" | "execute"
  toolName: varchar("tool_name"),
  capabilityId: varchar("capability_id"),
  domainHints: jsonb("domain_hints").notNull().default(sql`'[]'::jsonb`),
  inputShapeKeys: jsonb("input_shape_keys").notNull().default(sql`'[]'::jsonb`),
  /** True when this captured attempt was denied/blocked (e.g. discovery sandbox, drift, policy) rather than allowed. */
  wasDenied: boolean("was_denied").notNull().default(false),
  denialReason: text("denial_reason"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigDiscoveryEventSchema = createInsertSchema(migDiscoveryEvents).omit({
  id: true,
  createdAt: true,
});

export type MigDiscoveryEvent = typeof migDiscoveryEvents.$inferSelect;

export type InsertMigDiscoveryEvent = z.infer<typeof insertMigDiscoveryEventSchema>;

export const migDraftIntentProfiles = pgTable("mig_draft_intent_profiles", {
  id: serial("id").primaryKey(),
  draftId: varchar("draft_id").notNull().unique(),
  agentId: varchar("agent_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  proposedName: text("proposed_name").notNull(),
  proposedDescription: text("proposed_description").notNull(),
  proposedAllowedToolNames: jsonb("proposed_allowed_tool_names").notNull().default(sql`'[]'::jsonb`),
  proposedCapabilityIds: jsonb("proposed_capability_ids").notNull().default(sql`'[]'::jsonb`),
  proposedDomainScope: jsonb("proposed_domain_scope").notNull().default(sql`'[]'::jsonb`),
  proposedRiskZone: varchar("proposed_risk_zone", { length: 16 }).notNull().default("low"),
  observedEventCount: integer("observed_event_count").notNull().default(0),
  /** 0-100 heuristic confidence that the proposed scope reflects the agent's real, stable usage pattern. */
  confidence: integer("confidence").notNull().default(0),
  /** Denied/risky attempts and other observations surfaced to the reviewing admin (never invented — derived only from captured events). */
  policyFindings: jsonb("policy_findings").notNull().default(sql`'[]'::jsonb`),
  evidenceSummary: text("evidence_summary").notNull().default(""),
  status: varchar("status", { length: 16 }).notNull().default("pending"),
  resultingIntentId: varchar("resulting_intent_id"),
  reviewedBy: varchar("reviewed_by"),
  reviewNotes: text("review_notes"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  reviewedAt: timestamp("reviewed_at"),
});

export const insertMigDraftIntentProfileSchema = createInsertSchema(migDraftIntentProfiles).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  reviewedAt: true,
});

export type MigDraftIntentProfile = typeof migDraftIntentProfiles.$inferSelect;

export type InsertMigDraftIntentProfile = z.infer<typeof insertMigDraftIntentProfileSchema>;

export const migDriftEvents = pgTable("mig_drift_events", {
  id: serial("id").primaryKey(),
  eventId: varchar("event_id").notNull().unique(),
  agentId: varchar("agent_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  driftType: varchar("drift_type", { length: 32 }).notNull(), // e.g. "unauthorized_tool_call"
  toolName: varchar("tool_name"),
  detail: text("detail").notNull(),
  severity: varchar("severity", { length: 16 }).notNull().default("warning"),
  resolved: boolean("resolved").notNull().default(false),
  resolvedBy: varchar("resolved_by"),
  resolvedAt: timestamp("resolved_at"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigDriftEventSchema = createInsertSchema(migDriftEvents).omit({
  id: true,
  createdAt: true,
  resolved: true,
  resolvedBy: true,
  resolvedAt: true,
});

export type MigDriftEvent = typeof migDriftEvents.$inferSelect;

export type InsertMigDriftEvent = z.infer<typeof insertMigDriftEventSchema>;

export const migSecurityReports = pgTable("mig_security_reports", {
  id: serial("id").primaryKey(),
  reportId: varchar("report_id").notNull().unique(),
  mcpServerId: varchar("mcp_server_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  overallScore: integer("overall_score").notNull().default(0),
  grade: varchar("grade", { length: 4 }).notNull().default("F"),
  layerScores: jsonb("layer_scores").notNull().default(sql`'{}'::jsonb`),
  findings: jsonb("findings").notNull().default(sql`'[]'::jsonb`),
  scorecard: jsonb("scorecard").notNull().default(sql`'{}'::jsonb`),
  capabilityInventory: jsonb("capability_inventory").default(sql`'[]'::jsonb`),
  reportData: jsonb("report_data"),
  snapshotHash: text("snapshot_hash"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigSecurityReportSchema = createInsertSchema(migSecurityReports).omit({
  id: true,
  createdAt: true,
});

export type MigSecurityReport = typeof migSecurityReports.$inferSelect;

export type InsertMigSecurityReport = z.infer<typeof insertMigSecurityReportSchema>;

export const migSecurityFindings = pgTable("mig_security_findings", {
  id: serial("id").primaryKey(),
  reportId: varchar("report_id").notNull(),
  mcpServerId: varchar("mcp_server_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  layer: varchar("layer", { length: 16 }).notNull(),
  severity: varchar("severity", { length: 16 }).notNull(),
  category: varchar("category", { length: 64 }).notNull(),
  evidence: text("evidence").notNull(),
  recommendation: text("recommendation").notNull(),
  likelihood: varchar("likelihood", { length: 16 }),
  impact: varchar("impact", { length: 16 }),
  confidence: integer("confidence"),
  affectedProducts: text("affected_products").array(),
  patchDescriptor: jsonb("patch_descriptor"),
  acknowledged: boolean("acknowledged").notNull().default(false),
  acknowledgedAt: timestamp("acknowledged_at"),
  acknowledgedBy: varchar("acknowledged_by"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigSecurityFindingSchema = createInsertSchema(migSecurityFindings).omit({
  id: true,
  createdAt: true,
  acknowledgedAt: true,
  acknowledgedBy: true,
});

export type MigSecurityFinding = typeof migSecurityFindings.$inferSelect;

export type InsertMigSecurityFinding = z.infer<typeof insertMigSecurityFindingSchema>;

export const migToolOverrides = pgTable("mig_tool_overrides", {
  id: serial("id").primaryKey(),
  mcpServerId: varchar("mcp_server_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  toolName: varchar("tool_name").notNull(),
  template: varchar("template", { length: 64 }).notNull(),
  appliedByPatchId: integer("applied_by_patch_id"),
  appliedAt: timestamp("applied_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigToolOverrideSchema = createInsertSchema(migToolOverrides).omit({ id: true, appliedAt: true });

export type MigToolOverride = typeof migToolOverrides.$inferSelect;

export type InsertMigToolOverride = z.infer<typeof insertMigToolOverrideSchema>;

export const migGeneratedTests = pgTable("mig_generated_tests", {
  id: serial("id").primaryKey(),
  mcpServerId: varchar("mcp_server_id").notNull(),
  capabilityId: varchar("capability_id").notNull(),
  capabilityName: varchar("capability_name").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  testType: varchar("test_type", { length: 32 }).notNull(),
  testName: varchar("test_name").notNull(),
  inputPayload: jsonb("input_payload").notNull().default(sql`'{}'::jsonb`),
  expectedBehavior: text("expected_behavior").notNull(),
  lastPass: boolean("last_pass"),
  generatedAt: timestamp("generated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigGeneratedTestSchema = createInsertSchema(migGeneratedTests).omit({
  id: true,
  generatedAt: true,
});

export type MigGeneratedTest = typeof migGeneratedTests.$inferSelect;

export type InsertMigGeneratedTest = z.infer<typeof insertMigGeneratedTestSchema>;

export const migPatches = pgTable("mig_patches", {
  id: serial("id").primaryKey(),
  findingId: varchar("finding_id").notNull(),
  mcpServerId: varchar("mcp_server_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  status: varchar("status", { length: 16 }).notNull().default("PENDING"),
  diffText: text("diff_text").notNull(),
  riskBefore: integer("risk_before").notNull().default(0),
  riskAfter: integer("risk_after").notNull().default(0),
  coverageDelta: integer("coverage_delta").notNull().default(0),
  regressionRisk: varchar("regression_risk", { length: 8 }).notNull().default("low"),
  impactDescription: text("impact_description").notNull().default(""),
  capabilityName: varchar("capability_name"),
  findingSummary: text("finding_summary"),
  generatedAt: timestamp("generated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  reviewedAt: timestamp("reviewed_at"),
  mergedAt: timestamp("merged_at"),
});

export const insertMigPatchSchema = createInsertSchema(migPatches).omit({
  id: true,
  generatedAt: true,
  reviewedAt: true,
  mergedAt: true,
});

export type MigPatch = typeof migPatches.$inferSelect;

export type InsertMigPatch = z.infer<typeof insertMigPatchSchema>;

export const migPatchValidations = pgTable("mig_patch_validations", {
  id: serial("id").primaryKey(),
  patchId: integer("patch_id").notNull(),
  mcpServerId: varchar("mcp_server_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  scoreBefore: integer("score_before").notNull().default(0),
  scoreAfter: integer("score_after").notNull().default(0),
  gradeBefore: varchar("grade_before", { length: 4 }).notNull().default("F"),
  gradeAfter: varchar("grade_after", { length: 4 }).notNull().default("F"),
  certificationBefore: varchar("certification_before", { length: 32 }).notNull().default("FAILED"),
  certificationAfter: varchar("certification_after", { length: 32 }).notNull().default("FAILED"),
  findingDelta: integer("finding_delta").notNull().default(0),
  coverageDelta: integer("coverage_delta").notNull().default(0),
  validationReport: jsonb("validation_report").notNull().default(sql`'{}'::jsonb`),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMigPatchValidationSchema = createInsertSchema(migPatchValidations).omit({
  id: true,
  createdAt: true,
});

export type MigPatchValidation = typeof migPatchValidations.$inferSelect;

export type InsertMigPatchValidation = z.infer<typeof insertMigPatchValidationSchema>;

export const entraTenantMappings = pgTable("entra_tenant_mappings", {
  id: serial("id").primaryKey(),
  entraTenantId: varchar("entra_tenant_id", { length: 128 }).notNull().unique(),
  bcentriskTenantId: varchar("bcentrisk_tenant_id", { length: 128 }).notNull(),
  displayLabel: text("display_label"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  entraTenantIdx: index("entra_tenant_mappings_entra_idx").on(t.entraTenantId),
}));

export type EntraTenantMapping = typeof entraTenantMappings.$inferSelect;

export const STRUCTURAL_OBJECT_TYPES = [
  "evidence",
  "signal",
  "control",
  "domain_score",
  "metric",
  "scoring_run",
  "dependency",
  "decision",
] as const;

export type StructuralObjectType = typeof STRUCTURAL_OBJECT_TYPES[number];

export const structuralObjectHistory = pgTable("structural_object_history", {
  id:              serial("id").primaryKey(),
  tenantId:        text("tenant_id").notNull().default(DEFAULT_TENANT_ID),
  /**
   * Canonical object class. Determines how payload is interpreted.
   * evidence | signal | control | domain_score | metric | scoring_run | decision
   */
  objectType:      varchar("object_type", { length: 32 }).notNull(),
  /** Stable identifier for the tracked object (e.g. vendor_id, control_id). */
  objectId:        text("object_id").notNull(),
  /**
   * Owner identifier — the vendor, org, or tenant this record belongs to.
   * More specific than tenantId when tracking vendor- or org-scoped objects.
   */
  ownerId:         varchar("owner_id", { length: 255 }).notNull().default(DEFAULT_TENANT_ID),
  /**
   * Caller-supplied idempotency key for retry-safe dedup.
   * When the caller passes the same key on retry, ON CONFLICT DO NOTHING fires.
   * When omitted, the DB generates a UUID — every insert succeeds (no false dedup).
   * This is the sole reliable dedup target; (object_id, object_type, recorded_at)
   * cannot serve as a unique key because recorded_at is server-generated per call.
   */
  idempotencyKey:  varchar("idempotency_key", { length: 255 }).notNull().default(sql`gen_random_uuid()::text`),
  /** Optional scoping context (e.g. tenant+vendor composite key). */
  contextId:       text("context_id"),
  /** Current-state snapshot at record time. Never modified after insert. */
  payload:         jsonb("payload").notNull(),
  /** Previous state snapshot. null for the initial record. */
  previousPayload: jsonb("previous_payload"),
  /** Structured diff summary (which fields changed, direction, magnitude). */
  deltaSummary:    jsonb("delta_summary"),
  /** Module path that produced this record (for lineage tracing). */
  recordedBy:      text("recorded_by").notNull().default("structural-history-store"),
  /**
   * Human-readable reason this record was written
   * (e.g. "ttb_transition", "initial_assessment", "vendor_approval").
   */
  triggerReason:   text("trigger_reason").notNull().default(""),
  /** Correlates all writes produced by a single scoring pipeline run. */
  sessionId:       text("session_id"),
  /** True for the first record for a given objectType+objectId+tenantId. */
  isInitialRecord: boolean("is_initial_record").notNull().default(false),
  /** Schema version of the payload shape (for forward-compat deserialization). */
  schemaVersion:   varchar("schema_version", { length: 16 }).notNull().default("1.0"),
  recordedAt:      timestamp("recorded_at").defaultNow().notNull(),
}, (t) => ({
  objectIdx:             index("soh_object_idx").on(t.objectType, t.objectId, t.tenantId),
  contextIdx:            index("soh_context_idx").on(t.contextId),
  sessionIdx:            index("soh_session_idx").on(t.sessionId),
  timelineIdx:           index("soh_timeline_idx").on(t.objectId, t.recordedAt),
  // Owner-scoped timeline: all history for a vendor/tenant/org
  ownerTimelineIdx:      index("soh_owner_timeline_idx").on(t.ownerId, t.recordedAt),
  // Retry-safe duplicate suppression keyed on caller-supplied idempotency key.
  // (object_id, object_type, recorded_at) is NOT a reliable dedup target because
  // recorded_at is server-generated and changes on every retry.
  idempotencyKeyIdx:     uniqueIndex("soh_idempotency_key_idx").on(t.idempotencyKey),
}));

export type InsertMigRegistryHistory = typeof migRegistryHistory.$inferInsert;

export type InsertMigRegistryCandidate = typeof migRegistryCandidates.$inferInsert;

export const migRegistryHistory = pgTable("mig_registry_history", {
  id: serial("id").primaryKey(),
  eventId: varchar("event_id").notNull().unique(),
  candidateId: varchar("candidate_id").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  fromState: varchar("from_state", { length: 16 }),
  toState: varchar("to_state", { length: 16 }).notNull(),
  eventType: varchar("event_type", { length: 32 }).notNull(),
  actorId: varchar("actor_id").notNull(),
  evidence: jsonb("evidence").notNull().default(sql`'{}'::jsonb`),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  candidateCreatedIdx: index("mig_registry_history_candidate_created_idx").on(t.candidateId, t.createdAt),
}));

export type MigRegistryHistory = typeof migRegistryHistory.$inferSelect;

export const MIG_REGISTRY_STATES = ["discovered", "identified", "classified", "validated", "registered", "trusted", "failed_validation", "suspended", "revoked"] as const;

export const migRegistryCandidates = pgTable("mig_registry_candidates", {
  id: serial("id").primaryKey(),
  candidateId: varchar("candidate_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(),
  componentId: varchar("component_id").notNull(),
  principalId: varchar("principal_id"),
  clientClass: varchar("client_class", { length: 8 }),
  entryAdapter: varchar("entry_adapter", { length: 24 }).notNull(),
  approvedScopes: jsonb("approved_scopes").notNull().default(sql`'[]'::jsonb`),
  target: jsonb("target").notNull().default(sql`'{}'::jsonb`),
  idempotencyKey: varchar("idempotency_key", { length: 128 }),
  state: varchar("state", { length: 20 }).notNull().default("discovered"),
  createdBy: varchar("created_by").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  tenantComponentUnique: uniqueIndex("mig_registry_candidate_tenant_component_unique").on(t.tenantId, t.componentId),
  tenantIdempotencyUnique: uniqueIndex("mig_registry_candidate_tenant_idempotency_unique").on(t.tenantId, t.idempotencyKey),
  tenantStateIdx: index("mig_registry_candidate_tenant_state_idx").on(t.tenantId, t.state),
}));

export type MigRegistryCandidate = typeof migRegistryCandidates.$inferSelect;

export const migMcpSchemaObservations = pgTable("mig_mcp_schema_observations", {
  observationId: text("observation_id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  mcpServerId: text("mcp_server_id").notNull(),
  mcpToolName: text("mcp_tool_name").notNull(),
  schemaVersion: text("schema_version").notNull(),
  schemaFingerprint: text("schema_fingerprint").notNull(),
  observedAt: timestamp("observed_at").notNull(),
  sourceProofRef: text("source_proof_ref").notNull(),
}, (t) => ({
  exactIdx: index("mig_mcp_schema_observation_exact_idx").on(t.tenantId, t.mcpServerId, t.mcpToolName, t.schemaVersion, t.observedAt),
}));

export const migMcpSchemaAccessAlerts = pgTable("mig_mcp_schema_access_alerts", {
  alertId: text("alert_id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  mcpServerId: text("mcp_server_id").notNull(),
  mcpToolName: text("mcp_tool_name").notNull(),
  priorBindingId: text("prior_binding_id").notNull(),
  priorSchemaVersion: text("prior_schema_version").notNull(),
  priorSchemaFingerprint: text("prior_schema_fingerprint").notNull(),
  observedSchemaVersion: text("observed_schema_version").notNull(),
  observedSchemaFingerprint: text("observed_schema_fingerprint").notNull(),
  observationId: text("observation_id").notNull(),
  detectedAt: timestamp("detected_at").notNull(),
}, (t) => ({
  tenantDetectedIdx: index("mig_mcp_schema_access_alert_tenant_idx").on(t.tenantId, t.detectedAt),
  exactUnique: uniqueIndex("mig_mcp_schema_access_alert_exact_uq").on(t.tenantId, t.priorBindingId, t.observationId),
}));

export type MigRegistryEntryAdapter = typeof MIG_REGISTRY_ENTRY_ADAPTERS[number];

export type MigRegistryState = typeof MIG_REGISTRY_STATES[number];

export type MigAuthoritySnapshot = typeof migAuthoritySnapshots.$inferSelect;

export type InsertMigTenantAuthorityConfig = typeof migTenantAuthorityConfigs.$inferInsert;

export type InsertMigAuthoritySnapshot = typeof migAuthoritySnapshots.$inferInsert;

export const migTenantAuthorityConfigs = pgTable("mig_tenant_authority_configs", {
  id: serial("id").primaryKey(),
  configId: varchar("config_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(),
  version: varchar("version", { length: 64 }).notNull(),
  deploymentMode: varchar("deployment_mode", { length: 48 }).notNull().default("full_control_plane"),
  authorityProvider: varchar("authority_provider", { length: 32 }).notNull().default("mig_native"),
  executionFabric: varchar("execution_fabric", { length: 32 }).notNull().default("mig_managed"),
  providerTenantRef: varchar("provider_tenant_ref"),
  maximumSnapshotAgeSeconds: integer("maximum_snapshot_age_seconds").notNull().default(300),
  status: varchar("status", { length: 16 }).notNull().default("active"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  tenantVersionUnique: uniqueIndex("mig_tenant_authority_configs_tenant_version_unique").on(t.tenantId, t.version),
  tenantCreatedIdx: index("mig_tenant_authority_configs_tenant_created_idx").on(t.tenantId, t.createdAt),
  snapshotAgeCheck: check("mig_tenant_authority_configs_snapshot_age_check",
    sql`${t.maximumSnapshotAgeSeconds} > 0 AND ${t.maximumSnapshotAgeSeconds} <= 86400`),
}));

export type MigTenantAuthorityConfig = typeof migTenantAuthorityConfigs.$inferSelect;

export const migAuthoritySnapshots = pgTable("mig_authority_snapshots", {
  id: serial("id").primaryKey(),
  snapshotId: varchar("snapshot_id").notNull().unique(),
  tenantId: varchar("tenant_id").notNull(),
  provider: varchar("provider", { length: 32 }).notNull(),
  authorityRef: varchar("authority_ref").notNull(),
  providerTenantRef: varchar("provider_tenant_ref"),
  providerSubjectRef: varchar("provider_subject_ref"),
  principalId: varchar("principal_id").notNull(),
  agentId: varchar("agent_id"),
  targetIds: jsonb("target_ids").notNull().default(sql`'[]'::jsonb`),
  capabilityIds: jsonb("capability_ids").notNull().default(sql`'[]'::jsonb`),
  domainIds: jsonb("domain_ids").notNull().default(sql`'[]'::jsonb`),
  resourceScopes: jsonb("resource_scopes").notNull().default(sql`'[]'::jsonb`),
  assignedRoles: jsonb("assigned_roles").notNull().default(sql`'[]'::jsonb`),
  sourceEvidence: jsonb("source_evidence").notNull().default(sql`'[]'::jsonb`),
  riskZoneCeiling: varchar("risk_zone_ceiling", { length: 16 }).notNull(),
  observedAt: timestamp("observed_at").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  syncState: varchar("sync_state", { length: 24 }).notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (t) => ({
  tenantAuthorityIdx: index("mig_authority_snapshots_tenant_authority_idx").on(t.tenantId, t.authorityRef, t.createdAt),
}));

export type InsertMigJourneyIntentTransitionRevocation = typeof migJourneyIntentTransitionRevocations.$inferInsert;

export type MigJourneyIntentTransitionRevocation = typeof migJourneyIntentTransitionRevocations.$inferSelect;

export { type InsertMcpContractAuthRelationship, type McpContractAuthRelationship, mcpContractAuthRelationships, type InsertMcpContractInvocationReference, type McpContractInvocationReference, mcpContractInvocationReferences, type InsertMcpCapabilityContract, type McpCapabilityContract, mcpCapabilityContracts } from "./schema-mcp-contracts";
