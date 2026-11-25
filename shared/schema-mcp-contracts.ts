/**
 * shared/schema-mcp-contracts.ts
 *
 * Drizzle ORM table definitions for the MCP Capability Contract Negotiation layer.
 * All 10 tables carry: tenant_id, capability_id, client_id, created_at, hash, lineage_json.
 * Imported as a barrel by shared/schema.ts.
 */
import { sql } from "drizzle-orm";

import { pgTable, text, varchar, serial, integer, timestamp, jsonb } from "drizzle-orm/pg-core";

import { createInsertSchema } from "drizzle-zod";

import { z } from "zod";

export const mcpCapabilityContracts = pgTable("mcp_capability_contracts", {
  id: serial("id").primaryKey(),
  contractId: varchar("contract_id").notNull().unique(),
  contractVersion: integer("contract_version").notNull().default(1),
  tenantId: varchar("tenant_id").notNull(),
  capabilityId: varchar("capability_id").notNull(),
  clientId: varchar("client_id").notNull(),
  negotiationId: varchar("negotiation_id").notNull(),
  serverIdentity: varchar("server_identity", { length: 128 }).notNull().default("bripe-mcp"),
  supersedesContractId: varchar("supersedes_contract_id"),
  status: varchar("status", { length: 32 }).notNull().default("draft"),
  validFrom: timestamp("valid_from"),
  validUntil: timestamp("valid_until"),
  acceptedByClient: timestamp("accepted_by_client"),
  acceptedByServer: timestamp("accepted_by_server"),
  contractJson: jsonb("contract_json").notNull().default(sql`'{}'::jsonb`),
  hash: varchar("hash", { length: 128 }).notNull().default(""),
  lineageJson: jsonb("lineage_json").notNull().default(sql`'{}'::jsonb`),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMcpCapabilityContractSchema = createInsertSchema(mcpCapabilityContracts).omit({
  id: true, createdAt: true, updatedAt: true,
});

export type McpCapabilityContract = typeof mcpCapabilityContracts.$inferSelect;

export type InsertMcpCapabilityContract = z.infer<typeof insertMcpCapabilityContractSchema>;

export const mcpContractAuthRelationships = pgTable("mcp_contract_auth_relationships", {
  id: serial("id").primaryKey(),
  relationshipId: varchar("relationship_id").notNull().unique(),
  contractId: varchar("contract_id").notNull(),
  contractVersion: integer("contract_version").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  capabilityId: varchar("capability_id").notNull(),
  clientId: varchar("client_id").notNull(),
  issuedAt: timestamp("issued_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  validUntil: timestamp("valid_until"),
  migAttestation: text("mig_attestation").notNull(),
  attestationFingerprint: varchar("attestation_fingerprint", { length: 128 }).notNull(),
  status: varchar("status", { length: 32 }).notNull().default("active"),
  hash: varchar("hash", { length: 128 }).notNull().default(""),
  lineageJson: jsonb("lineage_json").notNull().default(sql`'{}'::jsonb`),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMcpContractAuthRelationshipSchema = createInsertSchema(mcpContractAuthRelationships).omit({
  id: true, createdAt: true, issuedAt: true,
});

export type McpContractAuthRelationship = typeof mcpContractAuthRelationships.$inferSelect;

export type InsertMcpContractAuthRelationship = z.infer<typeof insertMcpContractAuthRelationshipSchema>;

export const mcpContractInvocationReferences = pgTable("mcp_contract_invocation_references", {
  id: serial("id").primaryKey(),
  invocationRefId: varchar("invocation_ref_id").notNull().unique(),
  contractId: varchar("contract_id").notNull(),
  contractVersion: integer("contract_version").notNull(),
  tenantId: varchar("tenant_id").notNull(),
  capabilityId: varchar("capability_id").notNull(),
  clientId: varchar("client_id").notNull(),
  authorizationRelationshipId: varchar("authorization_relationship_id").notNull(),
  toolName: varchar("tool_name").notNull(),
  nonce: varchar("nonce", { length: 256 }).notNull(),
  gateResult: varchar("gate_result", { length: 32 }).notNull().default("pass"),
  failureCode: varchar("failure_code", { length: 64 }),
  hash: varchar("hash", { length: 128 }).notNull().default(""),
  lineageJson: jsonb("lineage_json").notNull().default(sql`'{}'::jsonb`),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertMcpContractInvocationReferenceSchema = createInsertSchema(mcpContractInvocationReferences).omit({
  id: true, createdAt: true,
});

export type McpContractInvocationReference = typeof mcpContractInvocationReferences.$inferSelect;

export type InsertMcpContractInvocationReference = z.infer<typeof insertMcpContractInvocationReferenceSchema>;
