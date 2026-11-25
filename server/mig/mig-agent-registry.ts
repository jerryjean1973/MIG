/**
 * server/mig/mig-agent-registry.ts
 *
 * Remote Agent Registry — thin governance wrapper over storage for
 * mig_remote_agents. No BRIPe/MCP knowledge lives here.
 */

import { storage } from "../storage";
import { generateAgentSecret } from "./mig-auth";
import type {
  MigRemoteAgent,
  InsertMigRemoteAgent,
  MigAgentStatus,
  MigAgentLifecycleState,
} from "@shared/schema";

export interface RegisterAgentInput {
  agentId: string;
  tenantId: string;
  displayName: string;
  agentType?: string;
  principalId?: string;
  trustLevel?: "standard" | "elevated" | "privileged";
  allowedIntentLibraries?: string[];
  allowedIntents?: string[];
  allowedDomains?: string[];
  allowedPackages?: string[];
  allowedRiskZones?: string[];
  maxCapabilityClassification?: "read_only" | "execution" | "admin";
  requiresHumanApproval?: boolean;
  oauthClientId?: string;
  jwksUrl?: string;
  createdBy?: string;
  /**
   * Defaults to "discovery" — a brand-new agent must be observed before it
   * is bound to any hand-authored intent scope (task-1800). Callers that
   * need the legacy hand-authored-scope path (an admin already knows the
   * exact intent set to grant) may explicitly pass "active".
   */
  lifecycleState?: MigAgentLifecycleState;
}

export async function registerMigAgent(input: RegisterAgentInput): Promise<{ agent: MigRemoteAgent; ticketSecret: string }> {
  const ticketSecret = generateAgentSecret();
  const principalId = input.principalId ?? `mig-agent:${input.agentId}`;
  const existingPrincipal = await storage.getMigPrincipal(input.tenantId, principalId);
  if (input.principalId && !existingPrincipal) {
    throw new Error("MIG_EXPLICIT_PRINCIPAL_NOT_FOUND");
  }
  if (!existingPrincipal) {
    await storage.createMigPrincipal({
      principalId,
      tenantId: input.tenantId,
      principalType: "agent",
      subjectRef: `mig-agent:${input.agentId}`,
      displayName: input.displayName,
      status: "active",
    });
  }
  const data: InsertMigRemoteAgent = {
    agentId: input.agentId,
    tenantId: input.tenantId,
    displayName: input.displayName,
    agentType: input.agentType ?? "external_mcp_client",
    principalId,
    trustLevel: input.trustLevel ?? "standard",
    allowedIntentLibraries: input.allowedIntentLibraries ?? [],
    allowedIntents: input.allowedIntents ?? [],
    allowedDomains: input.allowedDomains ?? [],
    allowedPackages: input.allowedPackages ?? [],
    allowedRiskZones: input.allowedRiskZones ?? ["low"],
    maxCapabilityClassification: input.maxCapabilityClassification ?? "read_only",
    requiresHumanApproval: input.requiresHumanApproval ?? false,
    oauthClientId: input.oauthClientId,
    jwksUrl: input.jwksUrl,
    ticketSecret,
    status: "active",
    lifecycleState: input.lifecycleState ?? "discovery",
    createdBy: input.createdBy,
  };
  const agent = await storage.createMigAgent(data);
  return { agent, ticketSecret };
}

export async function getMigAgent(agentId: string): Promise<MigRemoteAgent | undefined> {
  return storage.getMigAgentByAgentId(agentId);
}

export async function listMigAgents(tenantId?: string): Promise<MigRemoteAgent[]> {
  return storage.listMigAgents(tenantId);
}

export async function setMigAgentStatus(agentId: string, status: MigAgentStatus): Promise<MigRemoteAgent | undefined> {
  return storage.setMigAgentStatus(agentId, status);
}

export async function updateMigAgentScope(
  agentId: string,
  patch: Partial<InsertMigRemoteAgent>,
): Promise<MigRemoteAgent | undefined> {
  return storage.updateMigAgent(agentId, patch);
}

export function isAgentUsable(agent: MigRemoteAgent | undefined): agent is MigRemoteAgent {
  return !!agent && agent.status === "active";
}
