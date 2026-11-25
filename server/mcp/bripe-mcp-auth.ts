import { createHash } from "crypto";

import { storage } from "../storage";

import { MCP_CLASSIFICATION_RANK, type McpToolClassification } from "./bripe-mcp-schemas";

import type { McpApiKey, McpKeyClassification } from "@shared/schema";

export function hashMcpApiKey(rawKey: string): string {
  return createHash("sha256").update(rawKey.trim()).digest("hex");
}

export interface McpAuthResult {
  ok: true;
  tenantId: string;
  apiKeyId: number;
  /** Canonical principal selected when the key was issued. Legacy keys use the stable key principal. */
  principalId: string;
  canonicalPrincipalBound: boolean;
  migAgentId: string | null;
  classification: McpKeyClassification;
  /** Optional per-key tool allow-list. null/undefined = all tools at or below classification. */
  allowedTools: string[] | null;
  allowedIntents: string[] | null;
  allowedDomains: string[] | null;
  effectiveScopes: string[];
  resourceConstraints: Record<string, unknown>;
  environmentConstraints: Record<string, unknown>;
  networkConstraints: Record<string, unknown>;
}

export interface McpAuthFailure {
  ok: false;
  status: number;
  error: string;
}

export async function resolveMcpApiKey(rawKey: string | undefined | null): Promise<McpAuthResult | McpAuthFailure> {
  if (!rawKey || rawKey.trim().length === 0) {
    return { ok: false, status: 401, error: "Missing MCP API key. Supply it via the X-API-Key header." };
  }

  let record: McpApiKey | undefined;
  try {
    record = await storage.getMcpApiKeyByHash(hashMcpApiKey(rawKey));
  } catch (err) {
    console.error("[BRIPeMcpAuth] API key lookup failed:", err);
    return { ok: false, status: 401, error: "Invalid MCP API key" };
  }

  if (!record) {
    return { ok: false, status: 401, error: "Invalid or revoked MCP API key" };
  }

  // "pending_revocation" is the rotation grace window — the old key keeps
  // authenticating until expiresAt so a partner's integration doesn't break
  // the instant they rotate. Past expiresAt it is treated as revoked even if
  // the periodic sweep hasn't flipped the row yet.
  if (record.status === "revoked" || record.status === "disabled" || record.status === "review_required" || record.status === "expired") {
    return { ok: false, status: 401, error: "Invalid or revoked MCP API key" };
  }
  // Absolute expiry is enforced irrespective of lifecycle state. A pending
  // rotation uses the same field, so its grace semantics remain below.
  if (record.status === "active" && record.expiresAt && record.expiresAt.getTime() <= Date.now()) {
    return { ok: false, status: 401, error: "MCP API key has expired" };
  }
  if (record.reviewRequired || record.reviewState === "required") {
    return { ok: false, status: 401, error: "MCP API key requires administrative review" };
  }
  if (record.status === "pending_revocation" && (!record.expiresAt || record.expiresAt.getTime() <= Date.now())) {
    return { ok: false, status: 401, error: "MCP API key rotation grace period has expired" };
  }

  return {
    ok: true,
    tenantId: record.tenantId,
    apiKeyId: record.id,
    principalId: record.principalId || `mcp-api-key:${record.id}`,
    canonicalPrincipalBound: Boolean(record.principalId),
    migAgentId: record.migAgentId ?? null,
    classification: record.classification as McpKeyClassification,
    allowedTools: record.allowedTools && record.allowedTools.length > 0 ? record.allowedTools : null,
    allowedIntents: record.allowedIntents && record.allowedIntents.length > 0 ? record.allowedIntents : null,
    allowedDomains: record.allowedDomains && record.allowedDomains.length > 0 ? record.allowedDomains : null,
    effectiveScopes: Array.isArray(record.effectiveScopes) ? record.effectiveScopes.filter((value): value is string => typeof value === "string") : [],
    resourceConstraints: record.resourceConstraints && typeof record.resourceConstraints === "object" ? record.resourceConstraints as Record<string, unknown> : {},
    environmentConstraints: record.environmentConstraints && typeof record.environmentConstraints === "object" ? record.environmentConstraints as Record<string, unknown> : {},
    networkConstraints: record.networkConstraints && typeof record.networkConstraints === "object" ? record.networkConstraints as Record<string, unknown> : {},
  };
}

export function classificationPermits(keyClassification: McpKeyClassification, toolClassification: McpToolClassification): boolean {
  return MCP_CLASSIFICATION_RANK[keyClassification as McpToolClassification] >= MCP_CLASSIFICATION_RANK[toolClassification];
}

export function toolAllowedForKey(allowedTools: string[] | null | undefined, toolName: string): boolean {
  if (!allowedTools || allowedTools.length === 0) return true;
  return allowedTools.includes(toolName);
}
