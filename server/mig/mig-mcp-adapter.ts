/**
 * server/mig/mig-mcp-adapter.ts
 *
 * Protocol-facing adapter: wraps a MigDownstreamAdapter (bripeMcpAdapter by
 * default) with manifest-based gating. This is what external MCP discovery
 * and execution requests actually go through — it never talks to storage
 * or policy directly, it only enforces what a previously-built
 * MigCapabilityManifest already decided.
 */

import type { MigCapabilityManifest } from "@shared/schema";
import type { MigDownstreamAdapter, MigAdapterToolEntry } from "./mig-types";
import { bripeMcpAdapter, bripeToolCatalog } from "./mig-bripe-adapter";
import { consumeMigDelegation } from "./mig-delegation";

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** Trusted adapter metadata never comes from the caller's tool arguments. */
export function getGatedAuthorityAssertionInput(
  toolName: string, input: Record<string, unknown>,
  adapter: MigDownstreamAdapter = bripeMcpAdapter,
): Record<string, unknown> | Promise<Record<string, unknown>> {
  return adapter.authorityAssertionInput?.(toolName, input) ?? input;
}

export function getGatedToolList(
  manifest: MigCapabilityManifest,
  adapter: Pick<MigDownstreamAdapter, "listTools"> = { listTools: bripeToolCatalog },
): MigAdapterToolEntry[] {
  const allowed = new Set(asStringArray(manifest.allowedMcpTools));
  return adapter.listTools().filter(t => allowed.has(t.tool_name));
}

export interface GatedExecutionResult {
  allowed: boolean;
  reason?: string;
  output?: unknown;
}

/** Non-executing manifest boundary, used before any consequential PDP work. */
export function checkGatedToolAuthorization(
  manifest: MigCapabilityManifest,
  toolName: string,
): Pick<GatedExecutionResult, "allowed" | "reason"> {
  const allowed = new Set(asStringArray(manifest.allowedMcpTools));
  const denied = new Set(asStringArray(manifest.deniedMcpTools));
  if (denied.has(toolName)) return { allowed: false, reason: "tool_explicitly_denied_by_manifest" };
  if (!allowed.has(toolName)) return { allowed: false, reason: "tool_not_in_authorized_manifest" };
  return { allowed: true };
}

export async function executeGatedTool(
  manifest: MigCapabilityManifest,
  toolName: string,
  input: unknown,
  ctx: {
    tenantId: string;
    delegationToken?: string;
    delegationExpectation?: {
      requestId: string;
      mcpMethod: string;
      resourceRef: string;
      resourceVersion?: string;
      toolName?: string;
    };
  },
  adapter: MigDownstreamAdapter = bripeMcpAdapter,
): Promise<GatedExecutionResult> {
  const authorization = checkGatedToolAuthorization(manifest, toolName);
  if (!authorization.allowed) return authorization;
  if (!ctx.delegationExpectation) return { allowed: false, reason: "mig_delegation_missing" };
  const delegation = await consumeMigDelegation(ctx.delegationToken, {
    tenantId: ctx.tenantId,
    ...ctx.delegationExpectation,
    toolName,
  });
  if (!delegation.valid) return { allowed: false, reason: delegation.reason };
  if (!delegation.payload.tools.some(binding => binding.toolName === toolName)) {
    return { allowed: false, reason: "mig_delegation_tool_mismatch" };
  }

  const output = await adapter.executeTool(toolName, input, ctx);
  return { allowed: true, output };
}
