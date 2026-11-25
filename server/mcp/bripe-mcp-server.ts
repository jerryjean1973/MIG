import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { readOwnerCatalog } from "../standalone/catalog";
/**
 * server/mcp/bripe-mcp-server.ts
 *
 * Builds a per-request McpServer instance wired to the BRIPe MCP tool
 * registry. Every tool call is:
 *   1. classification-checked against the caller's API key ceiling,
 *   2. delegated to the canonical service via bripe-mcp-tools.ts,
 *   3. audited (input/output hashes, canonical service, tenant) via
 *      bripe-mcp-audit.ts.
 *
 * Stateless per-request server construction is intentional: it keeps tenant
 * context bound via closure instead of a shared/global session, so there is
 * no cross-tenant bleed between concurrent MCP calls.
 */

import { McpServer, type RegisteredTool } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getActiveMcpTools } from "./bripe-mcp-tools";
import { classificationPermits, toolAllowedForKey } from "./bripe-mcp-auth";
import { beginMcpInvocation, recordMcpInvocationSuccess, recordMcpInvocationFailure, type McpDecisionMetrics } from "./bripe-mcp-audit";
import type { McpKeyClassification } from "@shared/schema";
import { consumeMigDelegation, verifyMigDelegation } from "../mig/mig-delegation";
import { getBripeToolAuthorizationEntry } from "../mig/mig-bripe-adapter";
import type { CanonicalMCPKnowledgeBinding } from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";
import { MCP_INGESTION_INSTRUCTIONS } from "./mcp-ingestion-guidance";
import { withMcpClientWorkflow } from "./mcp-client-workflow";
import { isByolabDomainCaller, isByolabDomainTool } from "./byolab-domain-access";

export interface McpServerContext {
  tenantId: string;
  principalId?: string;
  apiKeyId?: number;
  classification: McpKeyClassification;
  /** Optional per-key tool allow-list. null/undefined = no per-tool restriction. */
  allowedTools?: string[] | null;
  delegationToken?: string;
  delegationExpectation?: {
    requestId: string;
    mcpMethod: string;
    resourceRef: string;
    resourceVersion?: string;
    toolName?: string;
  };
  migAllowedTools?: string[];
  /** Server-resolved canonical resource binding from the protected MIG route. */
  canonicalKnowledgeBinding?: CanonicalMCPKnowledgeBinding;
  /** Exact tools admitted by MIG for this client's capability inventory. */
  capabilityInventoryToolNames?: string[];
  migAudit?: Omit<import("../../shared/protocol/server/mcp/bripe-mcp-audit").McpInvocationContext,
    "requestId" | "toolName" | "toolClassification" | "tenantId" | "canonicalService">;
}

const MCP_SERVER_VERSION = "1.1.0";
const registeredTools = new WeakMap<McpServer, Map<string, RegisteredTool>>();

export function createBripeMcpServer(ctx: McpServerContext): McpServer {
  const server = new McpServer(
    { name: "bripe-mcp", version: MCP_SERVER_VERSION },
    { capabilities: { tools: {} }, instructions: MCP_INGESTION_INSTRUCTIONS + (
      isByolabDomainCaller({ tenantId: ctx.tenantId, principalId: ctx.principalId, clientId: ctx.migAudit?.migClientId })
        ? "\nByolab historical events: use the byolab_historical_events intent within your effective grants. Read get_historical_event_contract for the complete batch schema; submit_historical_events captures source assertions only. Retrieve the original receipt with get_historical_event_receipt under the same authorized resource reference. Follow receipt next_step instructions; a source receipt is an intermediate response, not a final business answer, adaptation qualification or action authorization."
        : "") },
  );
  refreshBripeMcpServerTools(server, ctx);
  server.server.setRequestHandler(ListToolsRequestSchema, async () => {
    const proof = ctx.delegationExpectation ? verifyMigDelegation(ctx.delegationToken, {
      tenantId: ctx.tenantId, ...ctx.delegationExpectation,
    }) : undefined;
    const allowed = new Set(proof?.valid ? proof.payload.tools.map(tool => tool.toolName) : []);
    return { tools: readOwnerCatalog().raw_tools.filter(tool => allowed.has(tool.name)).map(tool => ({
      name: tool.name, description: tool.description, inputSchema: tool.inputSchema,
      ...(tool.protocolOutputSchema ? { outputSchema: tool.protocolOutputSchema } : {}),
    })) };
  });
  return server;
}

export function refreshBripeMcpServerTools(server: McpServer, ctx: McpServerContext): void {
  const preflight = ctx.delegationExpectation
    ? verifyMigDelegation(ctx.delegationToken, {
        tenantId: ctx.tenantId,
        ...ctx.delegationExpectation,
      })
    : undefined;
  const signedToolNames = preflight?.valid
    ? new Set(preflight.payload.tools.map(binding => binding.toolName))
    : new Set<string>();
  if (!isByolabDomainCaller({
    tenantId: ctx.tenantId, principalId: ctx.principalId, clientId: ctx.migAudit?.migClientId,
  })) {
    for (const name of signedToolNames) if (isByolabDomainTool(name)) signedToolNames.delete(name);
  }
  let registered = registeredTools.get(server);
  if (!registered) {
    registered = new Map<string, RegisteredTool>();
    registeredTools.set(server, registered);
  }
  for (const [name, tool] of registered) {
    const shouldEnable = signedToolNames.has(name);
    if (shouldEnable && !tool.enabled) tool.enable();
    else if (!shouldEnable && tool.enabled) tool.disable();
  }

  for (const tool of getActiveMcpTools().filter(candidate => signedToolNames.has(candidate.name) && !registered!.has(candidate.name))) {
    const registration = server.registerTool(
      tool.name,
      {
        title: tool.name,
        // Plain JSON Schema is retained on the tool definition for documentation.
        // Tools with an MCP-native Zod output contract publish it through tools/list.
        description: `[${tool.classification}] ${tool.description} (canonical_service: ${tool.canonical_service})${tool.outputSchema ? ` | output_schema: ${JSON.stringify(tool.outputSchema)}` : ""}`,
        // Source-specific MSSP tools must preserve unknown caller keys until
        // the authenticated authority-argument check can reject them. A raw
        // Zod shape would silently strip forged fields before this callback.
        inputSchema: ((tool as typeof tool & { transportInputSchema?: any }).transportInputSchema ?? (tool.inputSchema instanceof z.ZodObject
          ? ((tool.name.startsWith("mssp_ingest_") && tool.name.endsWith("_observations")) || isByolabDomainTool(tool.name)
              ? tool.inputSchema.passthrough()
              : tool.inputSchema.shape as any)
          : undefined)),
        outputSchema: (tool.mcpOutputSchema instanceof z.ZodObject ? (tool.mcpOutputSchema.shape as any) : undefined),
      },
      async (rawInput: unknown) => {
        const startedAt = Date.now();
        const verification = ctx.delegationExpectation
          ? await consumeMigDelegation(ctx.delegationToken, {
              tenantId: ctx.tenantId,
              ...ctx.delegationExpectation,
              toolName: tool.name,
            })
          : { valid: false as const, reason: "mig_delegation_missing" };
        const binding = verification.valid
          ? verification.payload.tools.find(item => item.toolName === tool.name)
          : undefined;
        const expectedAction = tool.classification === "read_only" ? "read"
          : tool.classification === "execution" ? "execute"
          : "administer";
        const governedMapping = getBripeToolAuthorizationEntry(tool.name);
        const invocation = beginMcpInvocation({
          toolName: tool.name,
          toolClassification: tool.classification,
          tenantId: ctx.tenantId,
          apiKeyId: ctx.apiKeyId,
          canonicalService: tool.canonical_service,
          capabilityId: binding?.capabilityId,
          domainId: binding?.domainId,
          authorizationManifestId: binding?.authorizationManifestId,
          delegationJti: verification.valid ? verification.payload.jti : undefined,
          authorizationDecisionId: binding?.authorizationDecisionId,
          authorizationPolicyVersion: binding?.policyVersion,
          requestId: verification.valid ? verification.payload.requestId : undefined,
          ...ctx.migAudit,
        });

        if (!verification.valid || !binding ||
            binding.canonicalService !== tool.canonical_service ||
            binding.semanticAction !== expectedAction ||
            !governedMapping ||
            binding.mutationClass !== governedMapping.mutation_class ||
            binding.resourceType !== governedMapping.resource_types?.[0] ||
             (tool.name.startsWith("mssp_ingest_") && tool.name.endsWith("_observations") &&
               (binding.capabilityId !== governedMapping.capability_id ||
                !governedMapping.domain_scope.includes(binding.domainId))) ||
            !verification.payload.effectiveScopes.includes(binding.capabilityId)) {
          const deniedResult = {
            isError: true,
            content: [{ type: "text" as const, text: `Access denied: ${verification.valid ? "MIG tool binding invalid" : verification.reason}.` }],
          };
          await recordMcpInvocationFailure(invocation, rawInput, "MIG_DELEGATION_DENIED", startedAt, deniedResult);
          return deniedResult;
        }

        if (!classificationPermits(ctx.classification, tool.classification)) {
          const deniedResult = {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: `Access denied: tool "${tool.name}" requires "${tool.classification}" classification; this key is capped at "${ctx.classification}".`,
              },
            ],
          };
          await recordMcpInvocationFailure(invocation, rawInput, "CLASSIFICATION_DENIED", startedAt, deniedResult);
          return deniedResult;
        }

        if (!toolAllowedForKey(ctx.allowedTools, tool.name)) {
          const deniedResult = {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: `Access denied: tool "${tool.name}" is not in this key's allowed-tools list.`,
              },
            ],
          };
          await recordMcpInvocationFailure(invocation, rawInput, "TOOL_NOT_ALLOWLISTED", startedAt, deniedResult);
          return deniedResult;
        }

        const authorityKeys = new Set([
          "actor", "actor_id", "actorPrincipalId", "principal", "principal_id",
          "roles", "role", "groups", "group", "scopes", "scope",
          "authorization", "authorization_state", "policy_decision",
        ]);
        const supplied = rawInput && typeof rawInput === "object" && !Array.isArray(rawInput)
          ? rawInput as Record<string, unknown>
          : {};
        const selfAsserted = Object.keys(supplied).filter(key => authorityKeys.has(key));
        if (selfAsserted.length > 0 || (Object.hasOwn(supplied, "tenant_id") && supplied.tenant_id !== ctx.tenantId)) {
          const deniedResult = {
            isError: true,
            content: [{ type: "text" as const, text: "Access denied: tool arguments cannot assert authorization identity, scope, role, group, policy, or tenant." }],
          };
          await recordMcpInvocationFailure(invocation, rawInput, "AUTHORITY_ARGUMENT_CONFLICT", startedAt, deniedResult);
          return deniedResult;
        }
        const trustedInput = { ...supplied, tenant_id: ctx.tenantId };
        let parsedInput: unknown = trustedInput;
        try {
          const remoteParser = (tool as typeof tool & {
            parseInput?: (input: unknown) => Promise<unknown>;
          }).parseInput;
          parsedInput = remoteParser ? await remoteParser(trustedInput) : tool.inputSchema.parse(trustedInput);
        } catch (err) {
          const invalidResult = {
            isError: true,
            content: [{ type: "text" as const, text: `Invalid input for tool "${tool.name}": ${(err as Error).message}` }],
          };
          await recordMcpInvocationFailure(invocation, rawInput, "INPUT_VALIDATION_FAILED", startedAt, invalidResult);
          return invalidResult;
        }

        try {
          const capabilityInventoryToolNames = ["list_capabilities", "search_capabilities", "get_capability_contract"].includes(tool.name)
            ? (ctx.capabilityInventoryToolNames ?? [])
            : undefined;
          const ownerResult = await tool.handler(parsedInput, {
            tenantId: ctx.tenantId,
            principalId: ctx.principalId,
            intentId: verification.payload.intentId,
            capabilityId: binding.capabilityId,
            // These identities come exclusively from authenticated MIG
            // dispatch state and the one-shot delegation, never MCP arguments.
            migClientId: ctx.migAudit?.migClientId,
            requestId: verification.payload.requestId,
             resourceRef: verification.payload.resourceRef,
            canonicalKnowledgeBinding: ctx.canonicalKnowledgeBinding,
            authorizedToolNames: capabilityInventoryToolNames,
            authorizedCapabilityIds: capabilityInventoryToolNames
              ? [...new Set(capabilityInventoryToolNames
                  .map(name => getBripeToolAuthorizationEntry(name)?.capability_id)
                  .filter((value): value is string => Boolean(value)))]
              : undefined,
          });
          const result = withMcpClientWorkflow(tool.name, ownerResult, parsedInput);
          const remoteOutputValidator = (tool as typeof tool & {
            validateOutput?: (output: unknown) => Promise<unknown>;
          }).validateOutput;
          if (remoteOutputValidator) await remoteOutputValidator(result);
          // For run_bripe_decision: extract structured metrics and persist the full GDP JSON.
          let metrics: McpDecisionMetrics | undefined;
          if (tool.name === "run_bripe_decision" && result !== null && typeof result === "object" && !Array.isArray(result)) {
            const r = result as Record<string, unknown>;
            const decision = r.decision as Record<string, unknown> | undefined;
            const meta = r.metadata as Record<string, unknown> | undefined;
            const adamAuth = r.adam_authorization as Record<string, unknown> | undefined;
            metrics = {
              ttbDays:              typeof decision?.ttb_days === "number" ? Math.round(decision.ttb_days) : null,
              ttfDays:              typeof decision?.ttf_days === "number" ? Math.round(decision.ttf_days) : null,
              propagationScore:     typeof decision?.propagation_score === "number" ? decision.propagation_score : null,
              manifestId:           typeof meta?.run_id === "string" ? meta.run_id : undefined,
              fullOutputJson:       r as Record<string, unknown>,
              inputPayload:         (parsedInput !== null && typeof parsedInput === "object" && !Array.isArray(parsedInput))
                                      ? parsedInput as Record<string, unknown>
                                      : null,
              adamOutcome:          typeof adamAuth?.outcome === "string" ? adamAuth.outcome : null,
              adamProofManifestId:  typeof adamAuth?.proof_manifest_id === "string" ? adamAuth.proof_manifest_id : null,
              adamDowngradeReason:  typeof adamAuth?.downgrade_reason === "string" ? adamAuth.downgrade_reason : null,
            };
          }
          await recordMcpInvocationSuccess(invocation, parsedInput, result, startedAt, metrics);
          // structuredContent must be a plain record — the MCP schema rejects
          // arrays/primitives here even though `typeof [] === "object"` in JS.
          const isPlainRecord =
            result !== null && typeof result === "object" && !Array.isArray(result);
          const structuredContent = isPlainRecord
            ? (result as Record<string, unknown>)
            : { result };
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
            structuredContent,
          };
        } catch (err) {
          console.error(`[BRIPeMcpServer] Tool "${tool.name}" failed:`, err);
          const failedResult = {
            isError: true,
            content: [{ type: "text" as const, text: `Tool "${tool.name}" execution failed: ${(err as Error).message}` }],
          };
          await recordMcpInvocationFailure(invocation, parsedInput, "TOOL_EXECUTION_FAILED", startedAt, failedResult);
          return failedResult;
        }
      },
    );
    registered.set(tool.name, registration);
  }
}
