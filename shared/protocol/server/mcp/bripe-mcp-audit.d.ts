import type { McpToolClassification } from "./bripe-mcp-schemas";
export interface McpInvocationContext {
    requestId: string;
    toolName: string;
    toolClassification: McpToolClassification;
    tenantId: string;
    apiKeyId?: number;
    canonicalService: string;
    capabilityId?: string;
    domainId?: string;
    packageId?: string;
    authorizationManifestId?: string;
    delegationJti?: string;
    authorizationDecisionId?: string;
    authorizationPolicyVersion?: string;
    migClientId?: string;
    migPrincipalId?: string;
    journeyId?: string;
    parentCallId?: string;
    originUserId?: string;
    originAgentId?: string;
    rootIntentId?: string;
    currentIntentId?: string;
    compoundedIntentIds?: string[];
    graphCallIds?: string[];
    resourceRef?: string;
    resourceVersion?: string;
}
