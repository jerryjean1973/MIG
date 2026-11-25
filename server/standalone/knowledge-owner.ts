import { ownerCall } from "./owner-client";

// Canonical owner APIs remain external. These are transport projections only.
export const databaseKnowledgeAuthorityRepository = {
  listBindings: (tenantId: string) => ownerCall<any[]>("knowledge.listBindings", [tenantId], tenantId),
};
export const canonicalKnowledgeAuthorityService = {
  bindMcpCapability: (candidate: any, repository?: unknown) => {
    if (repository) throw new Error("MIG_REMOTE_REPOSITORY_OVERRIDE_UNSUPPORTED");
    return ownerCall("knowledge.bindMcpCapability", [candidate]);
  },
  authorizeAndPersist: (...args: any[]) => ownerCall("knowledge.authorizeAndPersist", args),
  recordMcpSchemaAccessAlert: (...args: any[]) => ownerCall("knowledge.recordMcpSchemaAccessAlert", args),
  listMcpSchemaAccessAlerts: (tenantId: string) => ownerCall("knowledge.listMcpSchemaAccessAlerts", [tenantId], tenantId),
  createMcpSchemaReviewCandidate: (...args: any[]) => ownerCall("knowledge.createMcpSchemaReviewCandidate", args),
};
export const corporateBrainKnowledgeService = {
  getGovernedKnowledgeById: (...args: any[]) => ownerCall("knowledge.getGovernedKnowledgeById", args),
};
export type CanonicalKnowledgeAuthorityRepository = unknown;
export type CanonicalKnowledgeAuthorityReceiptRepository = unknown;
export type CanonicalMCPBindingLookup = {
  tenant_id: string; binding_id: string; [key: string]: unknown;
};
