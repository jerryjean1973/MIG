import { ownerCall } from "../standalone/owner-client";
import type { CanonicalKnowledgeAuthorityReceipt } from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";

/** The external owner reconstructs the existing trusted evaluators; callbacks
 * and caller-provided repositories are never transported as authority. */
export async function authorizeProtectedMcpDispatch(input: {
  lookup: { tenant_id: string; binding_id: string; [key: string]: unknown };
  principal: unknown; evaluated_at?: string;
  authorityRepository?: unknown; receiptRepository?: unknown;
  trustedResults: unknown;
}): Promise<CanonicalKnowledgeAuthorityReceipt> {
  if (input.authorityRepository || input.receiptRepository) {
    throw new Error("MIG_REMOTE_REPOSITORY_OVERRIDE_UNSUPPORTED");
  }
  return ownerCall("knowledge.authorizeProtectedMcpInvocation", [{
    lookup: input.lookup, principal: input.principal, evaluated_at: input.evaluated_at,
    trustedResults: input.trustedResults,
  }], input.lookup.tenant_id);
}
