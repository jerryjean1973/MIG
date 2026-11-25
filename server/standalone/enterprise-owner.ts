import { ownerCall } from "./owner-client";
export const createScopedCEOStore = (tenantId: string) => ({
  listEnterpriseObjects: (requestedTenant: string, filter: unknown, limit: number) => {
    if (requestedTenant !== tenantId) throw new Error("MIG_OWNER_TENANT_MISMATCH");
    return ownerCall<any[]>("enterprise.listCapabilities", [requestedTenant, filter, limit], tenantId);
  },
});
