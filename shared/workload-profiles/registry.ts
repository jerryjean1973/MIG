import { readOwnerCatalog } from "../../server/standalone/catalog";
export const workloadProfileRegistry = {
  has(technology: string, deploymentType: string) {
    return readOwnerCatalog().workloads.some(profile =>
      profile.technology.toLowerCase() === technology.toLowerCase() && profile.deployment_type === deploymentType);
  },
  resolve(technology: string, deploymentType: string): any {
    const profile = readOwnerCatalog().workloads.find(profile =>
      profile.technology.toLowerCase() === technology.toLowerCase() && profile.deployment_type === deploymentType);
    if (!profile) throw new Error("MIG_OWNER_WORKLOAD_NOT_FOUND");
    return profile;
  },
  listAll(): any[] { return readOwnerCatalog().workloads; },
};
