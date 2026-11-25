import { readOwnerCatalog } from "../standalone/catalog";
export function getCapabilityContract(id: string): any {
  return readOwnerCatalog().capability_contracts.find(item => item.capability_id === id);
}
