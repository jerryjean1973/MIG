export interface ContractGateRepository {
    listMcpCapabilityContractsByClient(clientId: string, tenantId: string): Promise<ContractGateContract[]>;
    getMcpCapabilityContract(contractId: string): Promise<ContractGateContract | undefined>;
    updateMcpCapabilityContract(contractId: string, patch: {
        status?: string;
    }): Promise<ContractGateContract | undefined>;
    checkMcpContractNonceUsed(nonce: string, contractId: string): Promise<boolean>;
    getMcpContractAuthRelationship(relationshipId: string): Promise<ContractGateAuthRelationship | undefined>;
    createMcpContractInvocationReference(data: ContractGateInvocationReference): Promise<unknown>;
}
export interface ContractGateContract {
    contractId: string;
    contractVersion: number;
    tenantId: string;
    capabilityId: string;
    clientId: string;
    status: string;
    validUntil?: Date | string | null;
    contractJson?: unknown;
}
export interface ContractGateAuthRelationship {
    relationshipId?: string;
    contractId: string;
    status: string;
    validUntil?: Date | string | null;
    migAttestation?: string | null;
}
export interface ContractGateInvocationReference {
    invocationRefId: string;
    contractId: string;
    contractVersion: number;
    tenantId: string;
    capabilityId: string;
    clientId: string;
    authorizationRelationshipId: string;
    toolName: string;
    nonce: string;
    gateResult: "pass" | "fail";
    failureCode?: string;
    hash: string;
    lineageJson: unknown;
}
