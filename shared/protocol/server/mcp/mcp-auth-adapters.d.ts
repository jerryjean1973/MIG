export interface McpMigLineageContext {
    journeyId: string;
    parentCallId: string;
    originUserId: string;
    originAgentId: string;
    rootIntentId: string;
    rootIntent: string;
    compoundedIntentIds: string[];
    graphCallIds: string[];
}
