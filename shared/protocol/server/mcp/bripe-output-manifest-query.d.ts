export declare const MAX_SAVED_OUTPUT_SECTION_BYTES: number;
export interface McpOutputManifestQueryOptions {
    tenantId: string;
    limit?: number;
    toolName?: string;
    status?: string;
    invocationId?: number;
    includePayloads?: boolean;
    outputPath?: string[];
    inspectOnly?: boolean;
    inspectionOffset?: number;
}
export declare function buildMcpOutputManifestQuery(opts: McpOutputManifestQueryOptions): any;
export type McpOutputManifestEntry = Awaited<ReturnType<typeof buildMcpOutputManifestQuery>>[number];
