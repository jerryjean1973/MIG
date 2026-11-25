export const MCP_TOOL_CLASSIFICATIONS = ["read_only", "execution", "admin"] as const;

export type McpToolClassification = typeof MCP_TOOL_CLASSIFICATIONS[number];

export const MCP_CLASSIFICATION_RANK: Record<McpToolClassification, number> = {
  read_only: 0,
  execution: 1,
  admin: 2,
};
