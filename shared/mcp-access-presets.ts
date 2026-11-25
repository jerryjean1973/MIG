export const MCP_ACCESS_PRESETS = {
  read_only: ["read"],
  analyze: ["read", "analyze", "execute"],
  analyze_propose: ["read", "analyze", "propose", "execute"],
  approver: ["read", "analyze", "approve"],
  custom: ["read"],
} as const;
