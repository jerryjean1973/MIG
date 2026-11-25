import { readOwnerCatalog } from "../standalone/catalog";
import { ownerCall } from "../standalone/owner-client";
import { z } from "zod";

/** Metadata only. No tool handler or engine implementation is bundled here. */
export function getMcpTool(name: string) {
  const tool = readOwnerCatalog().raw_tools.find(item => item.name === name);
  return tool ? {
    ...tool,
    inputSchema: z.object({}).passthrough(),
    transportInputSchema: z.object({}).passthrough(),
    parseInput: (input: unknown) => ownerCall("tool.input.validate", [name, input]),
    validateOutput: (output: unknown) => ownerCall("tool.output.validate", [name, output]),
    handler: (input: unknown, ctx: any) => ownerCall("tool.execute", [name, input, ctx], ctx.tenantId),
  } : undefined;
}
export function getActiveMcpTools(): any[] {
  return readOwnerCatalog().raw_tools.map(tool => getMcpTool(tool.name)!);
}
export const MCP_CAPABILITY_GROUPS = new Proxy([] as Array<{ group: string; tools: string[] }>, {
  get(_target, key) {
    const groups = readOwnerCatalog().groups;
    const value = Reflect.get(groups, key);
    return typeof value === "function" ? value.bind(groups) : value;
  },
});
// MS5 reads the current list at review time, not a fabricated startup catalog.
export const ALL_MCP_TOOLS = new Proxy([] as any[], {
  get(_target, key) {
    const tools = readOwnerCatalog().raw_tools;
    const value = Reflect.get(tools, key);
    return typeof value === "function" ? value.bind(tools) : value;
  },
});
