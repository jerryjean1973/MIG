export const REMOTE_MCP_CLIENT_KINDS = ["claude_desktop", "claude_code", "vscode_copilot"] as const;

export type RemoteMcpClientKind = typeof REMOTE_MCP_CLIENT_KINDS[number];

export interface RemoteMcpClientProjection {
  id: string;
  name: string;
  clientKind: RemoteMcpClientKind;
  preset: "read_only";
  status: string;
  createdAt: string;
}

export function buildRemoteMcpConfig(kind: RemoteMcpClientKind, endpoint: string, secret: string) {
  const url = new URL(endpoint);
  if (url.protocol !== "https:" || url.pathname !== "/api/mcp" || url.search || url.hash ||
      url.username || url.password || ["localhost", "0.0.0.0", "[::1]", "[::]"].includes(url.hostname) ||
      url.hostname.endsWith(".localhost") || url.hostname.startsWith("127.")) {
    throw new Error("Configure MCP_RESOURCE_URL with this application's externally reachable HTTPS /api/mcp address.");
  }
  const headers = { "x-mig-api-key": secret, Accept: "application/json, text/event-stream" };
  const server = { type: "http", url: url.href, headers };
  if (kind === "claude_desktop") return {
    endpoint: url.href,
    filename: "claude_desktop_config.json",
    config: JSON.stringify({ mcpServers: { bcentrisk: {
      command: "npx", args: ["-y", "mcp-remote", url.href, "--transport", "http-only",
        "--header", "x-mig-api-key:${BCENTRISK_MCP_KEY}", "--header", "Accept:application/json, text/event-stream"],
      env: { BCENTRISK_MCP_KEY: secret },
    } } }, null, 2),
    instructions: [
      "Requires Claude Desktop and Node.js with npx on this computer. This uses the mcp-remote stdio-to-HTTP bridge.",
      "Merge the bcentrisk entry into claude_desktop_config.json (Settings → Developer → Edit Config), then restart Claude Desktop.",
      "This file contains your secret. Store it privately; do not commit or share it.",
    ],
  };
  if (kind === "claude_code") return {
    endpoint: url.href, filename: ".mcp.json",
    config: JSON.stringify({ mcpServers: { bcentrisk: server } }, null, 2),
    instructions: [
      "Requires a current Claude Code version supporting HTTP MCP servers.",
      "Merge this entry into your project's .mcp.json and approve the server in Claude Code. Keep this sensitive file out of source control.",
    ],
  };
  if (kind !== "vscode_copilot") throw new Error("Unsupported remote MCP client");
  return {
    endpoint: url.href, filename: "mcp.json",
    config: JSON.stringify({ servers: { bcentrisk: server } }, null, 2),
    instructions: [
      "Requires a current VS Code with GitHub Copilot Chat and HTTP MCP support.",
      "Merge into .vscode/mcp.json, or use MCP: Open User Configuration for a private user-level configuration. Start bcentrisk and approve its tools.",
      "This file contains your secret. Keep it out of source control.",
    ],
  };
}
