import { getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";

export function getMcpResourceUrl(): URL {
  const configured = process.env.MCP_RESOURCE_URL;
  if (configured) {
    const resourceUrl = new URL(configured);
    if (resourceUrl.username || resourceUrl.password) {
      throw new Error("MCP_RESOURCE_URL must not contain credentials");
    }
    if (resourceUrl.pathname !== "/api/mcp") {
      throw new Error("MCP_RESOURCE_URL must use the canonical /api/mcp path");
    }
    if (resourceUrl.search || resourceUrl.hash) {
      throw new Error("MCP_RESOURCE_URL must not contain query parameters or a fragment");
    }
    if (process.env.NODE_ENV === "production" && resourceUrl.protocol !== "https:") {
      throw new Error("MCP_RESOURCE_URL must use HTTPS in production");
    }
    return resourceUrl;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("MCP_RESOURCE_URL must be configured with the public deployed /api/mcp URL in production");
  }
  const domain = process.env.REPLIT_DEV_DOMAIN;
  return new URL(domain ? `https://${domain}/api/mcp` : "http://127.0.0.1:5000/api/mcp");
}

export function buildMcpBearerChallenge(resourceUrl = getMcpResourceUrl()): string {
  return `Bearer resource_metadata="${getOAuthProtectedResourceMetadataUrl(resourceUrl)}"`;
}
