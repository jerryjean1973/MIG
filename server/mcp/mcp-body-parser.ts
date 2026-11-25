import express, { type Express } from "express";

export const MCP_JSON_BODY_LIMIT_BYTES = 500_000_000;

export const MCP_JSON_BODY_LIMIT = MCP_JSON_BODY_LIMIT_BYTES;

export function registerMcpBodyParser(app: Express): void {
  
  // Must precede the global 2 MiB parser. Covers JSON-RPC and action forwarding.
  app.use("/api/mcp", express.json({
    limit: MCP_JSON_BODY_LIMIT,
    verify: (req, _res, buffer) => {
      (req as typeof req & { rawBody: Buffer }).rawBody = buffer;
    },
  }));
}
