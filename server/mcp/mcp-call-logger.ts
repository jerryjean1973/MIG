/**
 * server/mcp/mcp-call-logger.ts
 *
 * Persistent ring-buffer logger for every MCP tool invocation.
 * Writes NDJSON to .local/mcp-call-log.ndjson — last RING_SIZE entries kept.
 * Admin endpoint GET /api/mcp/admin/last-calls reads this file instantly.
 *
 * Usage inside a tool handler:
 *   import { logMcpCall } from "./mcp-call-logger";
 *   logMcpCall({ tool, tenant, classification, input, result, duration_ms });
 */
import { existsSync, readFileSync } from "fs";

import { join } from "path";

const LOG_DIR  = join(process.cwd(), ".local");

const LOG_FILE = join(LOG_DIR, "mcp-call-log.ndjson");

export interface McpCallLogEntry {
  ts:             string;       // ISO timestamp
  tool:           string;
  tenant:         string;
  classification: string;
  duration_ms:    number;
  adapted_from?:  string;       // "appguard_format" or undefined
  routing_mode?:  "canonical_envelope" | "decision_context" | "combined"; // which run_bripe_decision path was taken
  input_summary:  unknown;      // trimmed input (not raw — size-capped)
  result:         unknown;      // full response
}

export function readMcpCallLog(limit = 20): McpCallLogEntry[] {
  try {
    if (!existsSync(LOG_FILE)) return [];
    const lines = readFileSync(LOG_FILE, "utf8").split("\n").filter(Boolean);
    return lines
      .slice(-limit)
      .reverse()
      .map(l => JSON.parse(l) as McpCallLogEntry);
  } catch {
    return [];
  }
}
