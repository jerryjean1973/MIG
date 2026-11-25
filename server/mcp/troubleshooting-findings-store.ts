/**
 * server/mcp/troubleshooting-findings-store.ts
 *
 * Ring-buffer store for troubleshooting findings submitted by any MCP client.
 * Writes NDJSON to .local/mcp-ts-findings.ndjson — last RING_SIZE entries kept.
 * Admin endpoint GET /api/mcp/admin/ts-findings reads this file instantly.
 */
import { existsSync, readFileSync } from "fs";

import { join } from "path";

const LOG_DIR   = join(process.cwd(), ".local");

const LOG_FILE  = join(LOG_DIR, "mcp-ts-findings.ndjson");

const RING_SIZE = 100;

export interface TroubleshootingFinding {
  finding_id:         string;
  severity:           "critical" | "high" | "medium" | "low" | "info";
  category:           string;
  description:        string;
  expected_behavior?: string;
  observed_behavior?: string;
  evidence?:          unknown;
  timestamp:          string;
}

export interface TsFindingsEntry {
  ts:          string;
  session_id:  string;
  tenant:      string;
  client_id?:  string;
  mode:        "troubleshooting";
  findings:    TroubleshootingFinding[];
  client_context?: Record<string, unknown>;
  finding_count: number;
}

export function readTsFindings(limit = 20): TsFindingsEntry[] {
  try {
    if (!existsSync(LOG_FILE)) return [];
    const lines = readFileSync(LOG_FILE, "utf8").split("\n").filter(Boolean);
    return lines
      .slice(-Math.min(limit, RING_SIZE))
      .reverse()
      .map(l => JSON.parse(l) as TsFindingsEntry);
  } catch {
    return [];
  }
}
