/**
 * server/mcp/mcp-connection-log.ts
 *
 * Persistent ring-buffer logger for every POST /api/mcp connection attempt —
 * both auth successes and failures.  Writes NDJSON to
 * .local/mcp-connection-log.ndjson — last RING_SIZE entries kept.
 * Admin endpoint GET /api/mcp/admin/connection-log reads this file instantly.
 *
 * Mirrors the pattern in mcp-call-logger.ts.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, statSync, renameSync, openSync, closeSync, readSync, readdirSync } from "fs";

import { join } from "path";

const LOG_DIR  = join(process.cwd(), ".local");

const LOG_FILE = join(LOG_DIR, "mcp-connection-log.ndjson");

const RING_SIZE = 200;

export interface McpConnectionLogEntry {
  ts:           string;
  ip:           string;
  key_prefix_hint: string;
  auth_ok:      boolean;
  auth_error:   string | null;
  http_status:  number;
  api_key_id?: number | null;
  tenant_id?: string | null;
  classification?: string | null;
  jsonrpc_method?: string | null;
  request_id?: string | number | null;
  protocol_version?: string | null;
  client_name?: string | null;
  client_version?: string | null;
  user_agent?: string | null;
  tool_name?: string | null;
  requested_intent?: string | null;
  params?: unknown;
  request_body?: unknown;
  response_body?: unknown;
  duration_ms?: number | null;
  transaction_complete?: boolean;
  auth_mechanism?: "bearer" | "mig_proxy" | "legacy_api_key" | "none";
  auth_stage?: "discovery" | "token_verification" | "canonical_mapping" | "credential_binding" | "lineage" | "admitted";
}

export function logConnectionAttempt(entry: McpConnectionLogEntry): void {
  try {
    if (!existsSync(LOG_DIR)) mkdirSync(LOG_DIR, { recursive: true });

    // Retain the original oversized history intact; never load it into a string.
    if (existsSync(LOG_FILE) && statSync(LOG_FILE).size > 4 * 1024 * 1024) {
      renameSync(LOG_FILE, `${LOG_FILE}.archive-${Date.now()}`);
    }
    // This is a connection diagnostic, not the canonical source/evidence store.
    // Large source submissions and tool responses remain at their actual owners.
    const { params, request_body, response_body, ...metadata } = entry;
    const line = JSON.stringify({
      ...metadata,
      ...(params !== undefined || request_body !== undefined || response_body !== undefined
        ? { diagnostic_payload: "omitted; consult canonical invocation/evidence records" } : {}),
    }, (_key, value) => typeof value === "string" && value.length > 4096 ? value.slice(0, 4096) + "[bounded]" : value);
    appendFileSync(LOG_FILE, line + "\n", "utf8");

    const content = readFileSync(LOG_FILE, "utf8");
    const lines   = content.split("\n").filter(Boolean);
    if (lines.length > RING_SIZE) {
      writeFileSync(LOG_FILE, lines.slice(-RING_SIZE).join("\n") + "\n", "utf8");
    }
  } catch {
    // Non-fatal — logging must never crash the auth middleware
  }
}

export function readConnectionLog(limit = 50): McpConnectionLogEntry[] {
  try {
    const count = Math.min(500, Math.max(1, Math.trunc(limit) || 50));
    if (!existsSync(LOG_DIR)) return [];
    const archives = readdirSync(LOG_DIR).filter(name => name.startsWith("mcp-connection-log.ndjson.archive-")).sort().slice(-2);
    const paths = [...archives.map(name => join(LOG_DIR, name)), LOG_FILE];
    const entries: McpConnectionLogEntry[] = [];
    for (const path of paths) {
      if (!existsSync(path)) continue;
      const size = statSync(path).size;
      const length = Math.min(size, 16 * 1024 * 1024);
      const buffer = Buffer.alloc(length);
      const fd = openSync(path, "r");
      let received = 0;
      try {
        while (received < length) {
          const read = readSync(fd, buffer, received, length - received, size - length + received);
          if (!read) break;
          received += read;
        }
      } finally { closeSync(fd); }
      let start = size > length ? buffer.indexOf(10) + 1 : 0;
      if (size > length && start === 0) continue; // tail is entirely inside one giant historical row
      while (start < received) {
        const end = buffer.indexOf(10, start);
        const stop = end < 0 ? received : end;
        // Metadata precedes payload fields in historical entries. Decode only
        // a bounded prefix, preserving history without parsing giant bodies.
        const prefix = buffer.subarray(start, Math.min(stop, start + 64 * 1024)).toString("utf8");
        const cuts = [',"params":', ',"request_body":', ',"response_body":']
          .map(marker => prefix.indexOf(marker)).filter(index => index >= 0);
        try {
          entries.push(JSON.parse(cuts.length ? prefix.slice(0, Math.min(...cuts)) + "}" : prefix));
        } catch { /* A partial old payload is not connection metadata. */ }
        if (end < 0) break;
        start = end + 1;
      }
    }
    return entries.sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, count);
  } catch {
    return [];
  }
}
