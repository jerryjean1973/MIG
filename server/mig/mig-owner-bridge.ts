/**
 * Optional host-side adapter. Disabled unless a host explicitly registers it
 * with a secret, allowed tenants and durable replay protection. Not a new
 * canonical owner and never registered by the standalone MIG application.
 */
import type { Express } from "express";
import { json } from "express";
import { MCP_JSON_BODY_LIMIT_BYTES } from "../mcp/mcp-body-parser";
import {
  assertMigOwnerRequest, decodeMigOwnerValue, encodeMigOwnerValue,
  migOwnerHash, signMigOwnerMessage, verifyMigOwnerMessage,
  type MigOwnerBridgeRequest,
} from "@shared/contracts/mig-owner-bridge-v1";

export interface MigOwnerBridgeHost {
  secret: string;
  allowedTenantIds: ReadonlySet<string>;
  claimNonce(tenantId: string, nonce: string, expiresAt: number): Promise<boolean>;
  dispatch(request: MigOwnerBridgeRequest): Promise<unknown>;
}

export function createPostgresMigOwnerNonceClaimer(database: {
  query(text: string, values: unknown[]): Promise<{ rowCount: number | null }>;
}): MigOwnerBridgeHost["claimNonce"] {
  return async (tenantId, nonce, expiresAt) => {
    const result = await database.query(
      `INSERT INTO mig_owner_bridge_nonces (tenant_id, nonce, expires_at)
       VALUES ($1, $2, $3) ON CONFLICT (tenant_id, nonce) DO NOTHING`,
      [tenantId, nonce, new Date(expiresAt)],
    );
    return result.rowCount === 1;
  };
}

export function registerMigOwnerBridge(app: Express, host: MigOwnerBridgeHost): void {
  if (host.secret.length < 32 || !host.allowedTenantIds.size) {
    throw new Error("MIG_OWNER_HOST_NOT_CONFIGURED");
  }
  app.post("/api/mig/owner-bridge/v1", json({ limit: MCP_JSON_BODY_LIMIT_BYTES + 1_000_000 }), async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try {
      assertMigOwnerRequest(req.body);
      if (!host.allowedTenantIds.has(req.body.tenant_id) ||
          !verifyMigOwnerMessage(req.body, req.header("x-mig-owner-signature"), host.secret)) {
        return void res.status(401).json({ error: "MIG_OWNER_AUTHENTICATION_REQUIRED" });
      }
      decodeMigOwnerValue(req.body.args); // Reject unsafe wire objects before admission.
      if (!await host.claimNonce(req.body.tenant_id, req.body.nonce, req.body.expires_at)) {
        return void res.status(409).json({ error: "MIG_OWNER_REPLAY_REJECTED" });
      }
      const value = await host.dispatch({
        ...req.body, args: decodeMigOwnerValue(req.body.args),
      });
      const response = {
        schema_version: req.body.schema_version,
        request_hash: migOwnerHash(req.body),
        tenant_id: req.body.tenant_id,
        value: encodeMigOwnerValue(value),
      };
      res.setHeader("x-mig-owner-signature", signMigOwnerMessage(response, host.secret));
      res.json(response);
    } catch (error) {
      const code = error instanceof Error ? error.message : "MIG_OWNER_FAILURE";
      const invalid = /^MIG_OWNER_(REQUEST_INVALID|TENANT_MISMATCH|UNSAFE_OBJECT|INVALID_DATE)$/.test(code);
      res.status(invalid ? 400 : 503).json({
        error: invalid ? code : "MIG_OWNER_OPERATION_UNAVAILABLE",
      });
    }
  });
}
