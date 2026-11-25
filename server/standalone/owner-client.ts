/**
 * Authenticated, deadline-bound transport to the canonical owner's host.
 * No local authority, score, topology, admission or snapshot fallback.
 */
import { randomUUID } from "node:crypto";
import { MCP_JSON_BODY_LIMIT_BYTES } from "../mcp/mcp-body-parser";
import {
  MIG_OWNER_BRIDGE_SCHEMA, assertMigOwnerOperationScope, decodeMigOwnerValue,
  encodeMigOwnerValue, migOwnerHash, signMigOwnerMessage, verifyMigOwnerMessage,
  type MigOwnerOperation,
   } from "../../shared/contracts/mig-owner-bridge-v1";

export function ownerConfigured(): boolean {
  return !!process.env.MIG_OWNER_BRIDGE_URL &&
    (process.env.MIG_OWNER_BRIDGE_SECRET?.length ?? 0) >= 32 &&
    !!process.env.MIG_TENANT_ID;
}

export async function ownerCall<T = any>(
  operation: MigOwnerOperation, args: unknown[], tenantId = process.env.MIG_TENANT_ID,
): Promise<T> {
  const configuredTenant = process.env.MIG_TENANT_ID;
  if (!tenantId || !configuredTenant || tenantId !== configuredTenant) {
    throw new Error("MIG_OWNER_TENANT_MISMATCH");
  }
  const rawUrl = process.env.MIG_OWNER_BRIDGE_URL;
  const secret = process.env.MIG_OWNER_BRIDGE_SECRET;
  if (!rawUrl || !secret || secret.length < 32) throw new Error("MIG_OWNER_BRIDGE_UNAVAILABLE");
  const url = new URL(rawUrl);
  if (url.username || url.password || url.search || url.hash ||
      url.pathname !== "/api/mig/owner-bridge/v1" ||
      (url.protocol !== "https:" && !(process.env.NODE_ENV === "test" &&
        url.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(url.hostname)))) {
    throw new Error("MIG_OWNER_ENDPOINT_INVALID");
  }
  assertMigOwnerOperationScope(operation, args, tenantId);
  const request = {
    schema_version: MIG_OWNER_BRIDGE_SCHEMA, operation, tenant_id: tenantId,
    nonce: randomUUID(), expires_at: Date.now() + 120_000,
    args: encodeMigOwnerValue(args) as unknown[],
  };
  const response = await fetch(url, {
    method: "POST", redirect: "error", signal: AbortSignal.timeout(120_000),
    headers: {
      "Content-Type": "application/json",
      "x-mig-owner-signature": signMigOwnerMessage(request, secret),
    },
    body: JSON.stringify(request),
  });
  if (!response.ok) throw new Error(`MIG_OWNER_HTTP_${response.status}`);
  const limit = MCP_JSON_BODY_LIMIT_BYTES + 1_000_000;
  if (!response.body) throw new Error("MIG_OWNER_EMPTY_RESPONSE");
  const reader = response.body.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new Error("MIG_OWNER_RESPONSE_TOO_LARGE");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const text = Buffer.concat(chunks).toString("utf8");
  const body = JSON.parse(text);
  if (!verifyMigOwnerMessage(body, response.headers.get("x-mig-owner-signature"), secret) ||
      body.schema_version !== MIG_OWNER_BRIDGE_SCHEMA ||
      body.request_hash !== migOwnerHash(request) || body.tenant_id !== tenantId) {
    throw new Error("MIG_OWNER_RESPONSE_BINDING_INVALID");
  }
  return decodeMigOwnerValue(body.value) as T;
}
