/**
 * Product-free MCP authority primitives.  This module deliberately contains
 * no route, product, or application-storage imports and is shared by native
 * and hosted MCP adapters.
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export interface McpAuthorityCredential {
  tenantId: string; principalId: string; clientId: string;
  scopes: string[]; jti: string; expiresAt: number;
}
export interface McpDelegationBinding {
  tenantId: string; requestId: string; toolName?: string;
  resourceRef: string; scopes: string[]; expiresAt: number; jti: string;
}

export function verifySignedCredential(raw: string, secret: string, now = Date.now()): McpAuthorityCredential {
  const [encoded, signature] = raw.split(".");
  if (!encoded || !signature) throw new Error("MCP_CREDENTIAL_FORMAT_INVALID");
  const expected = createHmac("sha256", secret).update(encoded).digest("base64url");
  if (signature.length !== expected.length ||
      !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    throw new Error("MCP_CREDENTIAL_SIGNATURE_INVALID");
  }
  let value: any;
  try { value = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")); }
  catch { throw new Error("MCP_CREDENTIAL_PAYLOAD_INVALID"); }
  if (!value.tenantId || !value.principalId || !value.clientId || !value.jti ||
      !Array.isArray(value.scopes) || typeof value.exp !== "number" || value.exp * 1000 <= now) {
    throw new Error("MCP_CREDENTIAL_EXPIRED_OR_INCOMPLETE");
  }
  return { tenantId: value.tenantId, principalId: value.principalId, clientId: value.clientId,
    scopes: value.scopes.filter((s: unknown): s is string => typeof s === "string"),
    jti: value.jti, expiresAt: value.exp * 1000 };
}

export function authorizeTool(credential: McpAuthorityCredential, toolName: string,
  requiredScope: string, resourceRef?: string): void {
  if (!credential.scopes.includes(requiredScope) && !credential.scopes.includes("*")) {
    throw new Error("MCP_CAPABILITY_CEILING_EXCEEDED");
  }
  if (resourceRef && !credential.scopes.includes("*") &&
      !credential.scopes.includes(`resource:${resourceRef}`)) {
    throw new Error("MCP_RESOURCE_SCOPE_DENIED");
  }
  if (!toolName.trim()) throw new Error("MCP_TOOL_BINDING_INVALID");
}

export function delegationDigest(binding: McpDelegationBinding): string {
  return createHash("sha256").update(JSON.stringify(binding)).digest("hex");
}