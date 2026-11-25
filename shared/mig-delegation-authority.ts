import { createHmac, timingSafeEqual } from "node:crypto";

export const MIG_DELEGATION_ISSUER = "bcentrisk:mig";
export const MIG_DELEGATION_AUDIENCE = "bcentrisk:mcp";
export const MIG_DELEGATION_TTL_SECONDS = 30;
export interface DelegationToolBinding {
  toolName: string; capabilityId: string;
  semanticAction: "read" | "execute" | "administer";
  domainId: string; resourceType: string;
  mutationClass: "none" | "append_only" | "governed_transition";
  canonicalService: string; authorizationManifestId: string;
  authorizationDecisionId: string; policyVersion: string;
}
export interface DelegationPayload {
  iss: typeof MIG_DELEGATION_ISSUER; aud: typeof MIG_DELEGATION_AUDIENCE;
  jti: string; tenantId: string; actorPrincipalId: string; clientPrincipalId: string;
  executorPrincipalId: string; intentId: string; requestId: string; mcpMethod: string;
  resourceRef: string; resourceVersion?: string; effectiveScopes: string[];
  tools: DelegationToolBinding[]; iat: number; exp: number;
}
export interface DelegationExpectation {
  tenantId: string; requestId: string; mcpMethod: string; resourceRef: string;
  resourceVersion?: string; toolName?: string;
}
function key(): string {
  const value = process.env.MIG_DELEGATION_SECRET ?? process.env.SESSION_SECRET;
  if (!value || value.length < 32) throw new Error("MIG_DELEGATION_SIGNING_KEY_UNAVAILABLE");
  return value;
}
export function verifyDelegation(token: string | undefined, expected: DelegationExpectation):
  { valid: true; payload: DelegationPayload } | { valid: false; reason: string } {
  if (!token) return { valid: false, reason: "mig_delegation_missing" };
  const p = token.split(".");
  if (p.length !== 3) return { valid: false, reason: "mig_delegation_malformed" };
  try {
    const h = JSON.parse(Buffer.from(p[0], "base64url").toString());
    if (h.alg !== "HS256" || h.typ !== "MIGD") return { valid: false, reason: "mig_delegation_header_invalid" };
  } catch { return { valid: false, reason: "mig_delegation_header_invalid" }; }
  const wanted = createHmac("sha256", key()).update(`${p[0]}.${p[1]}`).digest("base64url");
  if (p[2].length !== wanted.length || !timingSafeEqual(Buffer.from(p[2]), Buffer.from(wanted))) {
    return { valid: false, reason: "mig_delegation_signature_invalid" };
  }
  let value: DelegationPayload;
  try { value = JSON.parse(Buffer.from(p[1], "base64url").toString()); }
  catch { return { valid: false, reason: "mig_delegation_payload_invalid" }; }
  const now = Math.floor(Date.now() / 1000);
  if (value.iss !== MIG_DELEGATION_ISSUER || value.aud !== MIG_DELEGATION_AUDIENCE) return { valid: false, reason: "mig_delegation_issuer_invalid" };
  if (!Number.isFinite(value.iat) || !Number.isFinite(value.exp) || value.exp <= now ||
      value.exp <= value.iat || value.exp - value.iat > MIG_DELEGATION_TTL_SECONDS ||
      value.iat > now + 5) return { valid: false, reason: "mig_delegation_ttl_invalid" };
  if (value.tenantId !== expected.tenantId || value.requestId !== expected.requestId ||
      value.mcpMethod !== expected.mcpMethod || value.resourceRef !== expected.resourceRef ||
      value.resourceVersion !== expected.resourceVersion) return { valid: false, reason: "mig_delegation_binding_mismatch" };
  if (expected.toolName && !value.tools?.some((t) => t.toolName === expected.toolName)) return { valid: false, reason: "mig_delegation_tool_mismatch" };
  if (!Array.isArray(value.effectiveScopes) || !Array.isArray(value.tools) || !value.tools.length) return { valid: false, reason: "mig_delegation_claims_incomplete" };
  return { valid: true, payload: value };
}