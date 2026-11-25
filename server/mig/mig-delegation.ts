import { createHmac, randomUUID, timingSafeEqual } from "crypto";
import { sql } from "drizzle-orm";
import { db } from "../db";
import { verifyDelegation as verifyCanonicalDelegation } from "@shared/mig-delegation-authority";

const DELEGATION_ISSUER = "bcentrisk:mig";
const DELEGATION_AUDIENCE = "bcentrisk:mcp";
const DELEGATION_TTL_SECONDS = 30;
const usedDelegations = new Map<string, number>();

export interface MigDelegatedToolBinding {
  toolName: string;
  capabilityId: string;
  semanticAction: "read" | "execute" | "administer";
  domainId: string;
  resourceType: string;
  mutationClass: "none" | "append_only" | "governed_transition";
  canonicalService: string;
  authorizationManifestId: string;
  authorizationDecisionId: string;
  policyVersion: string;
}

export interface MigDelegationPayload {
  iss: typeof DELEGATION_ISSUER;
  aud: typeof DELEGATION_AUDIENCE;
  jti: string;
  tenantId: string;
  actorPrincipalId: string;
  clientPrincipalId: string;
  executorPrincipalId: string;
  intentId: string;
  requestId: string;
  mcpMethod: string;
  resourceRef: string;
  resourceVersion?: string;
  effectiveScopes: string[];
  tools: MigDelegatedToolBinding[];
  iat: number;
  exp: number;
}

function secret(): string {
  const value = process.env.MIG_DELEGATION_SECRET ?? process.env.SESSION_SECRET;
  if (!value || value.length < 32) throw new Error("MIG_DELEGATION_SIGNING_KEY_UNAVAILABLE");
  return value;
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signature(data: string): string {
  return createHmac("sha256", secret()).update(data).digest("base64url");
}

export function issueMigDelegation(input: Omit<MigDelegationPayload, "iss" | "aud" | "jti" | "iat" | "exp">): {
  token: string;
  payload: MigDelegationPayload;
} {
  const now = Math.floor(Date.now() / 1000);
  const payload: MigDelegationPayload = {
    ...input,
    iss: DELEGATION_ISSUER,
    aud: DELEGATION_AUDIENCE,
    jti: `mig_del_${randomUUID()}`,
    iat: now,
    exp: now + DELEGATION_TTL_SECONDS,
  };
  const header = encode({ alg: "HS256", typ: "MIGD" });
  const body = encode(payload);
  return { token: `${header}.${body}.${signature(`${header}.${body}`)}`, payload };
}

export interface MigDelegationExpectation {
  tenantId: string;
  requestId: string;
  mcpMethod: string;
  resourceRef: string;
  resourceVersion?: string;
  toolName?: string;
}

export function verifyMigDelegation(
  token: string | undefined,
  expected: MigDelegationExpectation,
  consume = false,
): { valid: true; payload: MigDelegationPayload } | { valid: false; reason: string } {
  const canonical = verifyCanonicalDelegation(token, expected);
  if (!canonical.valid) return canonical;
  // Preserve the hosted public contract while making the product-free shared
  // verifier the cryptographic authority.
  if (consume && usedDelegations.has(canonical.payload.jti)) return { valid: false, reason: "mig_delegation_replayed" };
  if (consume) usedDelegations.set(canonical.payload.jti, canonical.payload.exp);
  return canonical as { valid: true; payload: MigDelegationPayload };
  /*
  if (!token) return { valid: false, reason: "mig_delegation_missing" };
  const parts = token.split(".");
  if (parts.length !== 3) return { valid: false, reason: "mig_delegation_malformed" };
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (header?.alg !== "HS256" || header?.typ !== "MIGD") {
      return { valid: false, reason: "mig_delegation_header_invalid" };
    }
  } catch {
    return { valid: false, reason: "mig_delegation_header_invalid" };
  }
  const expectedSignature = signature(`${parts[0]}.${parts[1]}`);
  const actual = Buffer.from(parts[2]);
  const wanted = Buffer.from(expectedSignature);
  if (actual.length !== wanted.length || !timingSafeEqual(actual, wanted)) {
    return { valid: false, reason: "mig_delegation_signature_invalid" };
  }
  let payload: MigDelegationPayload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return { valid: false, reason: "mig_delegation_payload_invalid" };
  }
  const now = Math.floor(Date.now() / 1000);
  for (const [jti, expiry] of usedDelegations) if (expiry < now) usedDelegations.delete(jti);
  if (payload.iss !== DELEGATION_ISSUER) return { valid: false, reason: "mig_delegation_issuer_invalid" };
  if (payload.aud !== DELEGATION_AUDIENCE) return { valid: false, reason: "mig_delegation_audience_invalid" };
  if (!payload.jti || !Number.isFinite(payload.iat) || !Number.isFinite(payload.exp)) return { valid: false, reason: "mig_delegation_claims_incomplete" };
  const nonEmpty = (value: unknown): value is string => typeof value === "string" && value.length > 0;
  if (!nonEmpty(payload.tenantId) || !nonEmpty(payload.actorPrincipalId) || !nonEmpty(payload.clientPrincipalId) ||
      !nonEmpty(payload.executorPrincipalId) || !nonEmpty(payload.intentId) || !nonEmpty(payload.requestId) ||
      !nonEmpty(payload.mcpMethod) || !nonEmpty(payload.resourceRef) || !Array.isArray(payload.effectiveScopes) ||
      !payload.effectiveScopes.every(nonEmpty) ||
      !Array.isArray(payload.tools) || payload.tools.length === 0) {
    return { valid: false, reason: "mig_delegation_claims_incomplete" };
  }
  if (payload.tools.some(binding =>
    !nonEmpty(binding.toolName) || !nonEmpty(binding.capabilityId) ||
    !["read", "execute", "administer"].includes(binding.semanticAction) ||
    !nonEmpty(binding.domainId) || !nonEmpty(binding.resourceType) ||
    !["none", "append_only", "governed_transition"].includes(binding.mutationClass) ||
    !nonEmpty(binding.canonicalService) || !nonEmpty(binding.authorizationManifestId) ||
    !nonEmpty(binding.authorizationDecisionId) || !nonEmpty(binding.policyVersion) ||
    !payload.effectiveScopes.includes(binding.capabilityId)
  )) return { valid: false, reason: "mig_delegation_binding_incomplete" };
  if (payload.exp - payload.iat > DELEGATION_TTL_SECONDS || payload.exp <= payload.iat) {
    return { valid: false, reason: "mig_delegation_ttl_invalid" };
  }
  if (payload.exp <= now || payload.iat > now + 5) return { valid: false, reason: "mig_delegation_expired" };
  if (payload.tenantId !== expected.tenantId) return { valid: false, reason: "mig_delegation_tenant_mismatch" };
  if (payload.requestId !== expected.requestId) return { valid: false, reason: "mig_delegation_request_mismatch" };
  if (payload.mcpMethod !== expected.mcpMethod) return { valid: false, reason: "mig_delegation_method_mismatch" };
  if (payload.resourceRef !== expected.resourceRef || payload.resourceVersion !== expected.resourceVersion) {
    return { valid: false, reason: "mig_delegation_resource_mismatch" };
  }
  if (expected.toolName && !payload.tools.some(tool => tool.toolName === expected.toolName)) {
    return { valid: false, reason: "mig_delegation_tool_mismatch" };
  }
  if (usedDelegations.has(payload.jti)) return { valid: false, reason: "mig_delegation_replayed" };
  if (consume) usedDelegations.set(payload.jti, payload.exp);
  return { valid: true, payload };
  */
}

export async function consumeMigDelegation(
  token: string | undefined,
  expected: MigDelegationExpectation,
): Promise<{ valid: true; payload: MigDelegationPayload } | { valid: false; reason: string }> {
  const verified = verifyMigDelegation(token, expected, false);
  if (!verified.valid) return verified;
  try {
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS mig_delegation_consumptions (
        delegation_jti text PRIMARY KEY,
        tenant_id text NOT NULL,
        request_id text NOT NULL,
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz NOT NULL DEFAULT now()
      )
    `);
    await db.execute(sql`DELETE FROM mig_delegation_consumptions WHERE expires_at < now()`);
    const inserted = await db.execute(sql`
      INSERT INTO mig_delegation_consumptions (delegation_jti, tenant_id, request_id, expires_at)
      VALUES (${verified.payload.jti}, ${verified.payload.tenantId}, ${verified.payload.requestId},
              to_timestamp(${verified.payload.exp}))
      ON CONFLICT (delegation_jti) DO NOTHING
      RETURNING delegation_jti
    `);
    if (!Array.isArray(inserted.rows) || inserted.rows.length !== 1) {
      return { valid: false, reason: "mig_delegation_replayed" };
    }
    return verified;
  } catch {
    return { valid: false, reason: "mig_delegation_replay_store_unavailable" };
  }
}