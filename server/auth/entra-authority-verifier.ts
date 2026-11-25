/**
 * Transport-neutral Entra authority verification.
 *
 * MCP ingress and MIG authority resolution both consume this verifier. It
 * authenticates authority only; it has no Express or MCP dispatch behavior.
 */
import { createRemoteJWKSet, jwtVerify } from "jose";

import { discovery, type Configuration } from "openid-client";

const AZURE_TENANT_ID = process.env.AZURE_TENANT_ID ?? "";

const AZURE_CLIENT_ID = process.env.AZURE_CLIENT_ID ?? "";

const BCENTRISK_TENANT_MAPPING_RAW = process.env.BCENTRISK_TENANT_MAPPING ?? "";

const APPROVED_SCOPES = [
  "bcentrisk.read_evidence",
  "bcentrisk.investigate",
  "bcentrisk.simulate",
] as const;

export type EntraAuthorityClassification = "read_only" | "execution";

export interface EntraAuthResult {
  ok: true;
  tenantId: string;
  entraObjectId: string;
  entraTenantId: string;
  classification: EntraAuthorityClassification;
  scopes: string[];
  roles: string[];
  groups: string[];
  issuedAt: Date;
  expiresAt: Date;
}

export interface EntraAuthFailure {
  ok: false;
  status: number;
  error: string;
}

let dbMappingCache: Record<string, string> | null = null;

let dbMappingCachedAt = 0;

const DB_MAPPING_CACHE_TTL_MS = 60 * 1000;

let envMapping: Record<string, string> | null = null;

function getEnvMapping(): Record<string, string> {
  if (envMapping) return envMapping;
  if (!BCENTRISK_TENANT_MAPPING_RAW) {
    envMapping = {};
    return envMapping;
  }
  try {
    envMapping = JSON.parse(BCENTRISK_TENANT_MAPPING_RAW);
    return envMapping!;
  } catch {
    console.error("[EntraAuthorityVerifier] BCENTRISK_TENANT_MAPPING is not valid JSON — treating as empty");
    envMapping = {};
    return envMapping;
  }
}

export function invalidateEntraTenantMappingCache(): void {
  dbMappingCache = null;
  dbMappingCachedAt = 0;
}

async function resolveBcentriskTenant(entraTid: string): Promise<string | undefined> {
  try {
    const now = Date.now();
    if (!dbMappingCache || now - dbMappingCachedAt > DB_MAPPING_CACHE_TTL_MS) {
      const { storage } = await import("../storage");
      dbMappingCache = await storage.getEntraTenantMappingMap();
      dbMappingCachedAt = now;
    }
    if (dbMappingCache[entraTid]) return dbMappingCache[entraTid];
  } catch (error) {
    console.warn("[EntraAuthorityVerifier] DB mapping fetch failed — falling back to env var:", error);
  }
  return getEnvMapping()[entraTid];
}

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

let oidcConfiguration: Configuration | null = null;

let jwksCachedAt = 0;

const JWKS_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

async function getJwks(): Promise<ReturnType<typeof createRemoteJWKSet>> {
  const now = Date.now();
  if (jwks && now - jwksCachedAt < JWKS_CACHE_TTL_MS) return jwks;
  if (!AZURE_TENANT_ID) throw new Error("AZURE_TENANT_ID environment variable is not set");
  const issuer = new URL(`https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0`);
  oidcConfiguration = await discovery(issuer, AZURE_CLIENT_ID);
  const metadata = oidcConfiguration.serverMetadata();
  if (metadata.issuer !== issuer.href.replace(/\/$/, "") || !metadata.jwks_uri) {
    throw new Error("Entra OIDC discovery returned invalid issuer or JWKS metadata");
  }
  jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
  jwksCachedAt = now;
  return jwks;
}

async function refreshJwks(): Promise<ReturnType<typeof createRemoteJWKSet>> {
  jwks = null;
  jwksCachedAt = 0;
  oidcConfiguration = null;
  return getJwks();
}

function scopesToClassification(scopes: string[]): EntraAuthorityClassification {
  return scopes.includes("bcentrisk.investigate") || scopes.includes("bcentrisk.simulate")
    ? "execution"
    : "read_only";
}

export async function resolveEntraToken(rawJwt: string): Promise<EntraAuthResult | EntraAuthFailure> {
  if (!AZURE_TENANT_ID || !AZURE_CLIENT_ID) {
    return {
      ok: false,
      status: 401,
      error: "Entra ID JWT validation is not configured on this server. Set AZURE_TENANT_ID and AZURE_CLIENT_ID.",
    };
  }

  const expectedAudience = `api://${AZURE_CLIENT_ID}`;
  const expectedIssuer = `https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0`;
  let payload: any;
  let verifyError: unknown;

  try {
    const activeJwks = await getJwks();
    const result = await jwtVerify(rawJwt, activeJwks, {
      audience: expectedAudience,
      issuer: expectedIssuer,
    });
    payload = result.payload;
  } catch (error) {
    verifyError = error;
  }

  if (verifyError) {
    const message = String(verifyError);
    const isSignatureError =
      message.includes("signature") ||
      message.includes("JWSSignatureVerificationFailed") ||
      message.includes("no applicable keys");
    if (isSignatureError) {
      try {
        const refreshedJwks = await refreshJwks();
        const result = await jwtVerify(rawJwt, refreshedJwks, {
          audience: expectedAudience,
          issuer: expectedIssuer,
        });
        payload = result.payload;
        verifyError = undefined;
      } catch (refreshError) {
        verifyError = refreshError;
      }
    }
  }

  if (verifyError || !payload) {
    console.warn("[EntraAuthorityVerifier] JWT verification failed:", String(verifyError ?? "JWT verification failed"));
    return { ok: false, status: 401, error: "Invalid Entra ID JWT — authentication failed" };
  }

  const entraTenantId = typeof payload.tid === "string" ? payload.tid : undefined;
  if (!entraTenantId) return { ok: false, status: 401, error: "JWT missing tid claim" };
  const tenantId = await resolveBcentriskTenant(entraTenantId);
  if (!tenantId) {
    console.warn(`[EntraAuthorityVerifier] Unknown Entra tid '${entraTenantId}' — not in DB or BCENTRISK_TENANT_MAPPING`);
    return { ok: false, status: 403, error: "Entra tenant is not authorized to access this bCentRisk instance" };
  }

  const rawScopes = payload.scp ?? payload.roles ?? "";
  const scopes = typeof rawScopes === "string"
    ? rawScopes.split(" ").map((scope: string) => scope.trim()).filter(Boolean)
    : Array.isArray(rawScopes) ? rawScopes.filter((scope): scope is string => typeof scope === "string") : [];
  const approvedScopes = scopes.filter(scope =>
    (APPROVED_SCOPES as readonly string[]).includes(scope));
  if (approvedScopes.length === 0) {
    return {
      ok: false,
      status: 403,
      error: `JWT scopes do not include any approved bCentRisk scope. Required: ${APPROVED_SCOPES.join(", ")}`,
    };
  }

  const entraObjectId = typeof payload.oid === "string"
    ? payload.oid
    : typeof payload.sub === "string" ? payload.sub : undefined;
  if (!entraObjectId) return { ok: false, status: 401, error: "JWT missing stable oid/sub claim" };
  if (typeof payload.iat !== "number" || typeof payload.exp !== "number") {
    return { ok: false, status: 401, error: "JWT missing bounded iat/exp claims" };
  }

  return {
    ok: true,
    tenantId,
    entraObjectId,
    entraTenantId,
    classification: scopesToClassification(approvedScopes),
    scopes: approvedScopes,
    roles: Array.isArray(payload.roles)
      ? payload.roles.filter((role: unknown): role is string => typeof role === "string")
      : [],
    groups: Array.isArray(payload.groups)
      ? payload.groups.filter((group: unknown): group is string => typeof group === "string")
      : [],
    issuedAt: new Date(payload.iat * 1000),
    expiresAt: new Date(payload.exp * 1000),
  };
}
