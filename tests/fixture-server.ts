/** Isolated browser fixture. Never a production entry point or a real provider. */
import express from "express";
import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

if (process.env.NODE_ENV !== "test") throw Error("FIXTURE_REQUIRES_TEST_MODE");
const databaseUrl = process.env.MIG_FIXTURE_DATABASE_URL;
if (!databaseUrl) throw Error("FIXTURE_DATABASE_REQUIRED");
const database = new URL(databaseUrl);
if (database.hostname !== "127.0.0.1" || !database.pathname.startsWith("/mig_fixture_")) {
  throw Error("FIXTURE_REQUIRES_ISOLATED_LOOPBACK_DATABASE");
}
const origin = process.env.MIG_FIXTURE_PUBLIC_ORIGIN;
if (!origin || new URL(origin).protocol !== "https:") throw Error("FIXTURE_HTTPS_ORIGIN_REQUIRED");
Object.assign(process.env, {
  MIG_DATABASE_URL: databaseUrl, MIG_TENANT_ID: "fixture-tenant",
  MIG_PUBLIC_ORIGIN: origin, MIG_OIDC_ISSUER: origin + "/__fixture/issuer",
  MIG_OIDC_CLIENT_ID: "fixture-client", MIG_OIDC_TENANT_REF: "fixture-provider-tenant",
  MIG_OIDC_TENANT_CLAIM: "tenant_id", MIG_OIDC_ADMIN_ROLE: "MIG.Admin",
  MIG_OWNER_BRIDGE_URL: origin + "/api/mig/owner-bridge/v1",
  MIG_OWNER_BRIDGE_SECRET: "public-fixture-bridge-key-never-production",
  MIG_DELEGATION_SECRET: "public-fixture-delegation-key-never-production",
  MIG_ATTESTATION_SECRET: "public-fixture-attestation-key-never-production",
});
delete process.env.MIG_OIDC_CLIENT_SECRET;
const { registerMigOwnerBridge } = await import("../server/mig/mig-owner-bridge");
const { createMigApplication } = await import("../server/index");
const { publicKey, privateKey } = await generateKeyPair("RS256");
const publicJwk = { ...await exportJWK(publicKey), kid: "fixture-only", alg: "RS256", use: "sig" };
const codes = new Map<string, { nonce: string; challenge: string; redirect: string }>();
const wrapper = express();
wrapper.get(["/__fixture/issuer/.well-known/openid-configuration",
  "/.well-known/openid-configuration/__fixture/issuer"], (_req, res) => res.json({
  issuer: process.env.MIG_OIDC_ISSUER, authorization_endpoint: origin + "/__fixture/authorize",
  token_endpoint: origin + "/__fixture/token", jwks_uri: origin + "/__fixture/jwks",
  response_types_supported: ["code"], grant_types_supported: ["authorization_code"],
  id_token_signing_alg_values_supported: ["RS256"], token_endpoint_auth_methods_supported: ["none"],
  code_challenge_methods_supported: ["S256"], authorization_response_iss_parameter_supported: true,
  subject_types_supported: ["public"],
}));
wrapper.get("/__fixture/jwks", (_req, res) => res.json({ keys: [publicJwk] }));
wrapper.get("/__fixture/authorize", (req, res) => {
  const q = req.query;
  if (q.client_id !== "fixture-client" || q.redirect_uri !== origin + "/api/auth/callback" ||
      q.code_challenge_method !== "S256" || typeof q.nonce !== "string" ||
      typeof q.state !== "string" || typeof q.code_challenge !== "string") {
    res.status(400).end(); return;
  }
  const code = randomUUID();
  codes.set(code, { nonce: q.nonce, challenge: q.code_challenge, redirect: q.redirect_uri });
  const target = new URL(q.redirect_uri);
  target.searchParams.set("code", code); target.searchParams.set("state", q.state);
  target.searchParams.set("iss", process.env.MIG_OIDC_ISSUER!);
  res.redirect(target.href);
});
wrapper.post("/__fixture/token", express.urlencoded({ extended: false, limit: "8kb" }), async (req, res) => {
  const issued = codes.get(req.body.code); codes.delete(req.body.code);
  if (!issued || req.body.redirect_uri !== issued.redirect ||
      createHash("sha256").update(req.body.code_verifier ?? "").digest("base64url") !== issued.challenge) {
    res.status(400).json({ error: "invalid_grant" }); return;
  }
  const idToken = await new SignJWT({ nonce: issued.nonce,
    tenant_id: "fixture-provider-tenant", roles: ["MIG.Admin"] })
    .setProtectedHeader({ alg: "RS256", kid: "fixture-only" })
    .setIssuer(process.env.MIG_OIDC_ISSUER!).setAudience("fixture-client")
    .setSubject("fixture-administrator").setIssuedAt().setExpirationTime("5m").sign(privateKey);
  res.json({ access_token: "fixture-access-with-no-business-authority", token_type: "Bearer",
    expires_in: 300, id_token: idToken });
});
const seen = new Set<string>();
wrapper.use("/api/mig/owner-bridge/v1", express.json({ limit: "1mb" }));
registerMigOwnerBridge(wrapper, {
  secret: process.env.MIG_OWNER_BRIDGE_SECRET!, allowedTenantIds: new Set(["fixture-tenant"]),
  claimNonce: async (tenant, nonce) => {
    const key = tenant + ":" + nonce; if (seen.has(key)) return false; seen.add(key); return true;
  },
  dispatch: async request => {
    if (request.operation === "enterprise.listOrganizations") {
      return [{ id: "fixture-tenant", name: "Isolated fixture organization", isActive: true }];
    }
    // Explicit empty fixture, not a fallback or a native engine result.
    if (request.operation !== "catalog.read") throw Error("FIXTURE_HAS_NO_CANONICAL_EXECUTION_AUTHORITY");
    return { tools: [], raw_tools: [], domains: [], capability_contract_ids: [],
      capability_contracts: [], workloads: [], intents: [], restricted_callers: [], groups: [] };
  },
});
const application = await createMigApplication();
wrapper.use(application.app);
const server = createServer(wrapper);
await new Promise<void>(resolve => server.listen(5000, "0.0.0.0", resolve));
console.log("Isolated MIG fixture listening on port 5000; no native execution authority.");
setTimeout(() => void application.refresh(), 1500).unref();
async function close() {
  server.closeAllConnections(); server.close(); await application.close();
}
process.once("SIGTERM", () => void close());
process.once("SIGINT", () => void close());
