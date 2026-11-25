import type { Express, Request, Response } from "express";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import * as oidc from "openid-client";
import { requireMigPool } from "../db";

export interface MigAdminSession {
  orgId: string; userId: string; orgRole: "ORG_ADMIN";
  platformRole: undefined; expiresAt: Date;
}
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const random = () => randomBytes(32).toString("base64url");
const insecureLoopbackTest = () => process.env.NODE_ENV === "test" &&
  /^http:\/\/(?:127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(process.env.MIG_PUBLIC_ORIGIN ?? "");
const cookieName = () => insecureLoopbackTest() ? "mig-session" : "__Host-mig-session";
const stateCookieName = () => insecureLoopbackTest() ? "mig-login" : "__Host-mig-login";
let configuration: Promise<oidc.Configuration> | undefined;

export function oidcConfigured(): boolean {
  return ["MIG_PUBLIC_ORIGIN", "MIG_OIDC_ISSUER", "MIG_OIDC_CLIENT_ID",
    "MIG_OIDC_TENANT_REF", "MIG_TENANT_ID"].every(key => !!process.env[key]);
}
function publicOrigin(): string {
  const value = process.env.MIG_PUBLIC_ORIGIN;
  if (!value) throw new Error("MIG_PUBLIC_ORIGIN_NOT_CONFIGURED");
  const url = new URL(value);
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
      (url.protocol !== "https:" && !(process.env.NODE_ENV === "test" &&
        url.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(url.hostname)))) {
    throw new Error("MIG_PUBLIC_ORIGIN_INVALID");
  }
  return url.origin;
}
function configuredOidc() {
  if (!oidcConfigured()) throw new Error("MIG_OIDC_NOT_CONFIGURED");
  if (!configuration) {
    const issuer = new URL(process.env.MIG_OIDC_ISSUER!);
    if (issuer.protocol !== "https:") throw new Error("MIG_OIDC_ISSUER_INVALID");
    configuration = oidc.discovery(
      issuer, process.env.MIG_OIDC_CLIENT_ID!, process.env.MIG_OIDC_CLIENT_SECRET,
    ).catch(error => { configuration = undefined; throw error; });
  }
  return configuration;
}
function readCookie(req: Request, name: string): string | undefined {
  const found = req.headers.cookie?.split(";").map(part => part.trim())
    .find(part => part.startsWith(name + "="));
  if (!found) return;
  try { return decodeURIComponent(found.slice(name.length + 1)); } catch { return; }
}
const cookieOptions = () => ({
  httpOnly: true, secure: !insecureLoopbackTest(),
  sameSite: "lax" as const, path: "/",
});
function equal(a: string, b: string): boolean {
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
export function assertAdminMutationOrigin(req: Request): void {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return;
  if (req.header("origin") !== publicOrigin()) throw new Error("MIG_CSRF_REJECTED");
}

export async function verifyInternalSession(req: Request): Promise<MigAdminSession | null> {
  const token = readCookie(req, cookieName());
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token) || !process.env.MIG_TENANT_ID) return null;
  assertAdminMutationOrigin(req);
  const result = await requireMigPool().query(
    `SELECT tenant_id, subject_id, expires_at FROM mig_standalone_sessions
     WHERE token_hash = $1 AND tenant_id = $2 AND expires_at > NOW()`,
    [digest(token), process.env.MIG_TENANT_ID],
  );
  const row = result.rows[0];
  return row ? {
    orgId: row.tenant_id, userId: row.subject_id,
    orgRole: "ORG_ADMIN", platformRole: undefined, expiresAt: row.expires_at,
  } : null;
}

export async function requireEnterpriseAdminContext(
  req: Request, res: Response, options: { platformOnly?: boolean } = {},
) {
  try {
    assertAdminMutationOrigin(req);
    const session = await verifyInternalSession(req);
    if (!session) { res.status(401).json({ error: "MIG_ADMIN_AUTHENTICATION_REQUIRED" }); return; }
    if (options.platformOnly) {
      res.status(403).json({ error: "MIG_PLATFORM_ADMIN_AUTHORITY_REQUIRED" }); return;
    }
    return { tenantId: session.orgId, actorUserId: session.userId, role: session.orgRole };
  } catch (error) {
    res.status(error instanceof Error && error.message === "MIG_CSRF_REJECTED" ? 403 : 503)
      .json({ error: error instanceof Error && error.message === "MIG_CSRF_REJECTED"
        ? "MIG_CSRF_REJECTED" : "MIG_AUTHENTICATION_UNAVAILABLE" });
  }
}

export function registerMigAuthentication(app: Express): void {
  app.get("/api/auth/session", async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try {
      const session = await verifyInternalSession(req);
      res.json(session ? { authenticated: true,
        user: { id: session.userId, tenantId: session.orgId, role: session.orgRole } }
        : { authenticated: false });
    } catch { res.status(503).json({ error: "MIG_AUTHENTICATION_UNAVAILABLE" }); }
  });
  app.get("/api/auth/login", async (_req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try {
      const config = await configuredOidc();
      const state = random(), nonce = random(), verifier = oidc.randomPKCECodeVerifier();
      const challenge = await oidc.calculatePKCECodeChallenge(verifier);
      await requireMigPool().query(
        `INSERT INTO mig_standalone_login_states (state_hash, code_verifier, nonce, expires_at)
         VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes')`,
        [digest(state), verifier, nonce],
      );
      res.cookie(stateCookieName(), state, { ...cookieOptions(), maxAge: 5 * 60_000 });
      res.redirect(oidc.buildAuthorizationUrl(config, {
        redirect_uri: publicOrigin() + "/api/auth/callback", scope: "openid profile",
        code_challenge: challenge, code_challenge_method: "S256", state, nonce,
      }).href);
    } catch { res.status(503).json({ error: "MIG_OIDC_LOGIN_UNAVAILABLE" }); }
  });
  app.get("/api/auth/callback", async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.clearCookie(stateCookieName(), cookieOptions());
    try {
      const state = typeof req.query.state === "string" ? req.query.state : "";
      const cookie = readCookie(req, stateCookieName()) ?? "";
      if (!state || !cookie || !equal(state, cookie)) throw new Error("MIG_OIDC_STATE_MISMATCH");
      const row = await requireMigPool().query(
        `DELETE FROM mig_standalone_login_states
         WHERE state_hash = $1 AND expires_at > NOW() RETURNING code_verifier, nonce`,
        [digest(state)],
      );
      if (!row.rows[0]) throw new Error("MIG_OIDC_STATE_EXPIRED");
      const config = await configuredOidc();
      const callback = new URL(req.originalUrl, publicOrigin());
      const tokens = await oidc.authorizationCodeGrant(config, callback, {
        pkceCodeVerifier: row.rows[0].code_verifier, expectedState: state,
        expectedNonce: row.rows[0].nonce,
      });
      const claims = tokens.claims();
      const tenantClaim = process.env.MIG_OIDC_TENANT_CLAIM ?? "tenant_id";
      const roleClaim = process.env.MIG_OIDC_ROLE_CLAIM ?? "roles";
      const role = process.env.MIG_OIDC_ADMIN_ROLE ?? "MIG.Admin";
      if (!claims || typeof claims.sub !== "string" || !claims.sub ||
          claims[tenantClaim] !== process.env.MIG_OIDC_TENANT_REF ||
          !Array.isArray(claims[roleClaim]) || !(claims[roleClaim] as unknown[]).includes(role)) {
        throw new Error("MIG_OIDC_ADMIN_CLAIMS_REQUIRED");
      }
      const expiresAt = new Date(Math.min(Date.now() + 15 * 60_000,
        typeof claims.exp === "number" ? claims.exp * 1000 : 0));
      if (expiresAt.getTime() <= Date.now()) throw new Error("MIG_OIDC_TOKEN_EXPIRED");
      const token = random();
      await requireMigPool().query(
        `INSERT INTO mig_standalone_sessions (token_hash, tenant_id, subject_id, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [digest(token), process.env.MIG_TENANT_ID, claims.sub, expiresAt],
      );
      res.cookie(cookieName(), token, { ...cookieOptions(), expires: expiresAt });
      res.redirect("/mig");
    } catch { res.status(403).json({ error: "MIG_OIDC_AUTHENTICATION_REJECTED" }); }
  });
  app.post("/api/auth/logout", async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try {
      assertAdminMutationOrigin(req);
      const token = readCookie(req, cookieName());
      if (token) await requireMigPool().query(
        "DELETE FROM mig_standalone_sessions WHERE token_hash = $1 AND tenant_id = $2",
        [digest(token), process.env.MIG_TENANT_ID],
      );
      res.clearCookie(cookieName(), cookieOptions());
      res.status(204).end();
    } catch (error) {
      res.status(error instanceof Error && error.message === "MIG_CSRF_REJECTED" ? 403 : 503)
        .json({ error: "MIG_LOGOUT_NOT_ACKNOWLEDGED" });
    }
  });
}
