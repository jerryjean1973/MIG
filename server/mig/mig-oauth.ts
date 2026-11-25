/**
 * server/mig/mig-oauth.ts
 *
 * Extension point for external identity verification (OAuth2 client
 * credentials / JWKS-verified bearer tokens) before a MIG ticket is issued.
 * Today this is a documented stub: if an agent has no oauthClientId/jwksUrl
 * configured, identity is considered pre-verified via the admin-issued
 * agentId/ticketSecret pair alone. When an agent DOES configure OAuth,
 * callers must supply a bearer token and this module is the only place
 * that should ever validate it (never inline in routes).
 */

import type { MigRemoteAgent } from "@shared/schema";

export interface OAuthVerificationResult {
  verified: boolean;
  reason?: string;
}

/**
 * Stub verifier. Real JWKS-based verification would fetch agent.jwksUrl,
 * validate the bearer token's signature/issuer/audience, and confirm the
 * subject matches agent.oauthClientId. Left unimplemented intentionally —
 * no external IdP is wired into this project yet — but the call site in
 * mig-core.ts already gates ticket issuance on this function so wiring a
 * real IdP later requires no changes outside this file.
 */
export async function verifyExternalIdentity(
  agent: MigRemoteAgent,
  bearerToken?: string,
): Promise<OAuthVerificationResult> {
  if (!agent.oauthClientId && !agent.jwksUrl) {
    return { verified: true };
  }
  if (!bearerToken) {
    return { verified: false, reason: "oauth_configured_but_no_bearer_token_supplied" };
  }
  return {
    verified: false,
    reason: "oauth_verification_not_implemented — configure a real IdP integration before relying on this agent's oauthClientId/jwksUrl",
  };
}
