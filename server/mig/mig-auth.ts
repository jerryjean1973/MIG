/**
 * server/mig/mig-auth.ts
 *
 * Signed, scoped MIG tickets. No JWT library is installed in this project
 * (see .agents/memory) so tickets use a self-signed HMAC-SHA256 compact
 * serialization: base64url(header).base64url(payload).base64url(signature),
 * mirroring the sha256 hashed-key pattern already used by mcp_api_keys.
 *
 * This module ONLY signs/verifies. It never decides authorization — that is
 * mig-core.ts's job, using the agent/intent/policy data this module exposes.
 */

import { createHmac, randomBytes, timingSafeEqual } from "crypto";
import type { MigTicketPayload } from "./mig-types";

const HEADER = { alg: "HS256", typ: "MIGT" };

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function sign(data: string, secret: string): string {
  return createHmac("sha256", secret).update(data).digest("base64url");
}

export function generateTicketId(): string {
  return `mig_tkt_${randomBytes(16).toString("hex")}`;
}

export function generateAgentSecret(): string {
  return randomBytes(32).toString("hex");
}

/** Signs a ticket payload with the issuing agent's ticket secret. */
export function signMigTicket(payload: MigTicketPayload, agentSecret: string): string {
  const headerPart = b64url(JSON.stringify(HEADER));
  const payloadPart = b64url(JSON.stringify(payload));
  const signature = sign(`${headerPart}.${payloadPart}`, agentSecret);
  return `${headerPart}.${payloadPart}.${signature}`;
}

export interface MigTicketVerification {
  valid: boolean;
  payload?: MigTicketPayload;
  reason?: string;
}

/**
 * Verifies signature + structural shape only. Callers (mig-core.ts) are
 * responsible for checking expiry, revocation, and DB-backed ticket state.
 */
export function verifyMigTicketSignature(token: string, agentSecret: string): MigTicketVerification {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return { valid: false, reason: "malformed_ticket" };
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  const expectedSignature = sign(`${headerPart}.${payloadPart}`, agentSecret);

  const a = Buffer.from(signaturePart);
  const b = Buffer.from(expectedSignature);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { valid: false, reason: "signature_mismatch" };
  }

  let payload: MigTicketPayload;
  try {
    payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
  } catch {
    return { valid: false, reason: "malformed_payload" };
  }

  if (!payload.jti || !payload.agent_id || !payload.intent_id || !payload.exp) {
    return { valid: false, reason: "incomplete_payload" };
  }

  if (Date.now() / 1000 > payload.exp) {
    return { valid: false, reason: "expired" };
  }

  return { valid: true, payload };
}

/** Extracts the unverified agent_id from a ticket without checking signature — used only to look up which secret to verify against. */
export function peekTicketAgentId(token: string): string | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return payload.agent_id;
  } catch {
    return undefined;
  }
}
