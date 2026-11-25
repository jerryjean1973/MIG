/**
 * server/mcp/contract-invocation-gate.ts
 *
 * assertContractValid() — checks all 17 conditions from the spec's
 * "Constitutional Execution Rule" in order and throws the appropriate typed
 * error code when any condition fails. Integrated into mcp-routes.ts
 * before the MIG classification check.
 *
 * The gate operates in two modes:
 *  - strict: requires contract envelope on every call (enforced per capability)
 *  - backward_compat: allows calls without contract if the capability has no
 *    ACTIVE contract for this client (time-bound, capability-level flag)
 */
import { randomUUID, timingSafeEqual } from "crypto";

import type { ContractInvocationEnvelope } from "../../shared/protocol/shared/mcp-contract-types";

import { sha256, canonicalJson } from "./contract-fingerprint-engine";

import { generateContractFingerprints } from "./contract-fingerprint-engine";

export interface ContractGateRepository {
  listMcpCapabilityContractsByClient(clientId: string, tenantId: string): Promise<ContractGateContract[]>;
  getMcpCapabilityContract(contractId: string): Promise<ContractGateContract | undefined>;
  updateMcpCapabilityContract(contractId: string, patch: { status?: string }): Promise<ContractGateContract | undefined>;
  checkMcpContractNonceUsed(nonce: string, contractId: string): Promise<boolean>;
  getMcpContractAuthRelationship(relationshipId: string): Promise<ContractGateAuthRelationship | undefined>;
  createMcpContractInvocationReference(data: ContractGateInvocationReference): Promise<unknown>;
}

export interface ContractGateContract {
  contractId: string;
  contractVersion: number;
  tenantId: string;
  capabilityId: string;
  clientId: string;
  status: string;
  validUntil?: Date | string | null;
  contractJson?: unknown;
}

export interface ContractGateAuthRelationship {
  relationshipId?: string;
  contractId: string;
  status: string;
  validUntil?: Date | string | null;
  migAttestation?: string | null;
}

export interface ContractGateInvocationReference {
  invocationRefId: string;
  contractId: string;
  contractVersion: number;
  tenantId: string;
  capabilityId: string;
  clientId: string;
  authorizationRelationshipId: string;
  toolName: string;
  nonce: string;
  gateResult: "pass" | "fail";
  failureCode?: string;
  hash: string;
  lineageJson: unknown;
}

export type CapabilityPolicyResolver = (capabilityId: string) =>
  { contract_backward_compat_until?: string | null } | undefined;

export class ContractGateError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "ContractGateError";
  }
}

export interface ContractGateResult {
  passed: boolean;
  contractId?: string;
  contractVersion?: number;
  authRelationshipId?: string;
  invocationRefId?: string;
}

export interface ContractGateContext {
  tenantId: string;
  clientId: string;
  toolName: string;
  capabilityId?: string;
  usedNonces?: Set<string>;
}

export async function assertContractValid(
  envelope: Partial<ContractInvocationEnvelope> | undefined | null,
  repository: ContractGateRepository,
  ctx: ContractGateContext,
  resolveCapabilityPolicy: CapabilityPolicyResolver = () => undefined,
): Promise<ContractGateResult> {

  // ── Condition 1: Check if contract is required for this capability/client ──
  // Scoped to the specific capabilityId being invoked (when known) — a contract for
  // capability A does NOT impose strict mode on capability B.
  // Only ACTIVE contracts are considered — expired/revoked do not trigger strict mode.
  const allActiveContracts = await repository.listMcpCapabilityContractsByClient(ctx.clientId, ctx.tenantId);
  const relevantContracts = ctx.capabilityId
    ? allActiveContracts.filter(c => c.capabilityId === ctx.capabilityId)
    : allActiveContracts;
  const hasActiveContract = relevantContracts.length > 0;

  if (!hasActiveContract) {
    // No active contract for this client/capability.
    // Whether to allow the call without a contract depends on the capability's
    // backward-compatibility window (contract_backward_compat_until):
    //
    //   undefined  → not configured for contract governance; allow (lenient default).
    //   null       → strict enforcement active; reject with CONTRACT_REQUIRED.
    //   ISO-8601   → allow if the window has not yet expired; reject after expiry.
    //
    // When capabilityId is not known at invocation time we cannot look up the flag —
    // allow backward-compat to avoid blocking unknown/internal callers.
    if (ctx.capabilityId) {
      const cap = resolveCapabilityPolicy(ctx.capabilityId);
      const bcu = cap?.contract_backward_compat_until; // undefined | null | string
      if (bcu === null || (bcu !== undefined && new Date(bcu) <= new Date())) {
        // Explicit strict enforcement or window has closed.
        throw new ContractGateError(
          "CONTRACT_REQUIRED",
          `Capability "${ctx.capabilityId}" requires a negotiated contract — no active contract found for this client. ` +
          (bcu === null ? "Strict enforcement is active." : `Backward-compatibility window closed at ${bcu}.`),
        );
      }
    }
    return { passed: true };
  }

  // ── Condition 2: contractId must be present ────────────────────────────────
  if (!envelope?.contractId) {
    throw new ContractGateError("CONTRACT_REQUIRED", "No contractId in invocation envelope — contract required for this capability.");
  }

  // ── Condition 3: contractVersion must be present ──────────────────────────
  if (typeof envelope.contractVersion !== "number") {
    throw new ContractGateError("CONTRACT_VERSION_MISMATCH", "contractVersion must be a number.");
  }

  // ── Condition 4: authorizationRelationshipId must be present ─────────────
  if (!envelope.authorizationRelationshipId) {
    throw new ContractGateError("CONTRACT_AUTH_RELATIONSHIP_INVALID", "authorizationRelationshipId is required.");
  }

  // ── Condition 5: runtimeAuthorizationId must be present ──────────────────
  if (!envelope.runtimeAuthorizationId) {
    throw new ContractGateError("CONTRACT_AUTH_RELATIONSHIP_INVALID", "runtimeAuthorizationId is required.");
  }

  // ── Condition 6: nonce must be present ───────────────────────────────────
  if (!envelope.nonce) {
    throw new ContractGateError("CONTRACT_NONCE_REUSED", "nonce is required.");
  }

  // ── Condition 7: nonce must not be reused (persistent + in-memory check) ────
  // In-memory check for within-process nonce sets (fast path):
  if (ctx.usedNonces?.has(envelope.nonce)) {
    throw new ContractGateError("CONTRACT_NONCE_REUSED", "nonce has already been used — replay attack detected.");
  }
  // Persistent DB check — survives server restarts and horizontal scaling:
  const nonceExists = await repository.checkMcpContractNonceUsed(envelope.nonce, envelope.contractId!);
  if (nonceExists) {
    throw new ContractGateError("CONTRACT_NONCE_REUSED", "nonce has already been recorded — replay attack rejected.");
  }

  // ── Condition 8: intent must be present ──────────────────────────────────
  if (!envelope.intent) {
    throw new ContractGateError("CONTRACT_REQUIRED", "intent is required in invocation envelope.");
  }

  // ── Condition 9: Resolve the contract row ────────────────────────────────
  const contractRow = await repository.getMcpCapabilityContract(envelope.contractId);
  if (!contractRow) {
    throw new ContractGateError("CONTRACT_NOT_FOUND", `Contract "${envelope.contractId}" not found.`);
  }

  // ── Condition 10: Contract must be active ────────────────────────────────
  if (contractRow.status !== "active") {
    const code = contractRow.status === "revoked" ? "CONTRACT_REVOKED"
      : contractRow.status === "expired" ? "CONTRACT_EXPIRED"
      : "CONTRACT_INACTIVE";
    throw new ContractGateError(code, `Contract is "${contractRow.status}".`);
  }

  // ── Condition 11: Contract version must match ─────────────────────────────
  if (contractRow.contractVersion !== envelope.contractVersion) {
    throw new ContractGateError("CONTRACT_VERSION_MISMATCH",
      `Contract version mismatch: stored=${contractRow.contractVersion}, provided=${envelope.contractVersion}.`);
  }

  // ── Condition 12: tenantId must match ─────────────────────────────────────
  if (contractRow.tenantId !== ctx.tenantId) {
    throw new ContractGateError("CONTRACT_INACTIVE", "Contract tenant mismatch.");
  }

  // ── Condition 13: clientId must match ─────────────────────────────────────
  if (contractRow.clientId !== ctx.clientId) {
    throw new ContractGateError("CONTRACT_INACTIVE", "Contract client mismatch.");
  }

  // ── Condition 13b: Contract must cover the invoked capability ────────────
  // A contract for capability A cannot authorize invocation of capability B.
  // `CONTRACT_CAPABILITY_NOT_COVERED` is a hard gate failure — no backward-compat.
  if (ctx.capabilityId && contractRow.capabilityId !== ctx.capabilityId) {
    throw new ContractGateError("CONTRACT_CAPABILITY_NOT_COVERED",
      `Contract covers capability "${contractRow.capabilityId}" but invocation is for "${ctx.capabilityId}" — contract does not authorize this capability.`);
  }

  // ── Condition 14: Contract must not be expired ────────────────────────────
  if (contractRow.validUntil && new Date(contractRow.validUntil) < new Date()) {
    await repository.updateMcpCapabilityContract(contractRow.contractId, { status: "expired" });
    throw new ContractGateError("CONTRACT_EXPIRED", "Contract validity period has elapsed.");
  }

  // ── Condition 15: Fingerprint must match ──────────────────────────────────
  // Guards: only runs if contractJson has the required blocks to re-derive fingerprints.
  // If re-derivation fails (e.g. contractJson is an abbreviated snapshot), the check
  // is skipped — the gate does not fail on an inability to recompute, only on a
  // confirmed mismatch.
  const contractJson = contractRow.contractJson as any;
  if (contractJson && typeof contractJson === "object") {
    const storedFingerprints = (contractJson as any).fingerprints;
    if (storedFingerprints && contractJson.requestContract && contractJson.responseContract) {
      try {
        const currentFingerprints = generateContractFingerprints(contractJson);
        if (currentFingerprints.compatibilityFingerprint !== storedFingerprints.compatibilityFingerprint ||
            currentFingerprints.governanceFingerprint !== storedFingerprints.governanceFingerprint) {
          throw new ContractGateError("CONTRACT_FINGERPRINT_MISMATCH",
            "Contract fingerprints have changed since acceptance — renegotiation required.");
        }
      } catch (err) {
        if (err instanceof ContractGateError) throw err;
        // Computation failed for a non-material reason — skip the check.
      }
    }
  }

  // ── Condition 16: Authorization relationship must be active ───────────────
  const authRel = await repository.getMcpContractAuthRelationship(envelope.authorizationRelationshipId);
  if (!authRel) {
    throw new ContractGateError("CONTRACT_AUTH_RELATIONSHIP_INVALID",
      `Authorization relationship "${envelope.authorizationRelationshipId}" not found.`);
  }
  if (authRel.status !== "active") {
    throw new ContractGateError("CONTRACT_AUTH_RELATIONSHIP_INVALID",
      `Authorization relationship is "${authRel.status}".`);
  }
  if (authRel.contractId !== envelope.contractId) {
    throw new ContractGateError("CONTRACT_AUTH_RELATIONSHIP_INVALID",
      "Authorization relationship does not match the provided contractId.");
  }
  if (authRel.validUntil && new Date(authRel.validUntil) < new Date()) {
    throw new ContractGateError("CONTRACT_AUTH_RELATIONSHIP_INVALID",
      "Authorization relationship has expired.");
  }

  // ── Condition 17: signature must match the stored migAttestation ──────────
  // The client presents the migAttestation string they received when their contract
  // was finalized by issueMigContractAttestation(). We verify it against the stored
  // value using a constant-time comparison to prevent timing oracle attacks.
  // A missing or mismatched signature is a hard gate failure.
  if (!envelope.signature) {
    throw new ContractGateError("CONTRACT_SIGNATURE_INVALID",
      "signature is required — include the migAttestation value from your authorization relationship.");
  }
  const storedAttestation = authRel.migAttestation;
  if (!storedAttestation) {
    throw new ContractGateError("CONTRACT_SIGNATURE_INVALID",
      "Authorization relationship has no stored attestation — contract may not be fully finalized.");
  }
  try {
    const provided = Buffer.from(envelope.signature, "utf8");
    const stored   = Buffer.from(storedAttestation, "utf8");
    // timingSafeEqual requires equal-length buffers; mismatched length is itself a failure.
    const maxLen = Math.max(provided.length, stored.length);
    const padded1 = Buffer.concat([provided, Buffer.alloc(maxLen - provided.length)]);
    const padded2 = Buffer.concat([stored,   Buffer.alloc(maxLen - stored.length)]);
    const lengthMatch   = provided.length === stored.length;
    const contentMatch  = timingSafeEqual(padded1, padded2);
    if (!lengthMatch || !contentMatch) {
      throw new ContractGateError("CONTRACT_SIGNATURE_INVALID",
        "Provided signature does not match the stored MIG attestation — contract rejected.");
    }
  } catch (err) {
    if (err instanceof ContractGateError) throw err;
    throw new ContractGateError("CONTRACT_SIGNATURE_INVALID", "Signature verification failed.");
  }

  // ── All conditions passed — write invocation reference ───────────────────
  const invocationRefId = `invref_${randomUUID().replace(/-/g, "")}`;
  const reserved = await repository.createMcpContractInvocationReference({
    invocationRefId,
    contractId: contractRow.contractId,
    contractVersion: contractRow.contractVersion,
    tenantId: ctx.tenantId,
    capabilityId: contractRow.capabilityId,
    clientId: ctx.clientId,
    authorizationRelationshipId: envelope.authorizationRelationshipId,
    toolName: ctx.toolName,
    nonce: envelope.nonce,
    gateResult: "pass",
    hash: sha256(canonicalJson({ invocationRefId, contractId: contractRow.contractId, nonce: envelope.nonce })),
    lineageJson: { toolName: ctx.toolName, intent: envelope.intent },
  });
  if (reserved === false) {
    throw new ContractGateError(
      "CONTRACT_NONCE_REUSED",
      "nonce was concurrently recorded — replay attack rejected.",
    );
  }

  return {
    passed: true,
    contractId: contractRow.contractId,
    contractVersion: contractRow.contractVersion,
    authRelationshipId: envelope.authorizationRelationshipId,
    invocationRefId,
  };
}

export async function recordFailedGateInvocation(
  envelope: Partial<ContractInvocationEnvelope> | undefined | null,
  repository: ContractGateRepository,
  ctx: ContractGateContext,
  failureCode: string,
): Promise<void> {
  try {
    const invocationRefId = `invref_${randomUUID().replace(/-/g, "")}`;
    await repository.createMcpContractInvocationReference({
      invocationRefId,
      contractId: envelope?.contractId ?? "UNKNOWN",
      contractVersion: envelope?.contractVersion ?? 0,
      tenantId: ctx.tenantId,
      capabilityId: ctx.capabilityId ?? "UNKNOWN",
      clientId: ctx.clientId,
      authorizationRelationshipId: envelope?.authorizationRelationshipId ?? "UNKNOWN",
      toolName: ctx.toolName,
      nonce: envelope?.nonce ?? "UNKNOWN",
      gateResult: "fail",
      failureCode,
      hash: sha256(canonicalJson({ invocationRefId, failureCode })),
      lineageJson: { failureCode, toolName: ctx.toolName },
    });
  } catch {
    // best-effort audit
  }
}
