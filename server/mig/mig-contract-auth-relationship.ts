/**
 * server/mig/mig-contract-auth-relationship.ts
 *
 * issueMigContractAttestation() — runs final MIG policy validation after
 * mutual acceptance. Emits a ContractAuthorizationRelationship row and a
 * signed migAttestation string using the existing HMAC signing in mig-auth.ts.
 *
 * This relationship establishes eligibility but does NOT replace per-invocation
 * authorizeExecution() — it is a one-time, persistent proof that MIG approved
 * the negotiated contract.
 */

import { createHash, createHmac, randomBytes, randomUUID } from "crypto";
import type { IStorage } from "../storage";
import type {
  MCPCapabilityContract,
  MigContractPolicyResult,
  ContractAuthorizationRelationship,
} from "../../shared/protocol/shared/mcp-contract-types";
import { validateAcceptedContractForAttestation, type TenantPolicy } from "./mig-contract-policy";
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}
function sha256(value: string): string { return createHash("sha256").update(value).digest("hex"); }

// MIG uses the same HMAC-SHA256 signing pattern as mig-auth.ts.
// The signing secret is derived from the tenant's MIG configuration; for this
// implementation we derive it deterministically from the server-side secret.
/**
 * MIG_ATTESTATION_SECRET — must be set via MIG_ATTESTATION_SECRET env var.
 * Fail-closed: if the env var is absent the signing function throws, preventing
 * attestation issuance with a predictable key.
 */
function getMigAttestationSecret(): string {
  const secret = process.env.MIG_ATTESTATION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      "MIG_ATTESTATION_SECRET env var is not set or too short (min 32 chars). " +
      "Set it before issuing MIG contract attestations.",
    );
  }
  return secret;
}

function signAttestation(payload: Record<string, unknown>): string {
  const data = canonicalJson(payload);
  return createHmac("sha256", getMigAttestationSecret()).update(data).digest("base64url");
}

const DEFAULT_RELATIONSHIP_TTL_HOURS = 24 * 30; // 30 days

export interface AttestationInput {
  contract: MCPCapabilityContract;
  tenantPolicy: TenantPolicy;
  capabilityRegistry: { capability_id: string; capability_name: string; classification: string; eligible_domains: readonly string[] } | null;
}

export interface AttestationResult {
  relationship: ContractAuthorizationRelationship;
  policyResult: MigContractPolicyResult;
}

/**
 * issueMigContractAttestation — issues a ContractAuthorizationRelationship for
 * a mutually-accepted contract, provided it passes MIG final policy validation.
 */
export async function issueMigContractAttestation(
  storage: IStorage,
  input: AttestationInput,
): Promise<AttestationResult> {
  const { contract, tenantPolicy, capabilityRegistry } = input;

  // Run MIG final policy validation
  // Use the attestation-specific validator that does NOT check unchanged mandatory-tagged blocks
  const policyResult = validateAcceptedContractForAttestation(contract, capabilityRegistry, tenantPolicy);

  if (!policyResult.allowed) {
    throw new Error(
      `MIG_ATTESTATION_FAILED: ${policyResult.findings.filter(f => f.severity === "error").map(f => f.code).join(", ")}`,
    );
  }

  const relationshipId = `rel_${randomUUID().replace(/-/g, "")}`;
  const now = new Date();
  const validUntil = new Date(now.getTime() + DEFAULT_RELATIONSHIP_TTL_HOURS * 3600 * 1000);

  // Build the attestation payload — signed with MIG secret
  const attestationPayload = {
    relationshipId,
    contractId: contract.contractId,
    contractVersion: contract.contractVersion,
    tenantId: contract.tenantId,
    clientId: contract.clientId,
    capabilityId: contract.capabilityId,
    issuedAt: now.toISOString(),
    validUntil: validUntil.toISOString(),
    fingerprints: contract.fingerprints,
    policyFindings: policyResult.findings.length,
  };

  const migAttestation = signAttestation(attestationPayload);
  const attestationFingerprint = sha256(canonicalJson(attestationPayload));

  const relationshipHash = sha256(canonicalJson({ relationshipId, contractId: contract.contractId, attestationFingerprint }));

  const row = await storage.createMcpContractAuthRelationship({
    relationshipId,
    contractId: contract.contractId,
    contractVersion: contract.contractVersion,
    tenantId: contract.tenantId,
    capabilityId: contract.capabilityId,
    clientId: contract.clientId,
    validUntil,
    migAttestation,
    attestationFingerprint,
    status: "active",
    hash: relationshipHash,
    lineageJson: {
      policyFindings: policyResult.findings.length,
      contractFingerprints: contract.fingerprints,
    },
  });

  const relationship: ContractAuthorizationRelationship = {
    relationshipId: row.relationshipId,
    contractId: row.contractId,
    contractVersion: row.contractVersion,
    tenantId: row.tenantId,
    clientId: row.clientId,
    capabilityId: row.capabilityId,
    issuedAt: row.issuedAt.toISOString(),
    validUntil: row.validUntil?.toISOString() ?? validUntil.toISOString(),
    migAttestation: row.migAttestation,
    status: row.status as "active" | "revoked" | "expired",
    attestationFingerprint: row.attestationFingerprint,
  };

  return { relationship, policyResult };
}
