/**
 * server/mcp/contract-fingerprint-engine.ts
 *
 * Produces seven deterministic SHA-256 fingerprints from a contract draft.
 * Fingerprints use canonical JSON (sorted keys, normalized enums, stripped
 * doc-only text). Used at offer-generation time and on every capability-version
 * bump to detect which contract dimensions changed.
 */
import { createHash } from "crypto";

import type { MCPCapabilityContract, ContractFingerprints, ContractRequestBlock, ContractResponseBlock, ContractSemanticsBlock, ContractConstraintsBlock, ContractDataQualityBlock, ContractAuthorizationBlock, ContractErrorsBlock } from "../../shared/protocol/shared/mcp-contract-types";

function sortedKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sortedKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = sortedKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

function canonicalJson(obj: unknown): string {
  return JSON.stringify(sortedKeys(obj));
}

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

function stripDocFields<T extends Record<string, unknown>>(obj: T, docFields: string[]): Omit<T, string> {
  const copy = { ...obj } as Record<string, unknown>;
  for (const f of docFields) delete copy[f];
  return copy as Omit<T, string>;
}

function compatibilityFingerprint(
  req: ContractRequestBlock,
  res: ContractResponseBlock,
): string {
  const material = {
    required_fields: req.required_fields.map(f => ({ field: f.field, type: f.type })),
    optional_fields: req.optional_fields.map(f => ({ field: f.field, type: f.type })),
    forbidden_fields: req.forbidden_fields,
    guaranteed_fields: res.guaranteed_fields.map(f => ({ field: f.field, type: f.type })),
    conditional_fields: res.conditional_fields.map(f => ({ field: f.field, condition: f.condition })),
  };
  return sha256(canonicalJson(material));
}

function schemaFingerprint(
  req: ContractRequestBlock,
  res: ContractResponseBlock,
): string {
  const material = {
    request: req,
    response: stripDocFields(res as unknown as Record<string, unknown>, ["field_meanings"]),
  };
  return sha256(canonicalJson(material));
}

function semanticFingerprint(sem: ContractSemanticsBlock): string {
  const material = stripDocFields(sem as unknown as Record<string, unknown>, []);
  return sha256(canonicalJson(material));
}

function constraintFingerprint(con: ContractConstraintsBlock): string {
  const material = stripDocFields(con as unknown as Record<string, unknown>, []);
  return sha256(canonicalJson(material));
}

function governanceFingerprint(auth: ContractAuthorizationBlock): string {
  const material = stripDocFields(auth as unknown as Record<string, unknown>, []);
  return sha256(canonicalJson(material));
}

function dataQualityFingerprint(dq: ContractDataQualityBlock): string {
  const material = stripDocFields(dq as unknown as Record<string, unknown>, []);
  return sha256(canonicalJson(material));
}

function behaviorFingerprint(err: ContractErrorsBlock): string {
  const material = stripDocFields(err as unknown as Record<string, unknown>, []);
  return sha256(canonicalJson(material));
}

export function generateContractFingerprints(
  contract: Pick<
    MCPCapabilityContract,
    "requestContract" | "responseContract" | "semantics" | "constraints" | "dataQuality" | "authorization" | "errorsAndPartialResults"
  >,
): ContractFingerprints {
  return {
    compatibilityFingerprint: compatibilityFingerprint(contract.requestContract, contract.responseContract),
    schemaFingerprint: schemaFingerprint(contract.requestContract, contract.responseContract),
    semanticFingerprint: semanticFingerprint(contract.semantics),
    constraintFingerprint: constraintFingerprint(contract.constraints),
    governanceFingerprint: governanceFingerprint(contract.authorization),
    dataQualityFingerprint: dataQualityFingerprint(contract.dataQuality),
    behaviorFingerprint: behaviorFingerprint(contract.errorsAndPartialResults),
  };
}

export { sha256, canonicalJson };
