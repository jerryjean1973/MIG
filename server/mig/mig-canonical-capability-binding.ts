/**
 * MIG-side candidate binding and exact runtime resolution for Corporate Brain
 * capabilities. This is deliberately not an authority evaluator: candidates
 * never grant access, and confirmed bindings are still intersected with the
 * Corporate Brain authority service by the caller.
 */
import { createHash } from "node:crypto";
import type {
  CanonicalMCPKnowledgeBinding,
  CBAuthorityOperation,
} from "../../shared/protocol/shared/corporate-brain/canonical-knowledge-authority";
import { CB_AUTHORITY_OPERATIONS } from "@shared/corporate-brain/canonical-knowledge-authority";
import type { MigAdapterToolEntry } from "./mig-types";

export interface BindingMetadata {
  tenant_id: string;
  mcp_server_id: string;
  intent_ids?: string[];
  domains?: string[];
  resource_refs?: string[];
}

const canonicalJson = (value: unknown): string => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const row = value as Record<string, unknown>;
  return `{${Object.keys(row).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(row[key])}`).join(",")}}`;
};

export function schemaFingerprint(tool: MigAdapterToolEntry): string {
  return createHash("sha256").update(canonicalJson({
    input: tool.input_schema ?? {},
    output: tool.output_schema ?? {},
    schema_version: tool.schema_version ?? "1",
    canonical_operation: tool.canonical_operation,
  })).digest("hex");
}

function hasSemanticField(schema: Record<string, unknown> | undefined, names: string[]): boolean {
  const properties = schema?.properties;
  return !!properties && typeof properties === "object"
    && names.some(name => Object.prototype.hasOwnProperty.call(properties, name));
}

/**
 * Derives a non-authoritative candidate from all available declarations.
 * Tool-name heuristics are intentionally not used. Missing producer, object,
 * schema, or ownership evidence leaves the candidate INFERRED and fail-closed.
 */
export function deriveCanonicalCapabilityBinding(
  tool: MigAdapterToolEntry,
  metadata: BindingMetadata,
): CanonicalMCPKnowledgeBinding | undefined {
  const producer = tool.producer_declaration;
  const resource = tool.canonical_resource;
  if (!producer || !producer.producer_id || !producer.producer_domain || !producer.service_id
    || !resource || !resource.tenant_id || !resource.partition || !resource.canonical_object_id
    || resource.tenant_id !== metadata.tenant_id
    || !tool.schema_version || !tool.has_governance_contract) return undefined;
  const input = tool.input_schema;
  const output = tool.output_schema;
  if (!input || typeof input !== "object" || !output || typeof output !== "object") return undefined;
  const read = tool.semantic_action === "read" || hasSemanticField(output, ["knowledge", "knowledge_id", "records"]);
  const exportEffect = hasSemanticField(output, ["export", "export_ref", "extracted"]);
  const referenceEffect = hasSemanticField(output, ["reference", "reference_ref"]);
  const authoritative = tool.mutation_class === "append_only" || tool.mutation_class === "governed_transition";
  if (tool.canonical_operation !== undefined && !CB_AUTHORITY_OPERATIONS.includes(tool.canonical_operation)) {
    return undefined;
  }
  // Explicit declarations are authoritative for classification. The fallback is
  // retained solely for legacy candidate generation and never uses tool names.
  const operation: CBAuthorityOperation | undefined = tool.canonical_operation ?? (authoritative
    ? (tool.semantic_action === "administer" ? "SUPERSEDE" : "DECLARE")
    : exportEffect ? "EXPORT" : referenceEffect ? "REFERENCE" : read ? "READ" : undefined);
  const effect: CanonicalMCPKnowledgeBinding["effect"] = operation ?? "COMPUTATION_ONLY";
  const evidence = [
    `schema:${schemaFingerprint(tool)}`,
    `producer:${producer.producer_id}`,
    `resource:${resource.tenant_id}:${resource.partition}:${resource.canonical_object_id}`,
    ...(producer.ownership_proof_ref ? [`ownership:${producer.ownership_proof_ref}`] : []),
    ...(producer.origin_proof_ref ? [`origin:${producer.origin_proof_ref}`] : []),
  ];
  return {
    binding_id: `mcpkb_${createHash("sha256").update(canonicalJson({
      tenant_id: metadata.tenant_id, mcp_server_id: metadata.mcp_server_id,
      mcp_tool_name: tool.tool_name, mcp_schema_version: tool.schema_version,
      schema_fingerprint: schemaFingerprint(tool),
      producer_id: producer.producer_id, service_id: producer.service_id,
      capability_id: tool.capability_id, partition: resource.partition,
      canonical_object_id: resource.canonical_object_id, resource_version: resource.version,
    })).digest("hex").slice(0, 32)}`,
    binding_version: "1",
    tenant_id: metadata.tenant_id,
    mcp_server_id: metadata.mcp_server_id,
    mcp_tool_name: tool.tool_name,
    capability_id: tool.capability_id,
    mcp_schema_version: tool.schema_version,
    schema_fingerprint: schemaFingerprint(tool),
    producer_id: producer.producer_id,
    producer_domain: producer.producer_domain,
    service_id: producer.service_id,
    partition: resource.partition,
    canonical_object_id: resource.canonical_object_id,
    knowledge_id: resource.knowledge_id,
    resource_version: resource.version,
    knowledge_class: resource.knowledge_class,
    domain_id: resource.domain_id,
    sensitivity_class: resource.sensitivity_class,
    data_contract_id: tool.data_contract_id,
    data_contract_version: tool.data_contract_version,
    effect,
    operation,
    route_constraints: [...(metadata.domains ?? tool.domain_scope)],
    intent_constraints: [...(metadata.intent_ids ?? [])],
    capability_constraints: [tool.capability_id],
    derivation_evidence: evidence,
    status: "INFERRED",
    confirmation_lineage: [],
    effective_from: new Date().toISOString(),
  };
}

export function confirmCanonicalCapabilityBinding(
  candidate: CanonicalMCPKnowledgeBinding,
  input: {
    confirmation_ref: string;
    ownership_proof: { proof_ref: string; verified: boolean; tenant_id: string; producer_id: string; producer_domain: string };
    object_proof: { proof_ref: string; verified: boolean; tenant_id: string; canonical_object_id: string; resource_version?: string };
    data_contract?: { proof_ref: string; version: string; verified: boolean; contract_id: string };
  },
): CanonicalMCPKnowledgeBinding {
  if (!input.confirmation_ref.trim()
    || !input.ownership_proof?.proof_ref.trim() || !input.ownership_proof.verified
    || !input.object_proof?.proof_ref.trim() || !input.object_proof.verified) {
    throw new Error("MIG_KNOWLEDGE_BINDING_CONFIRMATION_INCOMPLETE");
  }
  if (input.ownership_proof.tenant_id !== candidate.tenant_id
    || input.ownership_proof.producer_id !== candidate.producer_id
    || input.ownership_proof.producer_domain !== candidate.producer_domain
    || input.object_proof.tenant_id !== candidate.tenant_id
    || input.object_proof.canonical_object_id !== candidate.canonical_object_id
    || (candidate.resource_version && input.object_proof.resource_version !== candidate.resource_version)) {
    throw new Error("MIG_KNOWLEDGE_BINDING_PROOF_MISMATCH");
  }
  if ((candidate.operation === "EXPORT" || candidate.effect !== "COMPUTATION_ONLY")
    && (!input.data_contract?.proof_ref.trim() || !input.data_contract.version.trim() || !input.data_contract.verified
      || input.data_contract.contract_id !== candidate.data_contract_id
      || input.data_contract.version !== candidate.data_contract_version)) {
    throw new Error("MIG_KNOWLEDGE_BINDING_DATA_CONTRACT_REQUIRED");
  }
  const successorId = `mcpkb_${createHash("sha256").update(canonicalJson({
    predecessor: candidate.binding_id, confirmation: input.confirmation_ref,
    ownership: input.ownership_proof.proof_ref, object: input.object_proof.proof_ref,
  })).digest("hex").slice(0, 32)}`;
  const version = String(Number.parseInt(candidate.binding_version, 10) + 1);
  return Object.freeze({
    ...candidate,
    binding_id: successorId,
    binding_version: Number.isFinite(Number.parseInt(version, 10)) ? version : "2",
    supersedes_binding_id: candidate.binding_id,
    status: "CONFIRMED",
    confirmation_lineage: [
      ...candidate.confirmation_lineage, input.confirmation_ref,
      `ownership:${input.ownership_proof.proof_ref}`,
      `object:${input.object_proof.proof_ref}`,
      ...(input.data_contract ? [`data-contract:${input.data_contract.proof_ref}@${input.data_contract.version}`] : []),
    ],
  });
}

export function resolveExactCanonicalCapabilityBinding(
  bindings: readonly CanonicalMCPKnowledgeBinding[],
  input: { tenant_id: string; mcp_server_id: string; tool_name: string; capability_id: string; schema_version: string; binding_id?: string },
): CanonicalMCPKnowledgeBinding {
  const matches = bindings.filter(binding =>
    ["CONFIRMED", "OVERRIDDEN"].includes(binding.status)
    && binding.tenant_id === input.tenant_id
    && binding.mcp_server_id === input.mcp_server_id
    && binding.mcp_tool_name === input.tool_name
    && binding.capability_id === input.capability_id
    && binding.mcp_schema_version === input.schema_version
    && (!input.binding_id || binding.binding_id === input.binding_id),
  );
  if (matches.length !== 1) throw new Error("MIG_KNOWLEDGE_BINDING_UNRESOLVED");
  return matches[0];
}

export function assertBindingRequestMatches(
  binding: CanonicalMCPKnowledgeBinding,
  request: { operation?: string; resource_ref?: string; capability_id?: string },
): void {
  if (request.capability_id !== undefined && request.capability_id !== binding.capability_id) {
    throw new Error("MIG_KNOWLEDGE_CAPABILITY_MISMATCH");
  }
  if (request.operation !== undefined && request.operation !== binding.operation) {
    throw new Error("MIG_KNOWLEDGE_OPERATION_MISMATCH");
  }
  if (request.resource_ref !== undefined) {
    const expected = `cb:${binding.tenant_id}:${binding.partition}:${binding.canonical_object_id}${binding.resource_version ? `@${binding.resource_version}` : ""}`;
    if (request.resource_ref !== expected) throw new Error("MIG_KNOWLEDGE_RESOURCE_MISMATCH");
  }
}