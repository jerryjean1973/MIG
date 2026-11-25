/**
 * MIG's transport contract with existing canonical owners. A bridge response
 * transports an owner's decision; it never grants authority by itself.
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const MIG_OWNER_BRIDGE_SCHEMA = "mig.owner-bridge.v1" as const;
export const MIG_OWNER_OPERATIONS = [
  "catalog.read", "tool.execute", "tool.input.validate", "tool.output.validate", "tool.authorityAssertionInput", "envelope.validate",
  "onboarding.evaluate", "knowledge.listBindings", "knowledge.bindMcpCapability",
  "knowledge.authorizeAndPersist", "knowledge.authorizeProtectedMcpInvocation",
  "knowledge.recordMcpSchemaAccessAlert", "knowledge.listMcpSchemaAccessAlerts",
  "knowledge.createMcpSchemaReviewCandidate", "knowledge.getGovernedKnowledgeById",
  "enterprise.listCapabilities", "enterprise.listOrganizations",
] as const;
export type MigOwnerOperation = typeof MIG_OWNER_OPERATIONS[number];

export interface MigOwnerBridgeRequest {
  schema_version: typeof MIG_OWNER_BRIDGE_SCHEMA;
  operation: MigOwnerOperation;
  tenant_id: string;
  nonce: string;
  expires_at: number;
  args: unknown[];
}

/** JSON-safe, lossless Date transport; ordinary evidence objects stay ordinary. */
export function encodeMigOwnerValue(value: unknown): unknown {
  if (typeof value === "number" && !Number.isFinite(value)) throw new Error("MIG_OWNER_UNSERIALIZABLE_VALUE");
  if (value === undefined) return { $mig_wire_type: "Undefined" };
  if (value instanceof Date) return { $mig_wire_type: "Date", value: value.toISOString() };
  if (value instanceof Set) return { $mig_wire_type: "Set", value: [...value].map(encodeMigOwnerValue) };
  if (value instanceof Map) return { $mig_wire_type: "Map",
    value: [...value].map(([key, item]) => [encodeMigOwnerValue(key), encodeMigOwnerValue(item)]) };
  if (Array.isArray(value)) return value.map(encodeMigOwnerValue);
  if (value && typeof value === "object" && Object.hasOwn(value, "$mig_wire_type")) {
    return { $mig_wire_type: "Object",
      value: Object.entries(value).map(([key, item]) => [key, encodeMigOwnerValue(item)]) };
  }
  if (value && typeof value === "object") {
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      throw new Error("MIG_OWNER_UNSERIALIZABLE_VALUE");
    }
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encodeMigOwnerValue(item)]));
  }
  if (typeof value === "bigint" || typeof value === "function" ||
      typeof value === "symbol") throw new Error("MIG_OWNER_UNSERIALIZABLE_VALUE");
  return value;
}

export function decodeMigOwnerValue(value: unknown): any {
  if (Array.isArray(value)) return value.map(decodeMigOwnerValue);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (record.$mig_wire_type === "Undefined" && Object.keys(record).length === 1) return undefined;
    if (record.$mig_wire_type === "Set" && Object.keys(record).length === 2 && Array.isArray(record.value)) {
      return new Set(record.value.map(decodeMigOwnerValue));
    }
    if (record.$mig_wire_type === "Map" && Object.keys(record).length === 2 && Array.isArray(record.value)) {
      return new Map(record.value.map((entry: any) => {
        if (!Array.isArray(entry) || entry.length !== 2) throw new Error("MIG_OWNER_UNSAFE_OBJECT");
        return [decodeMigOwnerValue(entry[0]), decodeMigOwnerValue(entry[1])] as [unknown, unknown];
      }));
    }
    if (record.$mig_wire_type === "Object" && Object.keys(record).length === 2 && Array.isArray(record.value)) {
      const entries = record.value.map((entry: any) => {
        if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" ||
            ["__proto__", "constructor", "prototype"].includes(entry[0])) throw new Error("MIG_OWNER_UNSAFE_OBJECT");
        return [entry[0], decodeMigOwnerValue(entry[1])];
      });
      return Object.fromEntries(entries);
    }
    if (record.$mig_wire_type === "Date" && Object.keys(record).length === 2 &&
        typeof record.value === "string") {
      const date = new Date(record.value);
      if (!Number.isFinite(date.getTime()) || date.toISOString() !== record.value) {
        throw new Error("MIG_OWNER_INVALID_DATE");
      }
      return date;
    }
    if (Object.keys(record).some(key => ["__proto__", "constructor", "prototype"].includes(key))) {
      throw new Error("MIG_OWNER_UNSAFE_OBJECT");
    }
    return Object.fromEntries(Object.entries(record).map(([key, item]) =>
      [key, decodeMigOwnerValue(item)]));
  }
  return value;
}

export function canonicalMigOwnerJson(value: unknown): string {
  return JSON.stringify(value, (_key, item) =>
    item && typeof item === "object" && !Array.isArray(item)
      ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))
      : item);
}

export function migOwnerHash(value: unknown): string {
  return createHash("sha256").update(canonicalMigOwnerJson(value)).digest("hex");
}

export function signMigOwnerMessage(value: unknown, secret: string): string {
  if (secret.length < 32) throw new Error("MIG_OWNER_SIGNING_KEY_UNAVAILABLE");
  return createHmac("sha256", secret).update(canonicalMigOwnerJson(value)).digest("hex");
}

export function verifyMigOwnerMessage(value: unknown, signature: unknown, secret: string): boolean {
  if (typeof signature !== "string" || !/^[a-f0-9]{64}$/.test(signature) || secret.length < 32) return false;
  const expected = Buffer.from(signMigOwnerMessage(value, secret), "hex");
  const presented = Buffer.from(signature, "hex");
  return expected.length === presented.length && timingSafeEqual(expected, presented);
}

export function assertMigOwnerTenant(value: unknown, tenantId: string): void {
  if (Array.isArray(value)) { value.forEach(item => assertMigOwnerTenant(item, tenantId)); return; }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    if ((key === "tenantId" || key === "tenant_id") && item !== undefined &&
        item !== null && item !== tenantId) throw new Error("MIG_OWNER_TENANT_MISMATCH");
    assertMigOwnerTenant(item, tenantId);
  }
}

export function assertMigOwnerOperationScope(operation: MigOwnerOperation, args: unknown[], tenantId: string): void {
  if (operation === "enterprise.listOrganizations") {
    if (args.length) throw new Error("MIG_OWNER_REQUEST_INVALID");
    return;
  }
  // Tool evidence is not an authorization context. Its arbitrary source fields
  // retain their native meaning and are validated by the canonical tool owner.
  if (operation === "tool.execute") {
    const context = args[2] as { tenantId?: unknown } | undefined;
    if (context?.tenantId !== tenantId) throw new Error("MIG_OWNER_TENANT_MISMATCH");
    assertMigOwnerTenant(context, tenantId);
    return;
  }
  if (["tool.input.validate", "tool.output.validate", "tool.authorityAssertionInput", "envelope.validate"].includes(operation)) return;
  if (operation === "onboarding.evaluate" && args[1] !== tenantId) throw new Error("MIG_OWNER_TENANT_MISMATCH");
  assertMigOwnerTenant(args, tenantId);
}

export function assertMigOwnerRequest(value: unknown, now = Date.now()): asserts value is MigOwnerBridgeRequest {
  const r = value as MigOwnerBridgeRequest;
  if (!r || r.schema_version !== MIG_OWNER_BRIDGE_SCHEMA ||
      !MIG_OWNER_OPERATIONS.includes(r.operation) ||
      typeof r.tenant_id !== "string" || !r.tenant_id || r.tenant_id.length > 128 ||
      typeof r.nonce !== "string" || !/^[a-f0-9-]{36}$/.test(r.nonce) ||
      !Number.isSafeInteger(r.expires_at) || r.expires_at <= now ||
      r.expires_at > now + 5 * 60_000 || !Array.isArray(r.args) ||
      Object.keys(r).some(key => !["schema_version", "operation", "tenant_id", "nonce", "expires_at", "args"].includes(key))) {
    throw new Error("MIG_OWNER_REQUEST_INVALID");
  }
  assertMigOwnerOperationScope(r.operation, decodeMigOwnerValue(r.args), r.tenant_id);
}
