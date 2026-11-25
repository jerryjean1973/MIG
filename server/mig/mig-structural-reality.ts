/** Server-owned incremental activity/reality projection. */
import { createHash, randomUUID } from "crypto";
import { appendStructuralHistory, getStructuralHistoryDb, type StructuralHistoryRecord } from "../../shared/persistence/structural-history-store";
import type { GraphDeltaV1, PrincipalActivityRealityV1 } from "../../shared/contracts/mig-structural-pdp-v1";
import type { CanonicalSignalV1 } from "../../shared/contracts/bripe-execution-v1";

export async function materializeMigActivityReality(input: {
  tenantId: string; principalId: string; credentialRef: string; intentId: string; toolName: string;
  operation: TrustedMigOperation; purpose: string; projectOrProcess: string; sessionId?: string;
  repository?: MigRealityRepository;
}): Promise<{ activity: PrincipalActivityRealityV1; delta: GraphDeltaV1 }> {
  const realityId = `mig_reality_${input.tenantId}_${input.principalId}`;
  return (input.repository ?? postgresMigRealityRepository).withLockedHistory(
    { tenantId: input.tenantId, principalId: input.principalId, realityId },
    async ({ head, recent, append }) => {
  const priorActivity = head?.payload as PrincipalActivityRealityV1 | undefined;
  const version = `rv_${randomUUID()}`;
  const resources = input.operation.resources;
  const nodes = [...new Set([input.principalId, input.toolName, ...resources])];
  if (nodes.length > 128) throw new Error("MIG_AFFECTED_SUBGRAPH_TOO_LARGE");
  const priorContext = recent.map(row => row.payload as PrincipalActivityRealityV1)
    .filter(value => value?.activity_id).map(value => ({ activity_id: value.activity_id, reality_version: value.reality_version, semantic_action: value.semantic_action, resource_refs: value.resource_refs }));
  const activity: PrincipalActivityRealityV1 = {
    schema_version: "mig.structural-pdp.v1", activity_id: `mig_activity_${randomUUID()}`, reality_id: realityId,
    reality_version: version, previous_reality_version: priorActivity?.reality_version ?? null,
    tenant_id: input.tenantId, principal_id: input.principalId, credential_ref: input.credentialRef,
    client_or_agent_id: input.principalId, intent_id: input.intentId, tool_name: input.toolName,
    semantic_action: input.operation.semantic_action, resource_refs: resources,
    destination: input.operation.destination, volume_or_range: input.operation.volume_or_range,
    operation_input_hash: input.operation.operation_input_hash,
    observed_at: new Date().toISOString(), observed_as_evidence: true,
    possible_outcomes: ["ALLOW", "ALLOW_WITH_CONTROL", "REQUIRE_APPROVAL", "BLOCK"],
    prior_activity_context: priorContext,
    business_context: { purpose: input.purpose, project_or_process: input.projectOrProcess },
  };
  const delta: GraphDeltaV1 = {
    schema_version: "mig.structural-pdp.v1", delta_id: `mig_delta_${activity.activity_id}`,
    base_reality_version: priorActivity?.reality_version ?? "0", affected_node_ids: nodes,
    added_edges: [{ from: input.principalId, to: input.toolName, relation: "proposes" }], removed_edges: [],
    affected_subgraph: { node_ids: nodes, edge_count: 1 },
  };
  await append({
    objectType: "evidence", objectId: realityId, ownerId: input.principalId, tenantId: input.tenantId,
    payload: activity as unknown as Record<string, unknown>, triggerReason: "mig_activity_observed",
    schemaVersion: "mig.pdp.v1", contextId: version, sessionId: input.sessionId,
    previousPayload: priorActivity ? priorActivity as unknown as Record<string, unknown> : null,
    deltaSummary: delta as unknown as Record<string, unknown>, isInitialRecord: !priorActivity,
    idempotencyKey: `${input.tenantId}:${activity.activity_id}`,
  });
  return { activity, delta };
    },
  );
}

type HistoryAppend = Parameters<typeof appendStructuralHistory>[0];
export interface MigRealityRepository {
  withLockedHistory<T>(
    key: { tenantId: string; principalId: string; realityId: string },
    work: (scope: { head?: StructuralHistoryRecord; recent: StructuralHistoryRecord[]; append: (input: HistoryAppend) => Promise<number | null> }) => Promise<T>,
  ): Promise<T>;
}

type TransactionalMigDb = {
  transaction<T>(fn: (tx: unknown) => Promise<T>): Promise<T>;
};

export function createPostgresMigRealityRepository(
  resolveConfiguredDb: () => unknown,
): MigRealityRepository {
  return {
  async withLockedHistory(key, work) {
    const configured = resolveConfiguredDb();
    if (!configured || typeof (configured as { transaction?: unknown }).transaction !== "function") {
      throw new Error("MIG_REALITY_TRANSACTION_UNAVAILABLE");
    }
    const transactional = configured as TransactionalMigDb;
    return transactional.transaction(async tx => {
      const { sql, and, desc, eq } = await import("drizzle-orm");
      const { structuralObjectHistory } = await import("@shared/schema");
      const db = tx as {
        execute(query: unknown): Promise<unknown>;
        select(): { from(table: unknown): { where(condition: unknown): { orderBy(...orders: unknown[]): { limit(limit: number): Promise<StructuralHistoryRecord[]> } } } };
      };
      await db.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`${key.tenantId}|${key.principalId}`}))`);
      const conditions = and(
        eq(structuralObjectHistory.tenantId, key.tenantId),
        eq(structuralObjectHistory.ownerId, key.principalId),
        eq(structuralObjectHistory.objectType, "evidence"),
        eq(structuralObjectHistory.objectId, key.realityId),
      );
      // The serial ID is authoritative for lock-serialized insertion order.
      // PostgreSQL NOW() is fixed at transaction start, so a transaction that
      // waited for this lock can have an earlier recordedAt than its predecessor.
      const headRows = await db.select().from(structuralObjectHistory).where(conditions)
        .orderBy(desc(structuralObjectHistory.id)).limit(1);
      const recent = await db.select().from(structuralObjectHistory).where(conditions)
        .orderBy(desc(structuralObjectHistory.id)).limit(16);
      return work({
        head: headRows[0], recent,
        append: value => appendStructuralHistory(value, tx as Parameters<typeof appendStructuralHistory>[1]),
      });
    });
  },
  };
};

export const postgresMigRealityRepository = createPostgresMigRealityRepository(getStructuralHistoryDb);

export interface TrustedMigOperation {
  semantic_action: string; resources: string[]; destination?: string; volume_or_range?: string;
  operation_input_hash: string; canonical_payload: Record<string, unknown>;
}

const RESOURCE_KEY = /(^|_)(resource|resource_id|object_id|record_id|entity_id|target_id|file_id|document_id|url|uri)(s)?$/i;
const DESTINATION_KEY = /(^|_)(destination|recipient|target|output_path|bucket)$/i;
const RANGE_KEY = /(^|_)(volume|range|limit|count|quantity|amount)$/i;
export function projectTrustedMigOperation(toolName: string, classification: string, payload: unknown): TrustedMigOperation {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("MIG_TOOL_INPUT_INVALID");
  const canonical_payload = JSON.parse(canonicalJson(payload)) as Record<string, unknown>;
  const resources: string[] = [], destinations: string[] = [], ranges: string[] = [];
  const walk = (value: unknown, key = ""): void => {
    if (Array.isArray(value)) return void value.forEach(item => walk(item, key));
    if (value && typeof value === "object") return void Object.entries(value as Record<string, unknown>).forEach(([k, v]) => walk(v, k));
    if (typeof value !== "string" && typeof value !== "number") return;
    const text = String(value);
    if (RESOURCE_KEY.test(key)) resources.push(text);
    if (DESTINATION_KEY.test(key)) destinations.push(text);
    if (RANGE_KEY.test(key)) ranges.push(text);
  };
  walk(canonical_payload);
  return { semantic_action: `${classification}:${toolName}`, resources: [...new Set(resources.length ? resources : [toolName])],
    destination: destinations[0], volume_or_range: ranges[0],
    operation_input_hash: createHash("sha256").update(canonicalJson(canonical_payload)).digest("hex"), canonical_payload };
}
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(record[k])}`).join(",")}}`;
}

export function buildMigOperationSignals(
  activity: PrincipalActivityRealityV1, delta: GraphDeltaV1, severity: number,
): CanonicalSignalV1[] {
  if (!Number.isFinite(severity) || severity < 0 || severity > 1) throw new Error("MIG_POLICY_SEVERITY_INVALID");
  return [
    { signal_id: `${activity.activity_id}:operation`, type: "mig_proposed_operation", entity: activity.principal_id,
      system: "mig", timestamp: activity.observed_at, value: { severity, semantic_action: activity.semantic_action, resources: activity.resource_refs },
      confidence: 1, source: "mig_server_policy", source_key: `mig:${activity.tool_name}:operation:v1`,
      evidence_id: activity.activity_id, signal_category: "principal_activity", dependency_group: activity.reality_id,
      region: null, jurisdiction: null, limitations: ["proposed_not_executed"], completeness: true },
    { signal_id: `${activity.activity_id}:delta`, type: "mig_graph_delta", entity: activity.reality_id,
      system: "mig", timestamp: activity.observed_at, value: { severity, delta_id: delta.delta_id, affected_nodes: delta.affected_node_ids.length },
      confidence: 1, source: "mig_server_policy", source_key: `mig:${activity.tool_name}:delta:v1`,
      evidence_id: delta.delta_id, signal_category: "structural_delta", dependency_group: activity.reality_id,
      region: null, jurisdiction: null, limitations: ["bounded_subgraph"], completeness: true },
  ];
}