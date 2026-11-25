/**
 * shared/bripe/structural-history-store.ts
 *
 * Unified Structural History Persistence Layer — canonical write path
 * ===================================================================
 *
 * The SINGLE low-level write path for appending records to
 * `structural_object_history`. All higher-level writers (e.g.
 * structural-history-writer.ts) MUST delegate their actual INSERT here.
 *
 * Contract:
 *   - `recorded_at` is server-assigned (DEFAULT NOW()) — never caller-supplied.
 *   - `payload` must be a non-null plain object before insert.
 *   - Dedup is keyed on `idempotency_key`: when the caller supplies the same
 *     key on retry, ON CONFLICT DO NOTHING fires (idempotent retry-safe).
 *     When `idempotencyKey` is omitted, the DB generates a UUID — every call
 *     succeeds independently (no false dedup between unrelated writes).
 *   - No UPDATE or DELETE path is exposed — append-only contract.
 *   - All structural columns (contextId, recordedBy, sessionId, previousPayload,
 *     deltaSummary, isInitialRecord) are accepted as optional fields so the
 *     rich writer can persist them at the column level — not buried in payload.
 *
 * Object types: evidence | signal | control | domain_score | metric |
 *               scoring_run | dependency | decision
 *
 * DB injection:
 *   Call configureStructuralHistoryDb(db) once at server startup.
 *   Pass db as the second argument to override per-call (useful in tests).
 */

import { z } from "zod";
import type { StructuralObjectType } from "../schema";
import { STRUCTURAL_OBJECT_TYPES } from "../schema";
import type { PersistedDiagnosisLineage } from "../protocol/shared/bripe/diagnosis-lineage";

// ── Input shape ───────────────────────────────────────────────────────────────

export const appendStructuralHistoryInputSchema = z.object({
  // ── Required identity fields ─────────────────────────────────────────────
  objectType:    z.enum(STRUCTURAL_OBJECT_TYPES),
  objectId:      z.string().min(1),
  ownerId:       z.string().min(1),
  /**
   * Tenant ID for row-level isolation. Required so prior-history lookups and
   * queryStructuralHistory calls that filter by tenantId work correctly for
   * non-default tenants. Defaults to DEFAULT_TENANT_ID for backward compat.
   */
  tenantId:      z.string().default("1001"),
  payload:       z.record(z.unknown()),
  triggerReason: z.string().min(1),
  schemaVersion: z.string().default("1.0"),

  // ── Optional structural lineage fields (populated by rich writer) ────────
  /** Scoping context key (e.g. `${tenantId}:${vendorId}`). */
  contextId:       z.string().nullable().optional(),
  /**
   * Module path that produced this record — canonical lineage anchor.
   * Defaults to "structural-history-store" for direct-store callers.
   */
  recordedBy:      z.string().optional(),
  /** Correlates all writes produced by a single scoring pipeline run. */
  sessionId:       z.string().nullable().optional(),
  /** Previous state snapshot. null for the initial record. */
  previousPayload: z.record(z.unknown()).nullable().optional(),
  /** Structured diff summary (which fields changed, direction, magnitude). */
  deltaSummary:    z.record(z.unknown()).nullable().optional(),
  /** True for the first record for a given objectType+objectId+tenantId. */
  isInitialRecord: z.boolean().optional(),
  /** Scoped derivation edges persisted with the native history record. */
  lineage: z.custom<PersistedDiagnosisLineage>().optional(),

  /**
   * Optional caller-supplied key for retry-safe idempotency.
   *
   * Supply the same key on every retry to guarantee exactly-once semantics.
   * If omitted, the DB generates a UUID so each call always inserts independently.
   *
   * Good keys: `${tenantId}:${objectType}:${objectId}:${runId}`
   */
  idempotencyKey: z.string().optional(),
});

export type AppendStructuralHistoryInput = z.infer<typeof appendStructuralHistoryInputSchema>;

// ── Query shape ───────────────────────────────────────────────────────────────

export interface QueryStructuralHistoryParams {
  objectType: StructuralObjectType;
  objectId:   string;
  /**
   * Required: tenant ID for row-level isolation.
   * Queries without a tenantId would return rows across all tenants for the
   * same objectId — a cross-tenant data disclosure risk.
   */
  tenantId:   string;
  ownerId?:   string;
  since?:     Date;
  /** Continue an ascending timeline after this immutable record position. */
  after?:     { recordedAt: Date; id: number };
  limit?:     number;
}

export interface StructuralHistoryRecord {
  id:              number;
  objectType:      string;
  objectId:        string;
  tenantId:        string;
  ownerId:         string;
  recordedAt:      Date;
  payload:         Record<string, unknown>;
  triggerReason:   string;
  schemaVersion:   string;
  idempotencyKey:  string;
  // Lineage fields — populated when written via the rich writer
  contextId?:       string | null;
  recordedBy?:      string;
  sessionId?:       string | null;
  previousPayload?: Record<string, unknown> | null;
  deltaSummary?:    Record<string, unknown> | null;
  isInitialRecord?: boolean;
  lineage?: PersistedDiagnosisLineage;
}

// ── DB injection ──────────────────────────────────────────────────────────────

type DrizzleDb = {
  insert:  (...args: unknown[]) => unknown;
  select:  (...args: unknown[]) => unknown;
};

let _db: DrizzleDb | null = null;

/**
 * Inject the drizzle db instance. Call once at server startup.
 * Also accepts null to reset (test isolation).
 */
export function configureStructuralHistoryDb(db: DrizzleDb | null): void {
  _db = db;
}

/** Retrieve the currently configured db (for use by higher-level writers). */
export function getStructuralHistoryDb(): DrizzleDb | null {
  return _db;
}

function resolveDb(override?: DrizzleDb): DrizzleDb {
  const db = override ?? _db;
  if (!db) {
    throw new Error(
      "[structural-history-store] No DB configured. " +
      "Call configureStructuralHistoryDb(db) at server startup, or pass db explicitly.",
    );
  }
  return db;
}

// ── appendStructuralHistory ───────────────────────────────────────────────────

/**
 * Append a structural history record (canonical write path).
 *
 * - recorded_at: server-assigned via DB DEFAULT NOW() — not caller-supplied.
 * - idempotencyKey: supply the same key on retry for exactly-once semantics;
 *   omit to allow independent inserts (DB generates a UUID, no false dedup).
 * - Duplicate idempotency key: silently ignored (ON CONFLICT DO NOTHING).
 * - All structural lineage columns are persisted at the column level when supplied
 *   (contextId, recordedBy, sessionId, previousPayload, deltaSummary, isInitialRecord).
 *
 * Returns the new row id, or null if the key was a duplicate.
 */
export async function appendStructuralHistory(
  input: AppendStructuralHistoryInput,
  dbOverride?: DrizzleDb,
): Promise<number | null> {
  // 1. Validate input envelope
  const parsed = appendStructuralHistoryInputSchema.safeParse(input);
  if (!parsed.success) {
    throw new Error(
      `[structural-history-store] Invalid input: ${parsed.error.message}`,
    );
  }

  // 2. Validate payload is a non-null plain object
  if (
    typeof parsed.data.payload !== "object" ||
    parsed.data.payload === null ||
    Array.isArray(parsed.data.payload)
  ) {
    throw new Error("[structural-history-store] payload must be a non-null object");
  }

  const db = resolveDb(dbOverride);

  try {
    const { structuralObjectHistory } = await import("../schema");

    // Build the values row.
    // - recordedAt is intentionally omitted (DB DEFAULT NOW()).
    // - idempotencyKey: if supplied use it; when omitted, DB DEFAULT gen_random_uuid()
    //   generates a unique UUID so this insert never false-conflicts.
    // - Structural lineage columns are only set when the caller provides them.
    const persistedPayload = parsed.data.lineage
      ? { ...parsed.data.payload, __diagnosis_lineage: parsed.data.lineage }
      : parsed.data.payload;
    const values: Record<string, unknown> = {
      tenantId:      parsed.data.tenantId,
      objectType:    parsed.data.objectType,
      objectId:      parsed.data.objectId,
      ownerId:       parsed.data.ownerId,
      payload:       persistedPayload,
      recordedBy:    parsed.data.recordedBy ?? "structural-history-store",
      triggerReason: parsed.data.triggerReason,
      schemaVersion: parsed.data.schemaVersion,
    };

    // Optional structural lineage columns — write at the column level
    if (parsed.data.contextId     !== undefined) values.contextId       = parsed.data.contextId;
    if (parsed.data.sessionId     !== undefined) values.sessionId       = parsed.data.sessionId;
    if (parsed.data.previousPayload !== undefined) values.previousPayload = parsed.data.previousPayload;
    if (parsed.data.deltaSummary  !== undefined) values.deltaSummary    = parsed.data.deltaSummary;
    if (parsed.data.isInitialRecord !== undefined) values.isInitialRecord = parsed.data.isInitialRecord;
    if (parsed.data.idempotencyKey !== undefined) values.idempotencyKey = parsed.data.idempotencyKey;

    // 3. ON CONFLICT DO NOTHING on idempotency_key.
    //    When idempotencyKey was omitted the DB supplies a UUID so no conflict fires.
    const rows = await (db as any)
      .insert(structuralObjectHistory)
      .values(values)
      .onConflictDoNothing()
      .returning({ id: structuralObjectHistory.id });

    if (!rows || rows.length === 0) {
      return null; // duplicate idempotencyKey — suppress silently
    }

    return rows[0].id as number;
  } catch (err) {
    throw new Error(
      `[structural-history-store] Insert failed: ${(err as Error).message}`,
    );
  }
}

// ── queryStructuralHistory ────────────────────────────────────────────────────

/**
 * Read structural history records in chronological ascending order.
 *
 * Default limit: 100. tenantId is required for row-level isolation.
 */
export async function queryStructuralHistory(
  params: QueryStructuralHistoryParams,
  dbOverride?: DrizzleDb,
): Promise<StructuralHistoryRecord[]> {
  const db = resolveDb(dbOverride);

  try {
    const { structuralObjectHistory } = await import("../schema");
    const { eq, and, gte, gt, or, asc } = await import("drizzle-orm");

    const conditions: unknown[] = [
      eq(structuralObjectHistory.objectType, params.objectType),
      eq(structuralObjectHistory.objectId,   params.objectId),
      // tenantId is always included to enforce row-level isolation.
      eq(structuralObjectHistory.tenantId,   params.tenantId),
    ];

    if (params.ownerId) {
      conditions.push(eq(structuralObjectHistory.ownerId, params.ownerId));
    }
    if (params.since) {
      conditions.push(gte(structuralObjectHistory.recordedAt, params.since));
    }
    if (params.after) {
      // recorded_at is not unique. The id tie-breaker prevents a row with the
      // same server timestamp from being skipped between history pages.
      conditions.push(or(
        gt(structuralObjectHistory.recordedAt, params.after.recordedAt),
        and(
          eq(structuralObjectHistory.recordedAt, params.after.recordedAt),
          gt(structuralObjectHistory.id, params.after.id),
        ),
      )!);
    }

    const rows = await (db as any)
      .select()
      .from(structuralObjectHistory)
      .where(and(...conditions))
      // The cursor predicate uses (recorded_at, id), so ordering must use the
      // identical total order. Without the id tie-breaker equal-timestamp rows
      // can move between pages and be skipped or repeated.
      .orderBy(
        asc(structuralObjectHistory.recordedAt),
        asc(structuralObjectHistory.id),
      )
      .limit(params.limit ?? 100);

    return ((rows ?? []) as Array<Record<string, unknown>>).map((row) => ({
      id:              row.id as number,
      objectType:      row.objectType as string,
      objectId:        row.objectId as string,
      tenantId:        (row.tenantId ?? "1001") as string,
      ownerId:         (row.ownerId ?? row.tenantId ?? "") as string,
      recordedAt:      row.recordedAt as Date,
      payload:         (() => {
        const raw = (row.payload ?? {}) as Record<string, unknown>;
        const { __diagnosis_lineage: _lineage, ...clean } = raw;
        return clean;
      })(),
      triggerReason:   (row.triggerReason ?? row.recordedBy ?? "") as string,
      schemaVersion:   (row.schemaVersion ?? "1.0") as string,
      idempotencyKey:  (row.idempotencyKey ?? "") as string,
      contextId:       row.contextId as string | null | undefined,
      recordedBy:      row.recordedBy as string | undefined,
      sessionId:       row.sessionId as string | null | undefined,
      previousPayload: row.previousPayload as Record<string, unknown> | null | undefined,
      deltaSummary:    row.deltaSummary as Record<string, unknown> | null | undefined,
      isInitialRecord: row.isInitialRecord as boolean | undefined,
      lineage: ((row.payload as Record<string, unknown> | undefined)?.__diagnosis_lineage
        ?? row.lineage) as PersistedDiagnosisLineage | undefined,
    }));
  } catch (err) {
    throw new Error(
      `[structural-history-store] Query failed: ${(err as Error).message}`,
    );
  }
}

export interface QueryStructuralHistoryByLineageParams {
  tenantId: string;
  realityId?: string | null;
  realityVersion?: string | null;
  dependencyIds?: string[];
  limit?: number;
}

/**
 * Reads persisted derivation edges across native structural history records.
 * Tenant isolation is enforced in SQL; exact reality identity is then checked
 * against the deserialized lineage envelope.
 */
export async function queryStructuralHistoryByLineage(
  params: QueryStructuralHistoryByLineageParams,
  dbOverride?: DrizzleDb,
): Promise<StructuralHistoryRecord[]> {
  const db = resolveDb(dbOverride);
  try {
    const { structuralObjectHistory } = await import("../schema");
    const { eq, asc, and, or, sql } = await import("drizzle-orm");
    const conditions = [eq(structuralObjectHistory.tenantId, params.tenantId)];
    if (params.realityId !== undefined) {
      conditions.push(sql`${structuralObjectHistory.payload} -> '__diagnosis_lineage' -> 'scope' ->> 'reality_id' = ${params.realityId}`);
    }
    if (params.realityVersion !== undefined) {
      conditions.push(sql`${structuralObjectHistory.payload} -> '__diagnosis_lineage' -> 'scope' ->> 'reality_version' = ${params.realityVersion}`);
    }
    if (params.dependencyIds?.length) {
      const dependencyPredicates = [...new Set(params.dependencyIds)].map(id =>
        sql`${structuralObjectHistory.payload} -> '__diagnosis_lineage' -> 'edges' @> ${JSON.stringify([{
          to: { kind: "evidence", id },
        }])}::jsonb`,
      );
      conditions.push(or(...dependencyPredicates)!);
    }
    const orderedQuery = (db as any)
      .select()
      .from(structuralObjectHistory)
      .where(and(...conditions))
      .orderBy(asc(structuralObjectHistory.recordedAt));
    const rows = params.limit === undefined
      ? await orderedQuery
      : await orderedQuery.limit(params.limit);

    return ((rows ?? []) as Array<Record<string, unknown>>)
      .map(row => {
        const raw = (row.payload ?? {}) as Record<string, unknown>;
        const lineage = (raw.__diagnosis_lineage ?? row.lineage) as PersistedDiagnosisLineage | undefined;
        const { __diagnosis_lineage: _ignored, ...payload } = raw;
        return {
          id: row.id as number,
          objectType: row.objectType as string,
          objectId: row.objectId as string,
          tenantId: (row.tenantId ?? "1001") as string,
          ownerId: (row.ownerId ?? row.tenantId ?? "") as string,
          recordedAt: row.recordedAt as Date,
          payload,
          triggerReason: (row.triggerReason ?? row.recordedBy ?? "") as string,
          schemaVersion: (row.schemaVersion ?? "1.0") as string,
          idempotencyKey: (row.idempotencyKey ?? "") as string,
          contextId: row.contextId as string | null | undefined,
          recordedBy: row.recordedBy as string | undefined,
          sessionId: row.sessionId as string | null | undefined,
          previousPayload: row.previousPayload as Record<string, unknown> | null | undefined,
          deltaSummary: row.deltaSummary as Record<string, unknown> | null | undefined,
          isInitialRecord: row.isInitialRecord as boolean | undefined,
          lineage,
        } satisfies StructuralHistoryRecord;
      })
      .filter(record => {
        if (!record.lineage) return false;
        return (params.realityId === undefined || record.lineage.scope.reality_id === params.realityId)
          && (params.realityVersion === undefined || record.lineage.scope.reality_version === params.realityVersion);
      });
  } catch (err) {
    throw new Error(`[structural-history-store] Lineage query failed: ${(err as Error).message}`);
  }
}
