import { and, desc, eq, getTableColumns, sql } from "drizzle-orm";

import { mcpToolInvocations } from "@shared/schema";

import { db } from "../db";

export const MAX_SAVED_OUTPUT_SECTION_BYTES = 64 * 1024;

export interface McpOutputManifestQueryOptions {
  tenantId: string;
  limit?: number;
  toolName?: string;
  status?: string;
  invocationId?: number;
  includePayloads?: boolean;
  outputPath?: string[];
  inspectOnly?: boolean;
  inspectionOffset?: number;
}

export function buildMcpOutputManifestQuery(opts: McpOutputManifestQueryOptions) {
  if (!opts.tenantId?.trim()) throw new Error("Manifest retrieval requires an authenticated tenant.");
  if ((opts.includePayloads || opts.inspectOnly) && !opts.invocationId) {
    throw new Error("Saved output retrieval or inspection requires invocation_id. List the history index first.");
  }
  if (opts.inspectOnly && opts.includePayloads) {
    throw new Error("Use either inspect_only:true or include_payloads:true, not both.");
  }
  if (opts.outputPath && !opts.includePayloads && !opts.inspectOnly) {
    throw new Error("output_path requires include_payloads:true or inspect_only:true and invocation_id.");
  }
  if (opts.inspectionOffset && !opts.inspectOnly) {
    throw new Error("inspection_offset requires inspect_only:true.");
  }

  const includePayloads = opts.includePayloads === true;
  const includeInput = includePayloads && !opts.outputPath;
  const selectedOutput = opts.outputPath
    ? sql<unknown>`${mcpToolInvocations.fullOutputJson} #> ${sql.param(opts.outputPath)}::text[]`
    : mcpToolInvocations.fullOutputJson;
  const storedPayloadBytes = includePayloads
    ? sql<number>`coalesce(pg_column_size(${selectedOutput}), 0) + ${
      includeInput ? sql`coalesce(pg_column_size(${mcpToolInvocations.inputPayload}), 0)` : sql`0`
    }`
    : sql<null>`null`;
  // Reject obviously oversized stored nodes before serializing their JSON.
  // Expanding a whole saved graph merely to reject it can itself time out.
  const payloadBytes = includePayloads
    ? sql<number | null>`case when (${storedPayloadBytes}) > ${MAX_SAVED_OUTPUT_SECTION_BYTES} then null else
      coalesce(octet_length((${selectedOutput})::text), 0) + ${
      includeInput ? sql`coalesce(octet_length(${mcpToolInvocations.inputPayload}::text), 0)` : sql`0`
    } end`
    : sql<null>`null`;
  const tooLarge = sql<boolean>`case when (${storedPayloadBytes}) > ${MAX_SAVED_OUTPUT_SECTION_BYTES}
    then true else coalesce((${payloadBytes}) > ${MAX_SAVED_OUTPUT_SECTION_BYTES}, false) end`;
  const offset = opts.inspectionOffset ?? 0;
  // Materialize the selected node once, not once per descriptor property.
  // Keys are paged; large values never leave PostgreSQL during inspection.
  const inspection = sql<unknown>`(
    with inspected as materialized (select ${selectedOutput} as value),
    inspected_keys as materialized (
      select key from inspected
      cross join lateral jsonb_object_keys(
        case when jsonb_typeof(value) = 'object' then value else '{}'::jsonb end
      ) as key
      offset ${offset} limit 41
    )
    select jsonb_build_object(
      'pathExists', value is not null,
      'jsonType', jsonb_typeof(value),
      'objectKeys', (
        select coalesce(jsonb_agg(key), '[]'::jsonb)
        from (select key from inspected_keys limit 40) page
      ),
      'nextKeyOffset', case when (select count(*) from inspected_keys) > 40 then ${offset + 40} else null end,
      'arrayLength', case when jsonb_typeof(value) = 'array' then jsonb_array_length(value) else null end
    ) from inspected
  )`;
  const conditions = [eq(mcpToolInvocations.tenantId, opts.tenantId)];
  if (opts.toolName) conditions.push(eq(mcpToolInvocations.toolName, opts.toolName));
  if (opts.status) conditions.push(eq(mcpToolInvocations.status, opts.status));
  if (opts.invocationId) conditions.push(eq(mcpToolInvocations.id, opts.invocationId));

  return db.select({
    ...getTableColumns(mcpToolInvocations),
    // Do not hydrate hundreds of MB merely to list saved executions.
    fullOutputJson: !includePayloads ? sql<unknown>`null`
      : sql<unknown>`case when ${tooLarge} then null else ${selectedOutput} end`,
    inputPayload: includeInput
      ? sql<unknown>`case when ${tooLarge} then null else ${mcpToolInvocations.inputPayload} end`
      : sql<unknown>`null`,
    payloadsIncluded: sql<boolean>`${includePayloads}::boolean and not ${tooLarge}`,
    inputPayloadIncluded: sql<boolean>`${includeInput}::boolean and not ${tooLarge}`,
    payloadTooLarge: tooLarge,
    selectedPayloadBytes: payloadBytes,
    selectedPayloadStoredBytes: storedPayloadBytes,
    outputInspection: sql<unknown>`case when ${opts.inspectOnly === true}::boolean or ${tooLarge} then ${inspection} else null end`,
    outputPath: sql<unknown>`${JSON.stringify(opts.outputPath ?? [])}::jsonb`,
    fullOutputStoredBytes: sql<number | null>`pg_column_size(${mcpToolInvocations.fullOutputJson})`,
    inputPayloadStoredBytes: sql<number | null>`pg_column_size(${mcpToolInvocations.inputPayload})`,
  })
    .from(mcpToolInvocations)
    .where(and(...conditions))
    .orderBy(desc(mcpToolInvocations.createdAt), desc(mcpToolInvocations.id))
    .limit(opts.invocationId ? 1 : Math.min(500, Math.max(1, opts.limit ?? 50)));
}
