/**
 * server/mcp/mcp-adam-audit-migration.ts
 *
 * Best-effort startup migration that adds the ADAM gate outcome columns to
 * mcp_tool_invocations if they are not already present. Uses IF NOT EXISTS so
 * it is idempotent on repeated restarts and safe for existing deployments.
 */
import { pool } from "../db";

export async function runAdamAuditColumnsMigration(): Promise<void> {
  await pool.query(`
      ALTER TABLE mcp_tool_invocations
        ADD COLUMN IF NOT EXISTS adam_outcome       VARCHAR(30),
        ADD COLUMN IF NOT EXISTS adam_proof_manifest_id TEXT,
        ADD COLUMN IF NOT EXISTS adam_downgrade_reason  TEXT,
        ADD COLUMN IF NOT EXISTS delegation_jti TEXT,
        ADD COLUMN IF NOT EXISTS authorization_policy_version TEXT,
        ADD COLUMN IF NOT EXISTS mig_client_id VARCHAR,
        ADD COLUMN IF NOT EXISTS mig_principal_id VARCHAR,
        ADD COLUMN IF NOT EXISTS journey_id VARCHAR,
        ADD COLUMN IF NOT EXISTS parent_call_id VARCHAR,
        ADD COLUMN IF NOT EXISTS origin_user_id VARCHAR,
        ADD COLUMN IF NOT EXISTS origin_agent_id VARCHAR,
        ADD COLUMN IF NOT EXISTS root_intent_id VARCHAR,
        ADD COLUMN IF NOT EXISTS current_intent_id VARCHAR,
        ADD COLUMN IF NOT EXISTS compounded_intent_ids JSONB,
        ADD COLUMN IF NOT EXISTS graph_call_ids JSONB,
        ADD COLUMN IF NOT EXISTS resource_ref TEXT,
        ADD COLUMN IF NOT EXISTS resource_version TEXT,
        ADD COLUMN IF NOT EXISTS outcome VARCHAR(16);

      ALTER TABLE mig_audit_log
        ADD COLUMN IF NOT EXISTS authenticated_principal_id VARCHAR,
        ADD COLUMN IF NOT EXISTS journey_id VARCHAR,
        ADD COLUMN IF NOT EXISTS parent_call_id VARCHAR,
        ADD COLUMN IF NOT EXISTS origin_user_id VARCHAR,
        ADD COLUMN IF NOT EXISTS origin_agent_id VARCHAR,
        ADD COLUMN IF NOT EXISTS root_intent_id VARCHAR,
        ADD COLUMN IF NOT EXISTS compounded_intent_ids JSONB,
        ADD COLUMN IF NOT EXISTS graph_call_ids JSONB,
        ADD COLUMN IF NOT EXISTS resource_ref TEXT,
        ADD COLUMN IF NOT EXISTS outcome VARCHAR(16);

      CREATE OR REPLACE FUNCTION reject_gateway_audit_mutation()
      RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'gateway audit records are append-only';
      END;
      $$ LANGUAGE plpgsql;

      DROP TRIGGER IF EXISTS mcp_tool_invocations_append_only ON mcp_tool_invocations;
      CREATE TRIGGER mcp_tool_invocations_append_only
        BEFORE UPDATE OR DELETE ON mcp_tool_invocations
        FOR EACH ROW EXECUTE FUNCTION reject_gateway_audit_mutation();

      DROP TRIGGER IF EXISTS mig_audit_log_append_only ON mig_audit_log;
      CREATE TRIGGER mig_audit_log_append_only
        BEFORE UPDATE OR DELETE ON mig_audit_log
        FOR EACH ROW EXECUTE FUNCTION reject_gateway_audit_mutation()
    `);
}
