-- Apply on the CANONICAL OWNER, not the standalone MIG database.
CREATE TABLE IF NOT EXISTS mig_owner_bridge_nonces (
  tenant_id text NOT NULL,
  nonce text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, nonce)
);
CREATE INDEX IF NOT EXISTS mig_owner_bridge_nonce_expiry ON mig_owner_bridge_nonces (expires_at);
-- The owner may periodically delete expired rows; expired requests are rejected
-- before nonce admission. Never replace this store with an in-memory Set.
