-- MIG-owned authentication state only. No existing identities or grants are replaced.
CREATE TABLE IF NOT EXISTS mig_standalone_login_states (
  state_hash text PRIMARY KEY,
  code_verifier text NOT NULL,
  nonce text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS mig_standalone_login_expiry ON mig_standalone_login_states (expires_at);
CREATE TABLE IF NOT EXISTS mig_standalone_sessions (
  token_hash text PRIMARY KEY,
  tenant_id text NOT NULL,
  subject_id text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS mig_standalone_session_expiry ON mig_standalone_sessions (expires_at);
