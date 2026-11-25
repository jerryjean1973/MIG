/** Read-only endpoint observations and canonical permission-editor projections. */
export interface MigSimpleTool {
  name: string;
  description?: string;
  capability_id?: string;
}

export interface MigSimplePermissions {
  candidate_id: string;
  principal_id: string;
  entitlement_id: string | null;
  allowed_intents: string[];
  assigned_roles: string[];
  intent_options: string[];
  role_options: { key: string; label: string }[];
  editable: boolean;
  blockers: string[];
}

export interface MigSimpleConnectionTest {
  endpoint: string;
  identity: string | null;
  protocol_version: string;
  handshake_status: "compatible";
  capabilities: string[];
  tools: MigSimpleTool[];
  supports_lineage: boolean;
  supports_outcomes: boolean;
  secure_credential_delivery: boolean;
  registered: false;
  authority_granted: false;
}
