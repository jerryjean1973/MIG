/** Public enrollment contract. Private signing keys never cross this boundary. */
export interface MigHostOperatorSpec {
  principal_id: string;
  client_id: string;
  display_name: string;
  project: string;
  environment: "DEV";
  capability_ids: string[];
  intent_id: string;
  domain_id: string;
  public_key_pem: string;
}

export interface MigHostOperatorRequestView {
  request_id: string;
  state: string;
  principal_id: string;
  client_id: string;
  display_name: string;
  project: string;
  environment: "DEV";
  resource_scope: string;
  capability_ids: string[];
  intent_id: string;
  domain_id: string;
  public_key_fingerprint: string;
  key_ownership_verified: boolean;
  approval_state: "pending" | "approved" | "rejected";
  execution_contract_available: boolean;
  blockers: string[];
  registered: boolean;
  smartdev_enrollment: "not_verified_by_mig";
  authorized_execution: "not_verified";
}

export const MIG_HOST_OPERATOR_VALIDATION_FIELDS = [
  "identity_auth", "current_intent", "governed_invocation", "mig_root_lineage",
] as const;
