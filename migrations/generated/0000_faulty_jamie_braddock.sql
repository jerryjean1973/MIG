CREATE TABLE "entra_tenant_mappings" (
	"id" serial PRIMARY KEY NOT NULL,
	"entra_tenant_id" varchar(128) NOT NULL,
	"bcentrisk_tenant_id" varchar(128) NOT NULL,
	"display_label" text,
	"created_by" varchar,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"updated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "entra_tenant_mappings_entra_tenant_id_unique" UNIQUE("entra_tenant_id")
);
--> statement-breakpoint
CREATE TABLE "mcp_api_keys" (
	"id" serial PRIMARY KEY NOT NULL,
	"tenant_id" varchar NOT NULL,
	"display_name" text NOT NULL,
	"key_hash" text NOT NULL,
	"key_prefix" varchar(12) NOT NULL,
	"classification" varchar(16) DEFAULT 'read_only' NOT NULL,
	"status" varchar(24) DEFAULT 'active' NOT NULL,
	"allowed_tools" text[],
	"allowed_intents" text[],
	"principal_id" varchar,
	"mig_agent_id" varchar,
	"allowed_domains" text[],
	"semantic_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"effective_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"preset" varchar(32),
	"resource_constraints" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"environment_constraints" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"network_constraints" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"review_required" boolean DEFAULT false NOT NULL,
	"review_state" varchar(24) DEFAULT 'approved' NOT NULL,
	"reviewed_at" timestamp,
	"reviewed_by" varchar,
	"last_used_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"revoked_at" timestamp,
	"expires_at" timestamp,
	"rotated_from_id" integer,
	"rotated_to_id" integer
);
--> statement-breakpoint
CREATE TABLE "mcp_capability_contracts" (
	"id" serial PRIMARY KEY NOT NULL,
	"contract_id" varchar NOT NULL,
	"contract_version" integer DEFAULT 1 NOT NULL,
	"tenant_id" varchar NOT NULL,
	"capability_id" varchar NOT NULL,
	"client_id" varchar NOT NULL,
	"negotiation_id" varchar NOT NULL,
	"server_identity" varchar(128) DEFAULT 'bripe-mcp' NOT NULL,
	"supersedes_contract_id" varchar,
	"status" varchar(32) DEFAULT 'draft' NOT NULL,
	"valid_from" timestamp,
	"valid_until" timestamp,
	"accepted_by_client" timestamp,
	"accepted_by_server" timestamp,
	"contract_json" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"hash" varchar(128) DEFAULT '' NOT NULL,
	"lineage_json" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"updated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mcp_capability_contracts_contract_id_unique" UNIQUE("contract_id")
);
--> statement-breakpoint
CREATE TABLE "mcp_contract_auth_relationships" (
	"id" serial PRIMARY KEY NOT NULL,
	"relationship_id" varchar NOT NULL,
	"contract_id" varchar NOT NULL,
	"contract_version" integer NOT NULL,
	"tenant_id" varchar NOT NULL,
	"capability_id" varchar NOT NULL,
	"client_id" varchar NOT NULL,
	"issued_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"valid_until" timestamp,
	"mig_attestation" text NOT NULL,
	"attestation_fingerprint" varchar(128) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"hash" varchar(128) DEFAULT '' NOT NULL,
	"lineage_json" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mcp_contract_auth_relationships_relationship_id_unique" UNIQUE("relationship_id")
);
--> statement-breakpoint
CREATE TABLE "mcp_contract_invocation_references" (
	"id" serial PRIMARY KEY NOT NULL,
	"invocation_ref_id" varchar NOT NULL,
	"contract_id" varchar NOT NULL,
	"contract_version" integer NOT NULL,
	"tenant_id" varchar NOT NULL,
	"capability_id" varchar NOT NULL,
	"client_id" varchar NOT NULL,
	"authorization_relationship_id" varchar NOT NULL,
	"tool_name" varchar NOT NULL,
	"nonce" varchar(256) NOT NULL,
	"gate_result" varchar(32) DEFAULT 'pass' NOT NULL,
	"failure_code" varchar(64),
	"hash" varchar(128) DEFAULT '' NOT NULL,
	"lineage_json" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mcp_contract_invocation_references_invocation_ref_id_unique" UNIQUE("invocation_ref_id")
);
--> statement-breakpoint
CREATE TABLE "mcp_key_audit_log" (
	"id" serial PRIMARY KEY NOT NULL,
	"tenant_id" varchar NOT NULL,
	"api_key_id" integer NOT NULL,
	"action" varchar(24) NOT NULL,
	"related_key_id" integer,
	"actor_user_id" varchar,
	"detail" text,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mcp_tool_invocations" (
	"id" serial PRIMARY KEY NOT NULL,
	"request_id" varchar NOT NULL,
	"tool_name" text NOT NULL,
	"tool_classification" varchar(16) NOT NULL,
	"tenant_id" varchar NOT NULL,
	"api_key_id" integer,
	"capability_id" text,
	"domain_id" text,
	"package_id" text,
	"canonical_service" text NOT NULL,
	"input_hash" text NOT NULL,
	"output_hash" text,
	"manifest_id" text,
	"decision_id" text,
	"delegation_jti" text,
	"authorization_policy_version" text,
	"mig_client_id" varchar,
	"mig_principal_id" varchar,
	"journey_id" varchar,
	"parent_call_id" varchar,
	"origin_user_id" varchar,
	"origin_agent_id" varchar,
	"root_intent_id" varchar,
	"current_intent_id" varchar,
	"compounded_intent_ids" jsonb,
	"graph_call_ids" jsonb,
	"resource_ref" text,
	"resource_version" text,
	"outcome" varchar(16),
	"status" varchar(16) NOT NULL,
	"error_code" text,
	"duration_ms" integer,
	"ttb_days" integer,
	"ttf_days" integer,
	"propagation_score" real,
	"full_output_json" jsonb,
	"input_payload" jsonb,
	"adam_outcome" varchar(30),
	"adam_proof_manifest_id" text,
	"adam_downgrade_reason" text,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mig_audit_log" (
	"id" serial PRIMARY KEY NOT NULL,
	"event_id" varchar NOT NULL,
	"event_type" varchar(32) NOT NULL,
	"decision" varchar(16) NOT NULL,
	"ticket_jti" varchar,
	"manifest_id" varchar,
	"agent_id" varchar,
	"tenant_id" varchar,
	"session_id" varchar,
	"intent_id" varchar,
	"risk_zone" varchar(16),
	"tool_name" varchar,
	"capability_id" varchar,
	"policy_decision" text NOT NULL,
	"transition_proof_id" varchar,
	"input_hash" text,
	"output_hash" text,
	"reason" text,
	"authenticated_principal_id" varchar,
	"journey_id" varchar,
	"parent_call_id" varchar,
	"origin_user_id" varchar,
	"origin_agent_id" varchar,
	"root_intent_id" varchar,
	"compounded_intent_ids" jsonb,
	"graph_call_ids" jsonb,
	"resource_ref" text,
	"outcome" varchar(16),
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_audit_log_event_id_unique" UNIQUE("event_id")
);
--> statement-breakpoint
CREATE TABLE "mig_authority_snapshots" (
	"id" serial PRIMARY KEY NOT NULL,
	"snapshot_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"provider" varchar(32) NOT NULL,
	"authority_ref" varchar NOT NULL,
	"provider_tenant_ref" varchar,
	"provider_subject_ref" varchar,
	"principal_id" varchar NOT NULL,
	"agent_id" varchar,
	"target_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"capability_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"domain_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"resource_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"assigned_roles" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"source_evidence" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"risk_zone_ceiling" varchar(16) NOT NULL,
	"observed_at" timestamp NOT NULL,
	"expires_at" timestamp NOT NULL,
	"sync_state" varchar(24) NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_authority_snapshots_snapshot_id_unique" UNIQUE("snapshot_id")
);
--> statement-breakpoint
CREATE TABLE "mig_authorization_manifests" (
	"id" serial PRIMARY KEY NOT NULL,
	"authorization_manifest_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"actor_principal_id" varchar,
	"client_principal_id" varchar,
	"executor_principal_id" varchar,
	"credential_ref" varchar,
	"intent_id" varchar,
	"capability_id" varchar,
	"semantic_action" varchar,
	"domain_id" varchar,
	"resource_ref" varchar,
	"resource_version" varchar,
	"policy_version" varchar NOT NULL,
	"decision" varchar(16) NOT NULL,
	"reason" varchar NOT NULL,
	"effective_permissions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"sod_result" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"request_correlation_id" varchar,
	"delegation_ref" varchar,
	"authority_provider" varchar(32),
	"authority_ref" varchar,
	"authority_snapshot_id" varchar,
	"authority_evidence" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"authority_observed_at" timestamp,
	"authority_expires_at" timestamp,
	"effective_risk_zone_ceiling" varchar(16),
	"before_hash" text,
	"after_hash" text,
	"manifest_hash" text NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_authorization_manifests_authorization_manifest_id_unique" UNIQUE("authorization_manifest_id")
);
--> statement-breakpoint
CREATE TABLE "mig_capability_manifests" (
	"id" serial PRIMARY KEY NOT NULL,
	"manifest_id" varchar NOT NULL,
	"ticket_jti" varchar NOT NULL,
	"agent_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"session_id" varchar NOT NULL,
	"intent_id" varchar NOT NULL,
	"risk_zone" varchar(16) NOT NULL,
	"allowed_capabilities" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"suppressed_capabilities" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_mcp_tools" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"denied_mcp_tools" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"manifest_hash" varchar NOT NULL,
	"expires_at" timestamp NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"revoked_reason" text,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_capability_manifests_manifest_id_unique" UNIQUE("manifest_id")
);
--> statement-breakpoint
CREATE TABLE "mig_clients" (
	"id" serial PRIMARY KEY NOT NULL,
	"component_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"principal_id" varchar NOT NULL,
	"client_class" varchar(8) NOT NULL,
	"origin_user_id" varchar,
	"credential_hash" text NOT NULL,
	"credential_prefix" varchar(16) NOT NULL,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"revoked_at" timestamp,
	CONSTRAINT "mig_clients_credential_hash_unique" UNIQUE("credential_hash")
);
--> statement-breakpoint
CREATE TABLE "mig_credential_bindings" (
	"id" serial PRIMARY KEY NOT NULL,
	"credential_ref" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"principal_id" varchar NOT NULL,
	"credential_type" varchar(24) NOT NULL,
	"provider_kind" varchar(32),
	"endpoint_ref" varchar,
	"mcp_server_ref" varchar,
	"mcp_tool_name" varchar,
	"mcp_capability_id" varchar,
	"mcp_scope" varchar,
	"mcp_resource_ref" varchar,
	"mcp_intent_id" varchar,
	"mcp_ticket" text,
	"lineage_id" varchar,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"capability_ceiling" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_intents" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_domains" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_mcp_targets" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_capabilities" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"resource_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"risk_zone_ceiling" varchar(16),
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"revoked_at" timestamp,
	CONSTRAINT "mig_credential_bindings_credential_ref_unique" UNIQUE("credential_ref")
);
--> statement-breakpoint
CREATE TABLE "mig_discovery_events" (
	"id" serial PRIMARY KEY NOT NULL,
	"event_id" varchar NOT NULL,
	"agent_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"session_id" varchar,
	"request_kind" varchar(16) NOT NULL,
	"tool_name" varchar,
	"capability_id" varchar,
	"domain_hints" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"input_shape_keys" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"was_denied" boolean DEFAULT false NOT NULL,
	"denial_reason" text,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_discovery_events_event_id_unique" UNIQUE("event_id")
);
--> statement-breakpoint
CREATE TABLE "mig_draft_intent_profiles" (
	"id" serial PRIMARY KEY NOT NULL,
	"draft_id" varchar NOT NULL,
	"agent_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"proposed_name" text NOT NULL,
	"proposed_description" text NOT NULL,
	"proposed_allowed_tool_names" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"proposed_capability_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"proposed_domain_scope" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"proposed_risk_zone" varchar(16) DEFAULT 'low' NOT NULL,
	"observed_event_count" integer DEFAULT 0 NOT NULL,
	"confidence" integer DEFAULT 0 NOT NULL,
	"policy_findings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"evidence_summary" text DEFAULT '' NOT NULL,
	"status" varchar(16) DEFAULT 'pending' NOT NULL,
	"resulting_intent_id" varchar,
	"reviewed_by" varchar,
	"review_notes" text,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"updated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"reviewed_at" timestamp,
	CONSTRAINT "mig_draft_intent_profiles_draft_id_unique" UNIQUE("draft_id")
);
--> statement-breakpoint
CREATE TABLE "mig_drift_events" (
	"id" serial PRIMARY KEY NOT NULL,
	"event_id" varchar NOT NULL,
	"agent_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"drift_type" varchar(32) NOT NULL,
	"tool_name" varchar,
	"detail" text NOT NULL,
	"severity" varchar(16) DEFAULT 'warning' NOT NULL,
	"resolved" boolean DEFAULT false NOT NULL,
	"resolved_by" varchar,
	"resolved_at" timestamp,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_drift_events_event_id_unique" UNIQUE("event_id")
);
--> statement-breakpoint
CREATE TABLE "mig_generated_tests" (
	"id" serial PRIMARY KEY NOT NULL,
	"mcp_server_id" varchar NOT NULL,
	"capability_id" varchar NOT NULL,
	"capability_name" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"test_type" varchar(32) NOT NULL,
	"test_name" varchar NOT NULL,
	"input_payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"expected_behavior" text NOT NULL,
	"last_pass" boolean,
	"generated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mig_intent_definitions" (
	"id" serial PRIMARY KEY NOT NULL,
	"intent_id" varchar NOT NULL,
	"library_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"allowed_capability_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"denied_capability_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_tool_names" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"denied_tool_names" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"domain_scope" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"package_scope" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"risk_zone" varchar(16) DEFAULT 'low' NOT NULL,
	"payload_classes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"requires_human_approval" boolean DEFAULT false NOT NULL,
	"requires_evidence" boolean DEFAULT false NOT NULL,
	"requires_manifest" boolean DEFAULT true NOT NULL,
	"status" varchar(16) DEFAULT 'draft' NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"updated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_intent_definitions_intent_id_unique" UNIQUE("intent_id")
);
--> statement-breakpoint
CREATE TABLE "mig_intent_libraries" (
	"id" serial PRIMARY KEY NOT NULL,
	"library_id" varchar NOT NULL,
	"name" text NOT NULL,
	"version" varchar(32) DEFAULT '1.0.0' NOT NULL,
	"status" varchar(16) DEFAULT 'draft' NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"updated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_intent_libraries_library_id_unique" UNIQUE("library_id")
);
--> statement-breakpoint
CREATE TABLE "mig_journey_calls" (
	"id" serial PRIMARY KEY NOT NULL,
	"call_id" varchar NOT NULL,
	"journey_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"parent_call_id" varchar,
	"sequence" integer NOT NULL,
	"current_intent_id" varchar NOT NULL,
	"current_intent" text NOT NULL,
	"caller_component_id" varchar NOT NULL,
	"caller_class" varchar(8) NOT NULL,
	"target_component_id" varchar NOT NULL,
	"input_hash" text NOT NULL,
	"authorization_manifest_id" varchar,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_journey_calls_call_id_unique" UNIQUE("call_id")
);
--> statement-breakpoint
CREATE TABLE "mig_journey_intent_transition_revocations" (
	"id" serial PRIMARY KEY NOT NULL,
	"revocation_id" varchar NOT NULL,
	"transition_id" varchar NOT NULL,
	"journey_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"parent_call_id" varchar NOT NULL,
	"revoked_by_principal_id" varchar NOT NULL,
	"reason" text NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_journey_intent_transition_revocations_revocation_id_unique" UNIQUE("revocation_id"),
	CONSTRAINT "mig_journey_intent_transition_revocations_transition_id_unique" UNIQUE("transition_id")
);
--> statement-breakpoint
CREATE TABLE "mig_journey_intent_transitions" (
	"id" serial PRIMARY KEY NOT NULL,
	"transition_id" varchar NOT NULL,
	"journey_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"parent_call_id" varchar NOT NULL,
	"source_intent_id" varchar NOT NULL,
	"target_intent_id" varchar NOT NULL,
	"authority_delta" jsonb NOT NULL,
	"approver_principal_id" varchar NOT NULL,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_journey_intent_transitions_transition_id_unique" UNIQUE("transition_id")
);
--> statement-breakpoint
CREATE TABLE "mig_journey_outcomes" (
	"id" serial PRIMARY KEY NOT NULL,
	"outcome_id" varchar NOT NULL,
	"call_id" varchar NOT NULL,
	"journey_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"outcome" varchar(16) NOT NULL,
	"reason" text NOT NULL,
	"result_hash" text,
	"result_ref" varchar,
	"authorization_manifest_id" varchar,
	"requested_authority" jsonb,
	"effective_authority" jsonb,
	"accumulated_state" jsonb,
	"structural_decision_ref" varchar,
	"journey_state" varchar(16),
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_journey_outcomes_outcome_id_unique" UNIQUE("outcome_id")
);
--> statement-breakpoint
CREATE TABLE "mig_journeys" (
	"id" serial PRIMARY KEY NOT NULL,
	"journey_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"origin_user_id" varchar NOT NULL,
	"origin_agent_id" varchar NOT NULL,
	"root_intent_id" varchar NOT NULL,
	"root_intent" text NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_journeys_journey_id_unique" UNIQUE("journey_id")
);
--> statement-breakpoint
CREATE TABLE "mig_mcp_schema_access_alerts" (
	"alert_id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"mcp_server_id" text NOT NULL,
	"mcp_tool_name" text NOT NULL,
	"prior_binding_id" text NOT NULL,
	"prior_schema_version" text NOT NULL,
	"prior_schema_fingerprint" text NOT NULL,
	"observed_schema_version" text NOT NULL,
	"observed_schema_fingerprint" text NOT NULL,
	"observation_id" text NOT NULL,
	"detected_at" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mig_mcp_schema_observations" (
	"observation_id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"mcp_server_id" text NOT NULL,
	"mcp_tool_name" text NOT NULL,
	"schema_version" text NOT NULL,
	"schema_fingerprint" text NOT NULL,
	"observed_at" timestamp NOT NULL,
	"source_proof_ref" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mig_observation_correlations" (
	"id" serial PRIMARY KEY NOT NULL,
	"correlation_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"observation_event_id" varchar NOT NULL,
	"status" varchar(32) NOT NULL,
	"correlation_key" varchar,
	"evidence" jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_observation_correlations_correlation_id_unique" UNIQUE("correlation_id")
);
--> statement-breakpoint
CREATE TABLE "mig_observation_customer_outcomes" (
	"id" serial PRIMARY KEY NOT NULL,
	"outcome_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"journey_version_id" varchar,
	"outcome" text NOT NULL,
	"evidence_refs" jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_observation_customer_outcomes_outcome_id_unique" UNIQUE("outcome_id")
);
--> statement-breakpoint
CREATE TABLE "mig_observation_events" (
	"id" serial PRIMARY KEY NOT NULL,
	"observation_event_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"source_id" varchar NOT NULL,
	"source_kind" varchar NOT NULL,
	"evidence_regime" varchar(32) NOT NULL,
	"evidence_quality" varchar(24) NOT NULL,
	"source_event_id" varchar NOT NULL,
	"idempotency_key" varchar NOT NULL,
	"occurred_at" timestamp NOT NULL,
	"envelope" jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_observation_events_observation_event_id_unique" UNIQUE("observation_event_id")
);
--> statement-breakpoint
CREATE TABLE "mig_observation_factual_edges" (
	"id" serial PRIMARY KEY NOT NULL,
	"factual_edge_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"observation_event_id" varchar NOT NULL,
	"journey_version_id" varchar,
	"edge" jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_observation_factual_edges_factual_edge_id_unique" UNIQUE("factual_edge_id")
);
--> statement-breakpoint
CREATE TABLE "mig_observation_findings" (
	"id" serial PRIMARY KEY NOT NULL,
	"finding_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"journey_version_id" varchar NOT NULL,
	"status" varchar(32) NOT NULL,
	"would_have_denied" varchar(16) NOT NULL,
	"structural_decision_ref" varchar,
	"proof_ref" varchar,
	"supersedes_finding_id" varchar,
	"evidence_refs" jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_observation_findings_finding_id_unique" UNIQUE("finding_id")
);
--> statement-breakpoint
CREATE TABLE "mig_observation_proof_references" (
	"id" serial PRIMARY KEY NOT NULL,
	"proof_reference_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"observation_structural_decision_id" varchar NOT NULL,
	"proof_ref" varchar NOT NULL,
	"evidence_refs" jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_observation_proof_references_proof_reference_id_unique" UNIQUE("proof_reference_id")
);
--> statement-breakpoint
CREATE TABLE "mig_observation_structural_decisions" (
	"id" serial PRIMARY KEY NOT NULL,
	"observation_structural_decision_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"journey_version_id" varchar NOT NULL,
	"canonical_decision_id" varchar NOT NULL,
	"enforcement" varchar(24) NOT NULL,
	"reason" text NOT NULL,
	"canonical_request_ref" varchar NOT NULL,
	"canonical_request_hash" text NOT NULL,
	"evidence_refs" jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_observation_structural_decisions_observation_structural_decision_id_unique" UNIQUE("observation_structural_decision_id")
);
--> statement-breakpoint
CREATE TABLE "mig_observed_journey_versions" (
	"id" serial PRIMARY KEY NOT NULL,
	"journey_version_id" varchar NOT NULL,
	"observed_journey_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"source_observation_event_id" varchar NOT NULL,
	"version" integer NOT NULL,
	"supersedes_journey_version_id" varchar,
	"correlation_status" varchar(32) NOT NULL,
	"snapshot" jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_observed_journey_versions_journey_version_id_unique" UNIQUE("journey_version_id")
);
--> statement-breakpoint
CREATE TABLE "mig_patch_validations" (
	"id" serial PRIMARY KEY NOT NULL,
	"patch_id" integer NOT NULL,
	"mcp_server_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"score_before" integer DEFAULT 0 NOT NULL,
	"score_after" integer DEFAULT 0 NOT NULL,
	"grade_before" varchar(4) DEFAULT 'F' NOT NULL,
	"grade_after" varchar(4) DEFAULT 'F' NOT NULL,
	"certification_before" varchar(32) DEFAULT 'FAILED' NOT NULL,
	"certification_after" varchar(32) DEFAULT 'FAILED' NOT NULL,
	"finding_delta" integer DEFAULT 0 NOT NULL,
	"coverage_delta" integer DEFAULT 0 NOT NULL,
	"validation_report" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mig_patches" (
	"id" serial PRIMARY KEY NOT NULL,
	"finding_id" varchar NOT NULL,
	"mcp_server_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"status" varchar(16) DEFAULT 'PENDING' NOT NULL,
	"diff_text" text NOT NULL,
	"risk_before" integer DEFAULT 0 NOT NULL,
	"risk_after" integer DEFAULT 0 NOT NULL,
	"coverage_delta" integer DEFAULT 0 NOT NULL,
	"regression_risk" varchar(8) DEFAULT 'low' NOT NULL,
	"impact_description" text DEFAULT '' NOT NULL,
	"capability_name" varchar,
	"finding_summary" text,
	"generated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"reviewed_at" timestamp,
	"merged_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "mig_principal_entitlements" (
	"id" serial PRIMARY KEY NOT NULL,
	"entitlement_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"principal_id" varchar NOT NULL,
	"capability_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"domain_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"intent_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"resource_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"assigned_roles" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_principal_entitlements_entitlement_id_unique" UNIQUE("entitlement_id")
);
--> statement-breakpoint
CREATE TABLE "mig_principals" (
	"id" serial PRIMARY KEY NOT NULL,
	"principal_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"principal_type" varchar(16) NOT NULL,
	"subject_ref" varchar NOT NULL,
	"display_name" text NOT NULL,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"updated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mig_registry_candidates" (
	"id" serial PRIMARY KEY NOT NULL,
	"candidate_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"component_id" varchar NOT NULL,
	"principal_id" varchar,
	"client_class" varchar(8),
	"entry_adapter" varchar(24) NOT NULL,
	"approved_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"target" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"idempotency_key" varchar(128),
	"state" varchar(20) DEFAULT 'discovered' NOT NULL,
	"created_by" varchar NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_registry_candidates_candidate_id_unique" UNIQUE("candidate_id")
);
--> statement-breakpoint
CREATE TABLE "mig_registry_history" (
	"id" serial PRIMARY KEY NOT NULL,
	"event_id" varchar NOT NULL,
	"candidate_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"from_state" varchar(16),
	"to_state" varchar(16) NOT NULL,
	"event_type" varchar(32) NOT NULL,
	"actor_id" varchar NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_registry_history_event_id_unique" UNIQUE("event_id")
);
--> statement-breakpoint
CREATE TABLE "mig_remote_agents" (
	"id" serial PRIMARY KEY NOT NULL,
	"agent_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"agent_type" varchar(32) DEFAULT 'external_mcp_client' NOT NULL,
	"principal_id" varchar,
	"display_name" text NOT NULL,
	"trust_level" varchar(16) DEFAULT 'standard' NOT NULL,
	"allowed_intent_libraries" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_intents" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_domains" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_packages" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_risk_zones" jsonb DEFAULT '["low"]'::jsonb NOT NULL,
	"max_capability_classification" varchar(16) DEFAULT 'read_only' NOT NULL,
	"requires_human_approval" boolean DEFAULT false NOT NULL,
	"oauth_client_id" varchar,
	"jwks_url" varchar,
	"ticket_secret" text NOT NULL,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"lifecycle_state" varchar(16) DEFAULT 'active' NOT NULL,
	"discovery_exception_granted" boolean DEFAULT false NOT NULL,
	"created_by" varchar,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"updated_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"last_seen_at" timestamp,
	"revoked_at" timestamp,
	CONSTRAINT "mig_remote_agents_agent_id_unique" UNIQUE("agent_id")
);
--> statement-breakpoint
CREATE TABLE "mig_security_findings" (
	"id" serial PRIMARY KEY NOT NULL,
	"report_id" varchar NOT NULL,
	"mcp_server_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"layer" varchar(16) NOT NULL,
	"severity" varchar(16) NOT NULL,
	"category" varchar(64) NOT NULL,
	"evidence" text NOT NULL,
	"recommendation" text NOT NULL,
	"likelihood" varchar(16),
	"impact" varchar(16),
	"confidence" integer,
	"affected_products" text[],
	"patch_descriptor" jsonb,
	"acknowledged" boolean DEFAULT false NOT NULL,
	"acknowledged_at" timestamp,
	"acknowledged_by" varchar,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mig_security_reports" (
	"id" serial PRIMARY KEY NOT NULL,
	"report_id" varchar NOT NULL,
	"mcp_server_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"overall_score" integer DEFAULT 0 NOT NULL,
	"grade" varchar(4) DEFAULT 'F' NOT NULL,
	"layer_scores" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"findings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"scorecard" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"capability_inventory" jsonb DEFAULT '[]'::jsonb,
	"report_data" jsonb,
	"snapshot_hash" text,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_security_reports_report_id_unique" UNIQUE("report_id")
);
--> statement-breakpoint
CREATE TABLE "mig_tenant_authority_configs" (
	"id" serial PRIMARY KEY NOT NULL,
	"config_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"version" varchar(64) NOT NULL,
	"deployment_mode" varchar(48) DEFAULT 'full_control_plane' NOT NULL,
	"authority_provider" varchar(32) DEFAULT 'mig_native' NOT NULL,
	"execution_fabric" varchar(32) DEFAULT 'mig_managed' NOT NULL,
	"provider_tenant_ref" varchar,
	"maximum_snapshot_age_seconds" integer DEFAULT 300 NOT NULL,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "mig_tenant_authority_configs_config_id_unique" UNIQUE("config_id"),
	CONSTRAINT "mig_tenant_authority_configs_snapshot_age_check" CHECK ("mig_tenant_authority_configs"."maximum_snapshot_age_seconds" > 0 AND "mig_tenant_authority_configs"."maximum_snapshot_age_seconds" <= 86400)
);
--> statement-breakpoint
CREATE TABLE "mig_tenant_authorization_policies" (
	"id" serial PRIMARY KEY NOT NULL,
	"tenant_id" varchar NOT NULL,
	"version" varchar(64) NOT NULL,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"capability_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"domain_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"intent_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"resource_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_risk_zones" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_resource_states" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"static_sod_conflicts" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mig_tickets" (
	"id" serial PRIMARY KEY NOT NULL,
	"jti" varchar NOT NULL,
	"agent_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"intent_library_id" varchar NOT NULL,
	"intent_id" varchar NOT NULL,
	"risk_zone" varchar(16) NOT NULL,
	"session_id" varchar NOT NULL,
	"issued_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
	"expires_at" timestamp NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"revoked_at" timestamp,
	"revoked_reason" text,
	CONSTRAINT "mig_tickets_jti_unique" UNIQUE("jti")
);
--> statement-breakpoint
CREATE TABLE "mig_tool_overrides" (
	"id" serial PRIMARY KEY NOT NULL,
	"mcp_server_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"tool_name" varchar NOT NULL,
	"template" varchar(64) NOT NULL,
	"applied_by_patch_id" integer,
	"applied_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"industry" text,
	"active_frameworks" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"profile" jsonb DEFAULT '{}'::jsonb,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "structural_object_history" (
	"id" serial PRIMARY KEY NOT NULL,
	"tenant_id" text DEFAULT '1001' NOT NULL,
	"object_type" varchar(32) NOT NULL,
	"object_id" text NOT NULL,
	"owner_id" varchar(255) DEFAULT '1001' NOT NULL,
	"idempotency_key" varchar(255) DEFAULT gen_random_uuid()::text NOT NULL,
	"context_id" text,
	"payload" jsonb NOT NULL,
	"previous_payload" jsonb,
	"delta_summary" jsonb,
	"recorded_by" text DEFAULT 'structural-history-store' NOT NULL,
	"trigger_reason" text DEFAULT '' NOT NULL,
	"session_id" text,
	"is_initial_record" boolean DEFAULT false NOT NULL,
	"schema_version" varchar(16) DEFAULT '1.0' NOT NULL,
	"recorded_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tenant_roles" (
	"id" serial PRIMARY KEY NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"title" text NOT NULL,
	"icon" text,
	"is_system" boolean DEFAULT false NOT NULL,
	"tenant_id" text DEFAULT '1001' NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE "workflow_notifications" (
	"id" serial PRIMARY KEY NOT NULL,
	"workflow_item_id" integer,
	"recipient_id" text,
	"recipient_name" text,
	"channel" text DEFAULT 'internal' NOT NULL,
	"event_type" text NOT NULL,
	"message" text NOT NULL,
	"is_read" boolean DEFAULT false NOT NULL,
	"tenant_id" text DEFAULT '1001' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "entra_tenant_mappings_entra_idx" ON "entra_tenant_mappings" USING btree ("entra_tenant_id");--> statement-breakpoint
CREATE INDEX "mig_authority_snapshots_tenant_authority_idx" ON "mig_authority_snapshots" USING btree ("tenant_id","authority_ref","created_at");--> statement-breakpoint
CREATE INDEX "mig_authorization_manifests_tenant_created_idx" ON "mig_authorization_manifests" USING btree ("tenant_id","created_at");--> statement-breakpoint
CREATE INDEX "mig_authorization_manifests_correlation_idx" ON "mig_authorization_manifests" USING btree ("request_correlation_id");--> statement-breakpoint
CREATE INDEX "mig_mcp_schema_access_alert_tenant_idx" ON "mig_mcp_schema_access_alerts" USING btree ("tenant_id","detected_at");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_mcp_schema_access_alert_exact_uq" ON "mig_mcp_schema_access_alerts" USING btree ("tenant_id","prior_binding_id","observation_id");--> statement-breakpoint
CREATE INDEX "mig_mcp_schema_observation_exact_idx" ON "mig_mcp_schema_observations" USING btree ("tenant_id","mcp_server_id","mcp_tool_name","schema_version","observed_at");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_observation_customer_outcomes_tenant_outcome_unique" ON "mig_observation_customer_outcomes" USING btree ("tenant_id","outcome_id");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_observation_events_tenant_idempotency_unique" ON "mig_observation_events" USING btree ("tenant_id","source_id","idempotency_key");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_observation_proof_references_tenant_proof_unique" ON "mig_observation_proof_references" USING btree ("tenant_id","proof_ref");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_observation_structural_decisions_tenant_decision_unique" ON "mig_observation_structural_decisions" USING btree ("tenant_id","canonical_decision_id");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_observation_structural_decisions_tenant_evaluation_unique" ON "mig_observation_structural_decisions" USING btree ("tenant_id","journey_version_id","canonical_request_ref");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_observed_journey_versions_tenant_version_unique" ON "mig_observed_journey_versions" USING btree ("tenant_id","observed_journey_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_observed_journey_versions_tenant_event_unique" ON "mig_observed_journey_versions" USING btree ("tenant_id","source_observation_event_id");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_principal_entitlements_one_active_idx" ON "mig_principal_entitlements" USING btree ("tenant_id","principal_id") WHERE "mig_principal_entitlements"."status" = 'active';--> statement-breakpoint
CREATE UNIQUE INDEX "mig_principals_tenant_principal_unique" ON "mig_principals" USING btree ("tenant_id","principal_id");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_principals_tenant_subject_unique" ON "mig_principals" USING btree ("tenant_id","subject_ref");--> statement-breakpoint
CREATE INDEX "mig_principals_tenant_status_idx" ON "mig_principals" USING btree ("tenant_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_registry_candidate_tenant_component_unique" ON "mig_registry_candidates" USING btree ("tenant_id","component_id");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_registry_candidate_tenant_idempotency_unique" ON "mig_registry_candidates" USING btree ("tenant_id","idempotency_key");--> statement-breakpoint
CREATE INDEX "mig_registry_candidate_tenant_state_idx" ON "mig_registry_candidates" USING btree ("tenant_id","state");--> statement-breakpoint
CREATE INDEX "mig_registry_history_candidate_created_idx" ON "mig_registry_history" USING btree ("candidate_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_tenant_authority_configs_tenant_version_unique" ON "mig_tenant_authority_configs" USING btree ("tenant_id","version");--> statement-breakpoint
CREATE INDEX "mig_tenant_authority_configs_tenant_created_idx" ON "mig_tenant_authority_configs" USING btree ("tenant_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "mig_tenant_authorization_policies_tenant_version_unique" ON "mig_tenant_authorization_policies" USING btree ("tenant_id","version");--> statement-breakpoint
CREATE INDEX "mig_tenant_authorization_policies_tenant_created_idx" ON "mig_tenant_authorization_policies" USING btree ("tenant_id","created_at");--> statement-breakpoint
CREATE INDEX "soh_object_idx" ON "structural_object_history" USING btree ("object_type","object_id","tenant_id");--> statement-breakpoint
CREATE INDEX "soh_context_idx" ON "structural_object_history" USING btree ("context_id");--> statement-breakpoint
CREATE INDEX "soh_session_idx" ON "structural_object_history" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "soh_timeline_idx" ON "structural_object_history" USING btree ("object_id","recorded_at");--> statement-breakpoint
CREATE INDEX "soh_owner_timeline_idx" ON "structural_object_history" USING btree ("owner_id","recorded_at");--> statement-breakpoint
CREATE UNIQUE INDEX "soh_idempotency_key_idx" ON "structural_object_history" USING btree ("idempotency_key");--> statement-breakpoint
CREATE UNIQUE INDEX "workflow_notifications_governed_delivery_uq" ON "workflow_notifications" USING btree ("tenant_id","event_type","message") WHERE "workflow_notifications"."channel" = 'governed_operator';