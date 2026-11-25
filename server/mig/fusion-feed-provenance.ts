import type { MigObservationEvent } from "@shared/schema";
import type { MigExternalExecutionEventV1 } from "./mig-observation-types";
import { tenantOrganizationObjectId } from "@shared/corporate-brain/tenant-organization-identity";

const LISTENER_FAMILY = {
  listen_cyber_observation: "CYBER",
  listen_fraud_observation: "FRAUD",
  listen_physical_access_observation: "PHYSICAL_ACCESS",
} as const;

/**
 * BAL adapter input contract, not BAL admission. An adapter must attach this
 * provenance to the canonical signal's trace lineage; ontology/BDL may assign
 * different structural and consequence domains but must not rewrite this family.
 * Never use the BAL hostname field `source_domain` for this value.
 */
export function fusionFeedProvenanceForBal(row: MigObservationEvent, tenantId: string) {
  const event = row.envelope as Partial<MigExternalExecutionEventV1>;
  const feed = event?.fusion_feed;
  if (!feed) throw new Error("MIG_FUSION_FEED_PROVENANCE_MISSING");
  const expected = LISTENER_FAMILY[feed.listener_id as keyof typeof LISTENER_FAMILY];
  if (!expected || row.tenantId !== tenantId ||
    feed.organization_id !== tenantOrganizationObjectId(tenantId) ||
    feed.source_family !== expected || row.sourceKind !== expected ||
    event.tool_name !== feed.listener_id || event.source?.source_kind !== expected ||
    event.source?.source_id !== row.sourceId || event.event_id !== row.sourceEventId ||
    event.idempotency_key !== row.idempotencyKey ||
    new Date(event.occurred_at ?? "").getTime() !== new Date(row.occurredAt).getTime() ||
    feed.ingestion_id !== row.observationEventId ||
    feed.raw_evidence_reference !== event.envelope?.source_reference ||
    feed.evidence_class !== "UNVERIFIED_OBSERVATION" ||
    event.source?.quality !== "UNVERIFIED" || event.source?.regime !== "EXTERNAL_OBSERVED") {
    throw new Error("MIG_FUSION_FEED_PROVENANCE_INVALID");
  }
  return {
    tenant_id: tenantId,
    organization_id: feed.organization_id,
    source_family: expected,
    source_system: row.sourceId,
    source_event_id: row.sourceEventId,
    source_event_type: feed.source_event_type,
    observed_at: event.occurred_at!,
    evidence_class: feed.evidence_class,
    listener_id: feed.listener_id,
    ingestion_id: row.observationEventId,
    raw_evidence_reference: feed.raw_evidence_reference,
    admission_state: "NOT_ADMITTED" as const,
  };
}