import { createHash, randomUUID } from "crypto";
import { storage } from "../storage";
import { getBripeToolAuthorizationEntry, isValidBripeToolAuthorizationMapping } from "./mig-bripe-adapter";
import { evaluateMigStructuralDecision } from "./mig-structural-pdp";
import type { StructuralDecisionRequestV1 } from "../../shared/contracts/mig-structural-pdp-v1";
import { hashPayload } from "./mig-audit";
import { tenantOrganizationObjectId } from "@shared/corporate-brain/tenant-organization-identity";
import type {
  MigExternalExecutionEventV1, MigNormalizedCapabilityV1, MigObservedJourneyVersionV1,
  MigCorrelationStatus, MigEvidenceQuality, MigOperatingMode,
} from "./mig-observation-types";

export const MIG_OBSERVATION_OPERATING_MODE: MigOperatingMode = "observe";
export const MIG_OBSERVATION_STRUCTURAL_POLICY = Object.freeze({
  tolerance: 0.5,
});
export const MIG_OBSERVATION_MAX_EVIDENCE_AGE_MS = 24 * 60 * 60 * 1000;
export interface MigObservationAttestationVerifier {
  verify(input: { tenantId: string; event: MigExternalExecutionEventV1 }): boolean;
}
let attestationVerifier: MigObservationAttestationVerifier | null = null;
export function configureMigObservationAttestationVerifier(verifier: MigObservationAttestationVerifier | null) {
  attestationVerifier = verifier;
}
const sha = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const qualityRank: Record<MigEvidenceQuality, number> = { VERIFIED: 5, ATTESTED: 4, PARTIAL: 3, UNVERIFIED: 2, INSUFFICIENT: 1, UNKNOWN: 0 };
const FUSION_LISTENER_KINDS = {
  listen_cyber_observation: "CYBER",
  listen_fraud_observation: "FRAUD",
  listen_physical_access_observation: "PHYSICAL_ACCESS",
} as const;

export function validateExternalExecutionEvent(input: unknown): MigExternalExecutionEventV1 {
  const event = input as Partial<MigExternalExecutionEventV1>;
  if (!event || typeof event !== "object" || event.schema_version !== "mig.observation.v1" ||
    !event.event_id || !event.idempotency_key || !event.occurred_at || !event.source?.source_id ||
    !event.source.source_kind || !event.source.regime || !event.source.quality ||
    !Number.isFinite(Date.parse(event.occurred_at))) throw new Error("MIG_OBSERVATION_EVENT_INVALID");
  if (!["NATIVE_GOVERNED", "ENTERPRISE_ATTESTED", "EXTERNAL_OBSERVED", "UNKNOWN"].includes(event.source.regime) ||
    !["VERIFIED", "ATTESTED", "PARTIAL", "UNVERIFIED", "INSUFFICIENT", "UNKNOWN"].includes(event.source.quality)) {
    throw new Error("MIG_OBSERVATION_EVIDENCE_INVALID");
  }
  if (event.source.regime === "NATIVE_GOVERNED") throw new Error("MIG_OBSERVATION_NATIVE_REGIME_RESERVED");
  if (event.correlation?.some(c => !c || !c.kind || !c.value || c.exact !== true && c.exact !== false)) {
    throw new Error("MIG_OBSERVATION_CORRELATION_INVALID");
  }
  if (event.normalized_evidence?.some(signal => !signal || !signal.signal_id || !signal.type || !signal.timestamp ||
    !signal.source || !signal.source_key || !signal.evidence_id || signal.completeness !== true)) {
    throw new Error("MIG_OBSERVATION_NORMALIZED_EVIDENCE_INVALID");
  }
  if (event.factual_edges?.some(edge => {
    if (!edge.from_ref || !edge.to_ref || !edge.relation || !Array.isArray(edge.evidence_refs)) return true;
    return edge.status === "FACTUAL" && (!edge.evidence_refs.length || edge.evidence_refs.some(ref => ref !== event.event_id));
  })) {
    throw new Error("MIG_OBSERVATION_FACTUAL_EDGE_INVALID");
  }
  return event as MigExternalExecutionEventV1;
}

function correlation(event: MigExternalExecutionEventV1): { status: MigCorrelationStatus; key?: string } {
  const strong = (event.correlation ?? []).filter(c => c.exact &&
    ["trace_id", "journey_id", "session_id", "call_correlation_id"].includes(c.kind));
  const values = [...new Set(strong.map(c => `${c.kind}:${c.value}`))];
  return values.length === 1 ? { status: "CORRELATED", key: values[0] } :
    values.length > 1 ? { status: "UNCORRELATED_AMBIGUOUS" } : { status: "UNCORRELATED_INSUFFICIENT" };
}
function capability(event: MigExternalExecutionEventV1): MigNormalizedCapabilityV1 | undefined {
  if (!event.tool_name) return undefined;
  const mapping = getBripeToolAuthorizationEntry(event.tool_name);
  return mapping && isValidBripeToolAuthorizationMapping(mapping) ? {
    tool_name: mapping.tool_name, capability_id: mapping.capability_id,
    canonical_service: mapping.canonical_service!, semantic_action: mapping.semantic_action!,
  } : undefined;
}

async function ensureFactualEdgesPersisted(
  tenantId: string,
  inserted: import("@shared/schema").MigObservationEvent,
  journey: import("@shared/schema").MigObservedJourneyVersion,
) {
  const persisted = inserted.envelope as MigExternalExecutionEventV1;
  const factual = (persisted.factual_edges ?? []).filter(edge => edge.status === "FACTUAL");
  const derived = factual.map(edge => ({
    id: `mig_obs_edge_${sha([tenantId, inserted.observationEventId, edge]).slice(0, 32)}`, edge,
  }));
  const refs = new Set(((journey.snapshot as MigObservedJourneyVersionV1).factual_edge_refs ?? []));
  if (derived.some(item => !refs.has(item.id))) throw new Error("MIG_OBSERVATION_FACTUAL_EDGE_LINEAGE_INVALID");
  for (const item of derived) await storage.appendMigObservationFactualEdge({
    factualEdgeId: item.id, tenantId, observationEventId: inserted.observationEventId,
    journeyVersionId: journey.journeyVersionId, edge: item.edge,
  });
}

/** Appends evidence and, only with one exact correlation contract, a new version. */
export async function ingestMigObservation(
  tenantId: string, raw: unknown,
  serverContext?: { fusionListener: keyof typeof FUSION_LISTENER_KINDS },
) {
  const event = validateExternalExecutionEvent(raw);
  // The general MIG observation HTTP route has no listener authority. A
  // caller cannot mint Fusion lineage by submitting a tool_name/source_kind.
  if (Boolean(event.fusion_feed) !== Boolean(serverContext?.fusionListener)) {
    throw new Error("MIG_FUSION_FEED_LISTENER_REQUIRED");
  }
  if (serverContext && serverContext.fusionListener !== event.tool_name) {
    throw new Error("MIG_FUSION_FEED_PROVENANCE_INVALID");
  }
  if (["VERIFIED", "ATTESTED"].includes(event.source.quality) &&
    !attestationVerifier?.verify({ tenantId, event })) {
    throw new Error("MIG_OBSERVATION_ATTESTATION_UNVERIFIED");
  }
  const observationEventId = `mig_obs_evt_${sha([tenantId, event.source.source_id, event.idempotency_key]).slice(0, 32)}`;
  if (event.fusion_feed) {
    const feed = event.fusion_feed;
    if (!event.tool_name || !(event.tool_name in FUSION_LISTENER_KINDS) ||
      FUSION_LISTENER_KINDS[event.tool_name as keyof typeof FUSION_LISTENER_KINDS] !== event.source.source_kind ||
      feed.listener_id !== event.tool_name || feed.source_family !== event.source.source_kind ||
      feed.organization_id !== tenantOrganizationObjectId(tenantId) ||
      feed.ingestion_id !== "PENDING" || feed.evidence_class !== "UNVERIFIED_OBSERVATION" ||
      feed.raw_evidence_reference !== event.envelope?.source_reference ||
      !feed.raw_evidence_reference || !feed.source_event_type ||
      event.source.regime !== "EXTERNAL_OBSERVED" || event.source.quality !== "UNVERIFIED" ||
      event.normalized_evidence?.length || event.factual_edges?.length) {
      throw new Error("MIG_FUSION_FEED_PROVENANCE_INVALID");
    }
  }
  // Connector-provided signal details remain evidence, but their provenance is
  // rebound to the immutable admitted observation identity.
  const admittedEvent = { ...event,
    ...(event.fusion_feed ? { fusion_feed: { ...event.fusion_feed, ingestion_id: observationEventId } } : {}),
    normalized_evidence: (event.normalized_evidence ?? []).map(signal => ({
      ...signal, evidence_id: observationEventId, source_key: `${event.source.source_id}:${signal.source_key}`,
      source: event.source.source_id, timestamp: event.occurred_at,
    })) };
  const inserted = await storage.appendMigObservationEvent({
    observationEventId,
    tenantId, sourceId: event.source.source_id, sourceKind: event.source.source_kind,
    evidenceRegime: event.source.regime, evidenceQuality: event.source.quality,
    sourceEventId: event.event_id, idempotencyKey: event.idempotency_key, occurredAt: new Date(event.occurred_at),
    envelope: admittedEvent,
  });
  if (inserted.tenantId !== tenantId || inserted.sourceKind !== event.source.source_kind ||
    inserted.sourceEventId !== event.event_id || inserted.sourceId !== event.source.source_id ||
    inserted.idempotencyKey !== event.idempotency_key ||
    hashPayload(inserted.envelope) !== hashPayload(admittedEvent)) {
    throw new Error("MIG_OBSERVATION_IDEMPOTENCY_PAYLOAD_MISMATCH");
  }
  const persistedEvent = inserted.envelope as MigExternalExecutionEventV1;
  let c = correlation(persistedEvent);
  const existingCorrelation = await storage.getMigObservationCorrelationForEvent(tenantId, inserted.observationEventId);
  if (existingCorrelation) {
    c = { status: existingCorrelation.status as MigCorrelationStatus,
      key: existingCorrelation.correlationKey ?? undefined };
    const projected = await storage.getMigObservedJourneyVersionBySourceEvent(tenantId, inserted.observationEventId);
    if (projected) {
      await ensureFactualEdgesPersisted(tenantId, inserted, projected);
      return { event: inserted, correlation_status: existingCorrelation.status as MigCorrelationStatus,
        journey: projected, operating_mode: MIG_OBSERVATION_OPERATING_MODE, idempotent: true };
    }
    if (c.status !== "CORRELATED") return { event: inserted, correlation_status: existingCorrelation.status as MigCorrelationStatus,
      journey: undefined, operating_mode: MIG_OBSERVATION_OPERATING_MODE, idempotent: true };
  } else await storage.appendMigObservationCorrelation({ correlationId: `mig_obs_corr_${sha([inserted.observationEventId, c.key ?? c.status]).slice(0, 32)}`,
    tenantId, observationEventId: inserted.observationEventId, status: c.status, correlationKey: c.key ?? null,
    evidence: persistedEvent.correlation ?? [] });
  if (c.status !== "CORRELATED" || !c.key) return { event: inserted, correlation_status: c.status, journey: undefined, operating_mode: MIG_OBSERVATION_OPERATING_MODE };
  const cap = capability(persistedEvent);
  const factualEdges = (persistedEvent.factual_edges ?? []).filter(edge => edge.status === "FACTUAL");
  const edgeIds = factualEdges.map(edge => `mig_obs_edge_${sha([tenantId, inserted.observationEventId, edge]).slice(0, 32)}`);
  let journey;
  for (let attempt = 0; attempt < 4 && !journey; attempt++) {
    const already = await storage.getMigObservedJourneyVersionBySourceEvent(tenantId, inserted.observationEventId);
    if (already) { journey = already; break; }
    const prior = await storage.getLatestMigObservedJourneyVersion(tenantId, c.key);
    const oldCapabilities = ((prior?.snapshot as any)?.capabilities ?? []) as MigNormalizedCapabilityV1[];
    const capabilities = [...oldCapabilities, ...(cap ? [cap] : [])].filter((candidate, index, all) =>
      all.findIndex(other => other.capability_id === candidate.capability_id && other.tool_name === candidate.tool_name) === index);
    const priorQuality = ((prior?.snapshot as any)?.evidence_quality ?? persistedEvent.source.quality) as MigEvidenceQuality;
    const snapshot: MigObservedJourneyVersionV1 = {
      journey_version_id: `mig_obs_jv_${randomUUID()}`, observed_journey_id: c.key, version: (prior?.version ?? 0) + 1,
      supersedes_journey_version_id: prior?.journeyVersionId, correlation_status: c.status,
      event_refs: [...new Set([...((prior?.snapshot as any)?.event_refs ?? []), inserted.observationEventId])],
      mcp_refs: [...new Set([...(prior?.snapshot as any)?.mcp_refs ?? [], ...(persistedEvent.mcp_ref ? [persistedEvent.mcp_ref] : [])])],
      capabilities, resource_refs: [...new Set([...(prior?.snapshot as any)?.resource_refs ?? [], ...(persistedEvent.resource_refs ?? [])])],
      outcome_refs: [...new Set([...((prior?.snapshot as any)?.outcome_refs ?? []), ...(persistedEvent.outcome ? [inserted.observationEventId] : [])])],
      factual_edge_refs: [...new Set([...((prior?.snapshot as any)?.factual_edge_refs ?? []), ...edgeIds])],
      evidence_quality: qualityRank[persistedEvent.source.quality] < qualityRank[priorQuality] ? persistedEvent.source.quality : priorQuality,
    };
    try {
      journey = await storage.appendMigObservedJourneyVersion({ journeyVersionId: snapshot.journey_version_id, observedJourneyId: c.key,
        tenantId, sourceObservationEventId: inserted.observationEventId, version: snapshot.version,
        supersedesJourneyVersionId: snapshot.supersedes_journey_version_id ?? null, correlationStatus: c.status, snapshot });
    } catch (error) {
      if (!(error instanceof Error) || !["MIG_OBSERVATION_VERSION_LINEAGE_INVALID", "MIG_OBSERVATION_JOURNEY_LINEAGE_CONFLICT"]
        .some(code => error.message.includes(code))) throw error;
    }
  }
  if (!journey) throw new Error("MIG_OBSERVATION_JOURNEY_LINEAGE_CONFLICT");
  await ensureFactualEdgesPersisted(tenantId, inserted, journey);
  return { event: inserted, correlation_status: c.status, journey, operating_mode: MIG_OBSERVATION_OPERATING_MODE };
}

export function assertMigObservationObserveOnly(mode: string): asserts mode is MigOperatingMode {
  if (mode !== "observe") throw new Error("MIG_OBSERVATION_ENFORCEMENT_UNSUPPORTED");
}

/**
 * Canonical evaluation adapter. The authenticated canonical request is
 * re-bound at this server boundary to persisted observed evidence; observation
 * fields are never converted into principals, intents, parents, or authority.
 */
export async function evaluateObservedJourneyCanonical(input: {
  tenantId: string; observedJourneyId: string; journeyVersionId: string; canonicalRequest: StructuralDecisionRequestV1;
}) {
  assertMigObservationObserveOnly(MIG_OBSERVATION_OPERATING_MODE);
  if (input.canonicalRequest.tenant_id !== input.tenantId) throw new Error("MIG_OBSERVATION_TENANT_MISMATCH");
  const version = await storage.getMigObservedJourneyVersion(input.tenantId, input.journeyVersionId);
  const snapshot = version?.snapshot as Partial<MigObservedJourneyVersionV1> | undefined;
  if (!version || version.observedJourneyId !== input.observedJourneyId || snapshot?.correlation_status !== "CORRELATED" ||
    !["VERIFIED", "ATTESTED"].includes(snapshot.evidence_quality ?? "")) {
    throw new Error("MIG_OBSERVATION_EVALUATION_INSUFFICIENT_EVIDENCE");
  }
  const events = await storage.listMigObservationEventsByIds(input.tenantId, snapshot.event_refs ?? []);
  if (events.length !== (snapshot.event_refs ?? []).length) throw new Error("MIG_OBSERVATION_EVIDENCE_NOT_BOUND");
  const now = Date.now();
  if (events.some(row => {
    const occurredAt = new Date(row.occurredAt).getTime();
    return !Number.isFinite(occurredAt) || occurredAt > now + 5 * 60_000 ||
      now - occurredAt > MIG_OBSERVATION_MAX_EVIDENCE_AGE_MS;
  })) {
    throw new Error("MIG_OBSERVATION_EVALUATION_STALE_EVIDENCE");
  }
  const normalizedEvidence = events.flatMap(row =>
    (((row.envelope as MigExternalExecutionEventV1).normalized_evidence ?? [])));
  if (!normalizedEvidence.length) throw new Error("MIG_OBSERVATION_EVALUATION_INSUFFICIENT_EVIDENCE");
  const evidenceRefs = normalizedEvidence.map(signal => signal.evidence_id);
  const edgeRefs = [...new Set(snapshot.factual_edge_refs ?? [])];
  if (!edgeRefs.length) throw new Error("MIG_OBSERVATION_FACTUAL_EDGE_LINEAGE_INCOMPLETE");
  const edges = await storage.listMigObservationFactualEdgesByIds(input.tenantId, edgeRefs);
  const returnedIds = new Set(edges.map(row => row.factualEdgeId));
  if (edges.length !== edgeRefs.length || edgeRefs.some(id => !returnedIds.has(id)) ||
    edges.some(row => row.observationEventId && !snapshot.event_refs?.includes(row.observationEventId))) {
    throw new Error("MIG_OBSERVATION_FACTUAL_EDGE_LINEAGE_INCOMPLETE");
  }
  const factual = edges.map(row => row.edge as { from_ref: string; to_ref: string; relation: string; status: string });
  if (factual.some(edge => edge.status !== "FACTUAL")) throw new Error("MIG_OBSERVATION_FACTUAL_EDGE_LINEAGE_INCOMPLETE");
  const nodeIds = [...new Set(factual.flatMap(edge => [edge.from_ref, edge.to_ref]))];
  const mcps = [...new Set(snapshot.mcp_refs ?? [])];
  const caps = [...new Map((snapshot.capabilities ?? []).map(cap => [`${cap.tool_name}:${cap.capability_id}`, cap])).values()];
  const effectiveRequest: StructuralDecisionRequestV1 = {
    ...input.canonicalRequest,
    approvals: [],
    canonical_bripe_envelope: { ...input.canonicalRequest.canonical_bripe_envelope, signals: normalizedEvidence },
    normalized_evidence: normalizedEvidence,
    principal_activity: {
      ...input.canonicalRequest.principal_activity, principal_id: "UNKNOWN", credential_ref: "UNKNOWN", intent_id: "UNKNOWN",
      client_or_agent_id: mcps.length === 1 ? mcps[0] : "UNKNOWN", tool_name: caps.length === 1 ? caps[0].tool_name : "UNKNOWN",
      resource_refs: [...new Set(snapshot.resource_refs ?? [])], observed_as_evidence: true, prior_activity_context: [],
    },
    proposed_delta: { schema_version: "mig.structural-pdp.v1", delta_id: `observed:${version.journeyVersionId}`,
      base_reality_version: version.journeyVersionId, affected_node_ids: nodeIds,
      added_edges: factual.map(edge => ({ from: edge.from_ref, to: edge.to_ref, relation: edge.relation })), removed_edges: [],
      affected_subgraph: { node_ids: nodeIds, edge_count: factual.length } },
  };
  const requestHash = hashPayload(effectiveRequest);
  return storage.withMigObservationEvaluationLock(input.tenantId, input.journeyVersionId, effectiveRequest.request_id, async () => {
  const ensureArtifacts = async (row: import("@shared/schema").MigObservationStructuralDecision) => {
    const refs = (row.evidenceRefs as string[]) ?? [];
    let proof = await storage.getMigObservationProofForDecision(input.tenantId, row.observationStructuralDecisionId);
    if (!proof) proof = await storage.appendMigObservationProofReference({
      proofReferenceId: `mig_obs_proof_${sha([row.observationStructuralDecisionId, row.canonicalRequestHash]).slice(0, 32)}`,
      tenantId: input.tenantId, observationStructuralDecisionId: row.observationStructuralDecisionId,
      proofRef: `structural-history:${row.canonicalDecisionId}`, evidenceRefs: refs,
    });
    let finding = await storage.getMigObservationFindingForDecision(input.tenantId, row.observationStructuralDecisionId);
    if (!finding) finding = await storage.appendMigObservationFinding({
      findingId: `mig_obs_finding_${sha([row.observationStructuralDecisionId, row.canonicalRequestHash]).slice(0, 32)}`,
      tenantId: input.tenantId, journeyVersionId: row.journeyVersionId, status: "OBSERVED",
      wouldHaveDenied: ["BLOCK", "REQUIRE_APPROVAL"].includes(row.enforcement) ? "true" : "false",
      structuralDecisionRef: row.observationStructuralDecisionId, proofRef: proof.proofReferenceId, evidenceRefs: refs,
    });
    return { proof, finding };
  };
  const existing = await storage.getMigObservationStructuralDecisionByRequest(
    input.tenantId, input.journeyVersionId, effectiveRequest.request_id,
  );
  if (existing) {
    if (existing.canonicalRequestHash !== requestHash) throw new Error("MIG_OBSERVATION_EVALUATION_REPLAY_MISMATCH");
    const { proof, finding } = await ensureArtifacts(existing);
    return { decision: { decision_id: existing.canonicalDecisionId, enforcement: existing.enforcement, reason: existing.reason },
      finding, structuralDecision: existing, proof, operating_mode: MIG_OBSERVATION_OPERATING_MODE, idempotent: true };
  }
  const decision = await evaluateMigStructuralDecision(effectiveRequest, MIG_OBSERVATION_STRUCTURAL_POLICY);
  const observationDecision = await storage.appendMigObservationStructuralDecision({
    observationStructuralDecisionId: `mig_obs_decision_${sha([input.tenantId, input.journeyVersionId, effectiveRequest.request_id, requestHash]).slice(0, 32)}`, tenantId: input.tenantId,
    journeyVersionId: input.journeyVersionId, canonicalDecisionId: decision.decision_id,
    enforcement: decision.enforcement, reason: decision.reason, canonicalRequestRef: input.canonicalRequest.request_id,
    canonicalRequestHash: requestHash, evidenceRefs,
  });
  const { proof, finding } = await ensureArtifacts(observationDecision);
  return { decision: { decision_id: observationDecision.canonicalDecisionId, enforcement: observationDecision.enforcement,
    reason: observationDecision.reason }, finding, structuralDecision: observationDecision, proof,
    operating_mode: MIG_OBSERVATION_OPERATING_MODE };
  });
}

export async function appendMigObservedCustomerOutcome(input: {
  tenantId: string; outcomeId: string; journeyVersionId?: string; outcome: string; evidenceRefs: string[];
}) {
  if (!input.outcomeId || !input.outcome || !Array.isArray(input.evidenceRefs) || input.evidenceRefs.some(ref => !ref)) {
    throw new Error("MIG_OBSERVATION_CUSTOMER_OUTCOME_INVALID");
  }
  if (input.journeyVersionId && !await storage.getMigObservedJourneyVersion(input.tenantId, input.journeyVersionId)) {
    throw new Error("MIG_OBSERVATION_JOURNEY_VERSION_NOT_FOUND");
  }
  return storage.appendMigObservationCustomerOutcome(input);
}