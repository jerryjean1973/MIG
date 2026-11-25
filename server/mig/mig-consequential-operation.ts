import { projectTrustedMigOperation, type TrustedMigOperation } from "./mig-structural-reality";
import type { MigStructuralEnforcement } from "../../shared/contracts/mig-structural-pdp-v1";
import type { CanonicalBRIPeExecutionInputV1 } from "../../shared/contracts/bripe-execution-v1";

export interface MigConsequentialControl {
  approval_ids: string[];
  purpose: string;
  project_or_process: string;
}

/** The PDP evaluates the requested operation, not the submitted CRM evidence.
 * Keep its canonical context in the existing non-forwarded control shell.
 * Legacy envelope-only callers retain their original context location.
 * This selects a context only: the existing canonical gate still validates it
 * and MIG still supplies the operation evidence server-side.
 */
export function resolveMigStructuralEnvelope(
  supplied: Record<string, unknown>,
): CanonicalBRIPeExecutionInputV1 | undefined {
  const control = supplied.structural_pdp;
  if (!control || typeof control !== "object" || Array.isArray(control)) return undefined;
  const candidate = "canonical_envelope" in control
    ? control.canonical_envelope : supplied.canonical_envelope;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return undefined;
  return candidate as CanonicalBRIPeExecutionInputV1;
}

export function isMigEnforcementDispatchable(enforcement: MigStructuralEnforcement): boolean {
  return enforcement === "ALLOW" || enforcement === "ALLOW_WITH_CONTROL";
}

/** Common PEP preparation used by both harmless and consequential tools. */
export function prepareMigOperationForExecution(input: {
  toolName: string; classification: string; suppliedInput: Record<string, unknown>;
}, hardBoundary: (operation: TrustedMigOperation) => void): TrustedMigOperation {
  const exactPayload = { ...input.suppliedInput };
  delete exactPayload.structural_pdp;
  const operation = projectTrustedMigOperation(input.toolName, input.classification, exactPayload);
  hardBoundary(operation);
  return operation;
}

/**
 * Cohesive, dependency-injected PEP sequence. Hard boundaries run before any
 * canonical work; reservation commits before canonical evaluation; the exact
 * canonical payload returned here is the only payload eligible for execution.
 */
export async function evaluateConsequentialMigOperation<A, M, E>(input: {
  toolName: string;
  classification: string;
  suppliedInput: Record<string, unknown>;
  control: MigConsequentialControl;
  preparedOperation?: TrustedMigOperation;
  hardBoundaryAlreadyChecked?: boolean;
}, deps: {
  hardBoundary(operation: TrustedMigOperation): Promise<void> | void;
  resolveApprovals(ids: string[]): Promise<A>;
  reserveActivity(operation: TrustedMigOperation): Promise<M>;
  evaluateCanonical(materialized: M, approvals: A, operation: TrustedMigOperation): Promise<E>;
}): Promise<{ operation: TrustedMigOperation; canonicalPayload: Record<string, unknown>; materialized: M; approvals: A; enforcement: E }> {
  if ("operation" in (input.suppliedInput.structural_pdp as Record<string, unknown> | undefined ?? {}) ||
      "request_id" in (input.suppliedInput.structural_pdp as Record<string, unknown> | undefined ?? {})) {
    throw new Error("MIG_CALLER_OPERATION_DESCRIPTOR_FORBIDDEN");
  }
  const exactPayload = { ...input.suppliedInput };
  delete exactPayload.structural_pdp;
  const operation = input.preparedOperation ??
    projectTrustedMigOperation(input.toolName, input.classification, exactPayload);
  if (!input.hardBoundaryAlreadyChecked) await deps.hardBoundary(operation);
  const approvals = await deps.resolveApprovals(input.control.approval_ids);
  const materialized = await deps.reserveActivity(operation);
  const enforcement = await deps.evaluateCanonical(materialized, approvals, operation);
  return { operation, canonicalPayload: operation.canonical_payload, materialized, approvals, enforcement };
}