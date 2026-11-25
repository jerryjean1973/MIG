export const DEALER_PROJECTION_INPUT_CONTRACT = {
  version: "dealer-projection-request.v1",
  request_field: "operational_assessment.projection_request",
  negotiation: "Send projection_request:{} to receive required fields without executing a projection. Follow the published input schema; do not ask the platform operator to invent dashboard policy.",
  required_fields: ["contract_version", "selected_month", "mileage_policy", "payment_scope", "targets"],
  selected_month: "Explicit dashboard YYYY-MM. Never replace with the source month or infer newer source coverage.",
  mileage_policy: {
    basis: "MILEAGE_ONLY", unit: "km",
    rule: "Caller must supply A/B/C boundaries. All lower bounds are inclusive; upper bounds exclusive; C has a null upper bound. Cover [0,infinity) contiguously. No age criterion or default thresholds.",
  },
  payment_scope: {
    routes: ["CASH", "FINANCING"],
    meaning: "Cash and financed purchase routes are alternatives, not universal financing prerequisites.",
    source_binding: "Existing FinancingRecord classifications source_labeled_cash and source_named_lender; absent, ambiguous or conflicting records remain UNKNOWN, never guessed from names or amounts.",
  },
  targets: {
    scope: "Any caller-declared target linked to a domain outcome and measure, across the existing automotive opportunity families; not a sales-volume-only quota.",
    required: ["objective_id", "outcome_ref", "measure_ref", "opportunity_family", "target", "unit", "period_start", "deadline", "time_zone", "source_ref"],
    authority: "CLIENT_DECLARED_TARGET_NOT_OBSERVED_ACHIEVEMENT",
    native_support: "Targets require exact qualified outcome/measure and native computation binding. Retaining a target does not make it a native forecast input. Unbound target forecasts must remain unavailable; targets never tune forecast model selection.",
  },
  legacy: "Requests without projection_request retain the historical source-month/age-or-mileage policy. They are not compatible substitutes for a selected-month mileage-only dashboard request.",
} as const;
