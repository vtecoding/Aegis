# Aegis Phase 1 + Policy-v1 Part 7 Invariants

These are the invariants that must hold for **all inputs** in Aegis Phase 1.
Each invariant maps to Hypothesis property-based tests. See `docs/specs/test_matrix.md`
for the full mapping.

---

## INV-01: Pipeline Determinism

**Statement:** For any `(RawIntent, ExecutionContext)` pair, `run_pipeline` returns an
equal `PipelineResult` on every invocation.

**Formal:** `run_pipeline(i, c) == run_pipeline(i, c)` for all valid `i`, `c`.

**Hypothesis test:** `tests/invariants/test_invariant_pipeline_determinism.py`

---

## INV-02: No Hidden I/O in Core

**Statement:** No function inside `src/aegis/` reads from the filesystem, network,
environment variables, hardware, or any external state during a pipeline run.

**Enforcement:** ADR-0001, ADR-0006. Verified by code review and the Phase 1 allowed
dependency list in `skills.md`.

---

## INV-03: Unknown Commands Are Blocked

**Statement:** Any `RawIntent` whose `command` is not in
`{"move", "stop", "inspect", "wait"}` produces `ValidationResult(is_valid=False)`
with `code="unsupported_command"`. The pipeline outcome is `INVALID`.

**Hypothesis test:** `tests/invariants/test_invariant_validation_determinism.py`

---

## INV-04: Malformed Boundary Input Is Rejected

**Statement:** `RawIntent` with an empty command, empty source_id, bool priority,
out-of-range priority, or non-UTC timestamp raises `ValueError` at construction.
It never reaches the pipeline.

**Contract test:** `tests/contracts/test_intent_contract.py`

---

## INV-05: Audit Checksum Binds Executable Steps Only

**Statement:** Two `CommandPlan` objects with identical steps (same `step_type`,
`parameters`, `sequence`) produce equal `plan_checksum` values, regardless of
`plan_id` or `ExecutionContext`.

**Formal:** `steps(p1) == steps(p2) → plan_checksum(p1) == plan_checksum(p2)`

**Hypothesis test:** `tests/invariants/test_invariant_audit_determinism.py`

---

## INV-06: Audit ID Binds Checksum + Context

**Statement:** Two audited plans with equal checksums but different `plan_id`,
`request_id`, `submitted_at`, `policy_version`, or `run_id` produce different
`audit_id` values.

**Hypothesis test:** `tests/invariants/test_invariant_audit_determinism.py`

---

## INV-07: Gate Cannot Mutate an Audited Plan

**Statement:** `gate_audited_plan(ap)` never modifies any field of `ap`. The input
`AuditedPlan` is identical before and after the gate call.

**Enforcement:** `AuditedPlan` is a frozen dataclass; mutation is impossible by type.

**Invariant test:** `tests/invariants/test_invariant_gate_determinism.py`

---

## INV-08: Gate Blocks Any Tampered Plan

**Statement:** For any `AuditedPlan` where either `checksum` or `audit_id` differs
from the recomputed value, the gate returns `GateDecision(status=BLOCKED)`.

**Hypothesis test:** `tests/invariants/test_invariant_gate_determinism.py`

---

## INV-09: Pipeline Cannot Produce ALLOWED Without Gate Running

**Statement:** `PipelineResult(outcome=ALLOWED)` implies `gate_decision is not None`
and `gate_decision.status == "allowed"`.

**Enforcement:** `PipelineResult.__post_init__` raises `ValueError` if violated.

**Contract test:** `tests/contracts/test_pipeline_contract.py`

---

## INV-10: Pipeline INVALID Implies No Gate Approval

**Statement:** `PipelineResult(outcome=INVALID)` implies `gate_decision is None`.
Validation-invalid results have no plan or audit receipt. Policy-invalid results may
include a plan and audited plan because policy admission runs after audit, but they never
reach final gate approval.

**Enforcement:** `PipelineResult.__post_init__` raises `ValueError` if violated.

**Contract test:** `tests/contracts/test_pipeline_contract.py`

---

## INV-11: Validation Is Side-Effect-Free

**Statement:** Calling `validate_intent(intent)` any number of times with the same
`intent` returns equal `ValidationResult` objects and does not mutate `intent` or
any other value.

**Hypothesis test:** `tests/invariants/test_invariant_validation_determinism.py`

---

## INV-12: Planning Is Side-Effect-Free and Deterministic

**Statement:** `plan_validated_intent(vr)` returns an equal `CommandPlan` on every
call for the same `ValidationResult`. It does not mutate `vr`.

**Hypothesis test:** `tests/invariants/test_invariant_planning_determinism.py`

---

## INV-13: AegisError Subclasses Propagate Through run_pipeline

**Statement:** `ValidationError`, `PlanningError`, `AuditError`, and `GateError`
raised inside the pipeline propagate to the caller of `run_pipeline` unchanged.
They are never caught and converted to `PipelineOutcome.ERROR`.

**Unit test:** `tests/unit/test_pipeline_orchestrator.py`

---

## INV-14: Unexpected Exceptions Map to ERROR, Not Panic

**Statement:** Any unexpected non-`AegisError` exception raised inside a pipeline
stage causes `run_pipeline` to return `PipelineResult(outcome=ERROR)` rather than
propagating an unhandled exception.

**Unit test:** `tests/unit/test_pipeline_orchestrator.py`

---

## INV-15: Contract Objects Are Immutable After Construction

**Statement:** All contracts (`RawIntent`, `ExecutionContext`, `ValidationResult`,
`CommandPlan`, `AuditedPlan`, `GateDecision`, `PipelineResult`) are frozen. No field
can be mutated after construction.

**Enforcement:** `frozen=True` on all contract dataclasses. Verified by pyright strict.

**Contract test:** `tests/contracts/` (mutation tests in each contract test file)

---

## INV-16: Unknown Capability Does Not Imply Allow

**Statement:** `Capability` is descriptive metadata only. A capability name, including
one unknown to future evaluators, must never grant admission by construction.

**Contract test:** `tests/contracts/test_policy_contracts.py`

---

## INV-17: Unknown Policy Rule Does Not Imply Allow

**Statement:** A `PolicyRule` binds a capability name to constraints but never grants
execution permission by itself. A future evaluator must fail closed when no enabled rule
matches.

**Contract test:** `tests/contracts/test_policy_contracts.py`

---

## INV-18: Policy Default Decision Is Never ALLOW

**Statement:** `Policy.default_decision` may be `BLOCK` or `REQUIRE_REVIEW`, and must
reject `ALLOW`.

**Hypothesis test:** `tests/invariants/test_invariant_policy_contracts.py`

---

## INV-19: WorldSnapshotStub Is Immutable Evidence Input

**Statement:** `WorldSnapshotStub` stores caller-injected facts and timestamps. It is not
a live sensor model and never reads current time, sensors, files, network, or environment.

**Contract test:** `tests/contracts/test_policy_contracts.py`

---

## INV-20: SafetyCase Is Explanation, Not Permission

**Statement:** `SafetyCase` packages evidence explaining a `PolicyEvaluationResult`. It
does not execute, approve, or override gate decisions by itself.

**Contract test:** `tests/contracts/test_policy_contracts.py`

---

## INV-21: No Matching Policy Rule Never Allows

**Statement:** `evaluate_policy` never returns `ALLOW` when no enabled policy rule
matches `Capability.name` by exact string equality.

**Hypothesis test:** `tests/invariants/test_invariant_policy_evaluator.py`

---

## INV-22: Unknown Policy Constraint Never Allows

**Statement:** Unknown Policy-v1 constraint types fail closed. Required unknown
constraints block; optional unknown constraints require review.

**Hypothesis test:** `tests/invariants/test_invariant_policy_evaluator.py`

---

## INV-23: Failed Required Constraint Blocks

**Statement:** Any failed required constraint across all matching enabled rules produces
`PolicyDecision.BLOCK`.

**Hypothesis test:** `tests/invariants/test_invariant_policy_evaluator.py`

---

## INV-24: Failed Optional Constraint Requires Review

**Statement:** Failed optional constraints remain visible and produce
`PolicyDecision.REQUIRE_REVIEW` unless a required failure already produced `BLOCK`.

**Hypothesis test:** `tests/invariants/test_invariant_policy_evaluator.py`

---

## INV-25: Policy Evaluator Has No Hidden State Reads

**Statement:** `evaluate_policy` reads only explicit `Policy`, `Capability`, optional
`WorldSnapshotStub`, and optional deterministic context. It never reads current time,
environment variables, files, network, sensors, simulation, middleware, databases, or live
robot state.

**Enforcement:** Code review, forbidden pattern checks, and evaluator tests.

---

## INV-26: SafetyCase ID Is Deterministic

**Statement:** `build_safety_case` derives `safety_case_id` from canonical explicit input
only. Equal semantic evidence produces equal IDs; changed policy result, audited plan ID,
or world snapshot ID produces a different ID.

**Unit test:** `tests/policy/test_policy_evaluator_safety_case.py`

---

## INV-27: SafetyCase Evidence Is Not Execution Permission

**Statement:** A SafetyCase is an auditable explanation package for a policy result. It
does not execute, approve, override, or bypass future gate decisions.

**Contract and unit tests:** `tests/contracts/test_policy_contracts.py`,
`tests/policy/test_policy_evaluator_safety_case.py`

---

## INV-POLICY-WIRE-001: Enforced Approval Requires Policy Allow

**Statement:** In ENFORCE mode, final approval is impossible without a
`PolicyEvaluationResult(decision=ALLOW)`.

**Invariant test:** `tests/invariants/test_invariant_policy_admission.py`

---

## INV-POLICY-WIRE-002: Missing Policy Does Not Fall Back

**Statement:** In ENFORCE mode, missing policy cannot fall back to legacy gate approval.

**Invariant test:** `tests/invariants/test_invariant_policy_admission.py`

---

## INV-POLICY-WIRE-003: Missing Capability Does Not Fall Back

**Statement:** In ENFORCE mode, missing capability cannot fall back to legacy gate approval.

**Invariant test:** `tests/invariants/test_invariant_policy_admission.py`

---

## INV-POLICY-WIRE-004: Policy Allow Cannot Bypass Gate Integrity

**Statement:** Policy `ALLOW` cannot bypass existing gate checksum, audit ID, or malformed-plan checks.

**Pipeline test:** `tests/pipeline/test_policy_admission_gate_interaction.py`

---

## INV-POLICY-WIRE-005: Policy Block Prevents Approval

**Statement:** Policy `BLOCK` always prevents final approval.

**Pipeline test:** `tests/pipeline/test_policy_admission_wiring.py`

---

## INV-POLICY-WIRE-006: Policy Require Review Prevents Approval

**Statement:** Policy `REQUIRE_REVIEW` always prevents final approval.

**Pipeline test:** `tests/pipeline/test_policy_admission_wiring.py`

---

## INV-POLICY-WIRE-007: Policy Invalid Prevents Approval

**Statement:** Policy `INVALID` always prevents final approval.

**Pipeline test:** `tests/pipeline/test_policy_admission_wiring.py`

---

## INV-POLICY-WIRE-008: Policy Error Prevents Approval

**Statement:** Policy `ERROR` always prevents final approval.

**Pipeline test:** `tests/pipeline/test_policy_admission_wiring.py`

---

## INV-POLICY-WIRE-009: SafetyCase Binds Actual Audited Plan

**Statement:** SafetyCase admission binding uses the `AuditedPlan.audit_id`, plan ID,
plan checksum, policy result checksum, world snapshot identity/checksum when present,
and capability identity produced or supplied during pipeline execution.

**Invariant test:** `tests/invariants/test_invariant_policy_admission.py`

---

## INV-POLICY-WIRE-010: Metadata Cannot Override Admission

**Statement:** Caller metadata, policy-looking parameters, context, evidence, or world facts cannot override policy admission.

**Adversarial tests:** `tests/adversarial/test_policy_admission_adversarial_bypass.py`,
`tests/pipeline/test_policy_admission_bypass.py`

---

## INV-POLICY-WIRE-011: Disabled Mode Is Not Policy Allow

**Statement:** DISABLED mode is observable but non-approved. It never creates a policy
`ALLOW` result, never sets admission allowed, and never produces `PipelineOutcome.ALLOWED`.

**Invariant test:** `tests/invariants/test_invariant_policy_admission.py`

---

## INV-POLICY-WIRE-012: Policy Admission Is Visible

**Statement:** Every `PipelineResult` exposes a `PolicyAdmissionRecord`.

**Contract test:** `tests/contracts/test_pipeline_contract.py`

---

## INV-POLICY-HARDEN-001: Pipeline Allowed Requires Policy-Backed Approval

**Statement:** `PipelineOutcome.ALLOWED` implies enforced policy admission, policy
decision `ALLOW`, `admission_allowed=True`, `integrity_status=PASSED`, no exception
marker, a valid SafetyCase, and a final allowed gate decision for the same audited plan.

**Invariant test:** `tests/invariants/test_policy_admission_invariants.py`

---

## INV-POLICY-HARDEN-002: Admission Integrity Binds Audit, Plan, Policy, and Capability

**Statement:** Admission approval is rejected if the admission record, SafetyCase, policy
result checksum, audit ID, plan ID, plan checksum, world snapshot binding, or capability
binding is stale, mismatched, missing, or forged.

**Adversarial tests:** `tests/adversarial/test_policy_admission_adversarial_bypass.py`

---

## INV-POLICY-HARDEN-003: Admission Contradictions Fail Closed

**Statement:** Approval-like admission state is invalid for disabled, blocked, review,
invalid, error, `NOT_RUN`, or failed-integrity records. `PipelineResult(ERROR)` and
`PipelineResult(INVALID)` reject embedded approval state.

**Contract tests:** `tests/contracts/test_policy_admission_contract.py`,
`tests/contracts/test_pipeline_contract.py`

---

## INV-POLICY-HARDEN-004: Security Decision Strings Are Strict

**Statement:** Security-critical decision enum values are exact. Case changes,
leading/trailing whitespace, zero-width marks, bidi marks, and fullwidth/confusable
characters are rejected rather than normalized.

**Adversarial test:** `tests/adversarial/test_policy_admission_adversarial_bypass.py`

---

## INV-POLICY-FRESH-001: Allowed Implies Fresh Snapshot

**Statement:** `PipelineOutcome.ALLOWED` implies the enforced admission record carries
`freshness_status == "FRESH"`, `freshness_result_checksum is not None`, and a non-empty
world snapshot identity.

**Invariant test:** `tests/invariants/test_world_snapshot_freshness_invariants.py`

---

## INV-POLICY-FRESH-002: Freshness Uses Only Caller-Supplied Time

**Statement:** The deterministic core computes world snapshot age only from
`evaluation_time_ms - WorldSnapshotStub.captured_at_ms`. It never reads wall-clock time,
process state, environment state, files, networks, sensors, middleware, or hardware.

**Contract and integration tests:** `tests/contracts/test_world_snapshot_freshness_contract.py`,
`tests/integration/test_pipeline_world_snapshot_freshness.py`

---

## INV-POLICY-FRESH-003: Freshness Result Binds Snapshot, Time, and Policy

**Statement:** A FRESH result is valid only when its snapshot ID, observed timestamp,
evaluation time, maximum allowed age, status, and checksum match recomputation for the same
snapshot, caller-supplied evaluation time, and `FreshnessPolicy`.

**Contract and adversarial tests:** `tests/contracts/test_world_snapshot_freshness_contract.py`,
`tests/adversarial/test_world_snapshot_staleness_bypass.py`

---

## INV-POLICY-FRESH-004: Freshness Binding Propagates Through Admission

**Statement:** For any allowed pipeline result, `PolicyEvaluationResult`, `SafetyCase`, and
`PolicyAdmissionRecord` carry identical snapshot identity, observed timestamp, freshness
status, and freshness checksum.

**Invariant test:** `tests/invariants/test_world_snapshot_freshness_invariants.py`

---

## INV-POLICY-FRESH-005: Non-Fresh Evidence Fails Closed

**Statement:** Missing, stale, future-dated, malformed, contradictory, forged, reused, or
unchecked freshness evidence cannot produce final gate approval.

**Integration and adversarial tests:** `tests/integration/test_pipeline_world_snapshot_freshness.py`,
`tests/adversarial/test_world_snapshot_staleness_bypass.py`

---

## INV-POLICY-TRUST-001: Allowed Implies Trusted Snapshot Evidence

**Statement:** `PipelineOutcome.ALLOWED` implies the enforced admission record,
`PolicyEvaluationResult`, and `SafetyCase` carry `world_snapshot_trust_status == "TRUSTED"`
and a non-empty trust result checksum.

**Invariant test:** `tests/invariants/test_world_snapshot_trust_invariants.py`

---

## INV-POLICY-TRUST-002: Trust Binding Propagates Through Admission

**Statement:** For any allowed pipeline result, source ID, source type, trust domain,
trust result checksum, evidence envelope checksum, attestation checksum when present,
trust policy checksum, verifier certification checksum, verifier ID, verifier metadata
checksum, and trust-policy config validation checksum match across `WorldSnapshotTrustResult`,
`PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord`.

**Contract and integration tests:** `tests/contracts/test_policy_admission_contract.py`,
`tests/integration/test_pipeline_world_snapshot_trust.py`

---

## INV-POLICY-TRUST-003: Freshness Does Not Imply Trust

**Statement:** Fresh but missing, unauthenticated, disallowed, malformed, contradictory,
invalid, replayed, unsupported, or non-TRUSTED world snapshot evidence cannot produce
final gate approval.

**Integration and adversarial tests:** `tests/integration/test_pipeline_world_snapshot_trust.py`,
`tests/adversarial/test_world_snapshot_trust_bypass.py`

---

## INV-POLICY-TRUST-004: Snapshot Metadata Cannot Self-Attest

**Statement:** Caller-controlled snapshot facts or metadata that claim trusted status,
attestation validity, source approval, or admission approval are inert. They never convert
missing or invalid trust evidence into `TRUSTED`.

**Invariant and adversarial tests:** `tests/invariants/test_world_snapshot_trust_invariants.py`,
`tests/adversarial/test_world_snapshot_trust_bypass.py`

---

## INV-POLICY-TRUST-005: Allowed Implies Certified Verifier And Valid Config

**Statement:** `PipelineOutcome.ALLOWED` implies the enforced admission record carries
`verifier_certification_status == "CERTIFIED"` and `trust_policy_config_status == "VALID"`.

**Integration and contract tests:** `tests/integration/test_pipeline_trust_authority_hardening.py`,
`tests/contracts/test_policy_admission_contract.py`

---

## INV-POLICY-TRUST-006: Verifier Certification Is Deterministic

**Statement:** Certifying the same verifier adapter with the same runtime domain, enforce
mode, vectors, and replay count produces an equal `VerifierAdapterCertificationResult` and
checksum every time.

**Invariant test:** `tests/invariants/test_attestation_verifier_hardening_invariants.py`

---

## INV-POLICY-TRUST-007: Trust Policy Config Validation Is Deterministic

**Statement:** Validating the same `WorldSnapshotTrustPolicy` with the same verifier
metadata, runtime domain, capability, and enforce mode produces an equal
`TrustPolicyConfigValidationResult` and checksum every time.

**Invariant test:** `tests/invariants/test_attestation_verifier_hardening_invariants.py`

---

## INV-POLICY-TRUST-008: Arbitrary Verifier Or Trust Policy Cannot Approve

**Statement:** Missing, malformed, unsafe, non-deterministic, or uncertified verifier
adapters, and empty, wildcard, mismatched, disabled-attestation, or runtime-incompatible
trust-policy configs, cannot participate in `ENFORCE` approval.

**Contract, integration, and adversarial tests:**
`tests/contracts/test_attestation_verifier_contract.py`,
`tests/contracts/test_trust_policy_config_contract.py`,
`tests/integration/test_pipeline_trust_authority_hardening.py`,
`tests/adversarial/test_attestation_verifier_adapter_bypass.py`

---

## INV-APPROVAL-RECEIPT-001: Allowed Implies Valid Approval Receipt

**Statement:** `PipelineOutcome.ALLOWED` implies `approval_receipt.status == VALID`,
`receipt_validation.status == VALID`, and both are bound to the same decision trace
checksum.

**Invariant and integration tests:** `tests/invariants/test_approval_receipt_invariants.py`,
`tests/integration/test_pipeline_approval_receipt.py`

---

## INV-APPROVAL-RECEIPT-002: Allowed Requires Full Stage Chain

**Statement:** `PipelineOutcome.ALLOWED` implies the decision trace contains the full
ordered chain: raw intent, validation, planning, audit, world snapshot admissibility,
freshness, verifier certification, trust-policy config, world snapshot trust, policy
evaluation, SafetyCase, policy admission, and final gate decision.

**Invariant and adversarial tests:** `tests/invariants/test_approval_receipt_invariants.py`,
`tests/adversarial/test_approval_receipt_bypass.py`

---

## INV-APPROVAL-RECEIPT-003: Trace And Receipt Checksums Recompute

**Statement:** Every ALLOWED trace step checksum, predecessor checksum, trace checksum,
and approval receipt checksum must match canonical recomputation. Manual replacement,
stage reordering, duplicate stages, unknown stages, or broken predecessor links fail
closed.

**Contract and adversarial tests:** `tests/contracts/test_decision_trace_contract.py`,
`tests/contracts/test_approval_receipt_contract.py`,
`tests/adversarial/test_approval_receipt_bypass.py`

---

## INV-APPROVAL-RECEIPT-004: Partial Receipts Cannot Claim Unreached Stages

**Statement:** BLOCKED, INVALID, and ERROR receipts may be partial, but they must not
carry fake policy, trust, SafetyCase, admission, or gate checksums for stages that did
not execute.

**Contract and integration tests:** `tests/contracts/test_approval_receipt_contract.py`,
`tests/integration/test_pipeline_approval_receipt.py`

---

## INV-APPROVAL-RECEIPT-005: Direct Gate Allow Is Not Full Pipeline Approval

**Statement:** A direct `GateDecision(status=ALLOWED)` cannot be represented as a full
pipeline approval unless the policy chain and approval receipt also validate against the
same audited plan.

**Regression test:** `tests/regression/test_direct_gate_not_full_approval_receipt.py`
