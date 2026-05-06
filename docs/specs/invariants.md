# Aegis Phase 1 Invariants

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

## INV-10: Pipeline INVALID Implies No Plan

**Statement:** `PipelineResult(outcome=INVALID)` implies `plan is None`,
`audited_plan is None`, and `gate_decision is None`.

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
