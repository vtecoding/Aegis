# Pipeline Orchestrator v1 Specification

## Summary

Pipeline Orchestrator v1 is the single deterministic public API that composes all five Phase 1
Aegis layers in their canonical order and returns a typed `PipelineResult`.  It is not an
executor, simulator, or robot adapter.  Its purpose is to provide a clean, importable integration
boundary for demos, CLI wrappers, future simulator adapters, and eventually robot-action layers.
Phase 2 Part 3 adds policy admission between audit and gate. Phase 2 Part 4 hardens that
boundary so final pipeline approval is impossible without valid enforced policy admission.

---

## Goals

- Compose the Phase 1 pipeline in a single deterministic function:
  `RawIntent + ExecutionContext → validate_intent → plan_validated_intent → build_audited_plan → gate_audited_plan → PipelineResult`
- Return a typed, immutable `PipelineResult` that captures the outcome at every layer.
- Propagate all `AegisError` subclasses without swallowing them.
- Be fully deterministic: same inputs always produce the same `PipelineResult`.
- Provide the public entry point `run_pipeline(raw_intent, context, *, policy_admission=None) -> PipelineResult`.
- In policy-enforced mode, evaluate Policy-v1 after audit and before final gate approval.
- Require policy-backed admission integrity for any `PipelineOutcome.ALLOWED` result.

---

## Non-Goals

- No scenario fixtures — that is the scenario runner's job.
- No simulation, no robot adapter, no execution of commands.
- No ROS 2, no hardware interfaces, no network or filesystem I/O.
- No LLM SDK dependencies.
- No retry logic, no timeouts, no async I/O.
- No mutable state across invocations.
- No CLI entry point in v1.
- No global policy, environment-loaded policy, filesystem-loaded policy, or dynamic policy registry.

---

## Contracts

### `src/aegis/contracts/pipeline.py`

All models are frozen, slotted dataclasses.

#### `PipelineOutcome`

```python
class PipelineOutcome(StrEnum):
    ALLOWED  = "allowed"   # Plan passed gate — safe to hand off
    BLOCKED  = "blocked"   # Plan produced but gate rejected it
    INVALID  = "invalid"   # Validation failed — never planned
    ERROR    = "error"     # Unexpected non-AegisError exception
```

#### `PipelineResult`

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | `PipelineOutcome` | Final pipeline outcome |
| `validation_result` | `ValidationResult \| None` | Validation outcome; `None` only on `ERROR` |
| `plan` | `CommandPlan \| None` | Command plan; populated when planning succeeded |
| `audited_plan` | `AuditedPlan \| None` | Audit receipt; populated when auditing succeeded |
| `gate_decision` | `GateDecision \| None` | Gate decision; populated when gate ran |
| `policy_admission` | `PolicyAdmissionRecord` | Disabled or enforced policy admission state |

**Outcome derivation rules:**
- `ALLOWED` — policy admission is `ENFORCE`, policy decision is `ALLOW`, SafetyCase and
    admission bindings pass integrity checks, and `gate_decision.status == GateDecisionStatus.ALLOWED`
- `BLOCKED` — policy admission is disabled, missing, or denied; or the gate blocks after
    policy-backed admission
- `INVALID` — validation failed before planning, or policy admission produced `PolicyDecision.INVALID`
- `ERROR` — an unexpected non-`AegisError` exception was raised

`AegisError` subclasses (`ValidationError`, `PlanningError`, `AuditError`, `GateError`) are
**not** caught — they propagate to the caller.  Only unexpected exceptions produce `ERROR`.

---

## API

### `src/aegis/pipeline/__init__.py`

```python
def run_pipeline(
    raw_intent: RawIntent,
    context: ExecutionContext,
    *,
    policy_admission: PolicyAdmissionInput | None = None,
) -> PipelineResult:
    """Run raw intent through the full Phase 1 Aegis pipeline.

    Composes validate_intent → plan_validated_intent → build_audited_plan →
    optional policy admission → gate_audited_plan deterministically.

    AegisError subclasses propagate to the caller unchanged.

    Returns:
        PipelineResult with outcome ALLOWED, BLOCKED, INVALID, or ERROR.
    """
```

---

## Status Determination

| Condition | `outcome` | Fields populated |
|-----------|-----------|-----------------|
| Validation failed | `INVALID` | `validation_result` |
| Validation passed, policy disabled or omitted | `BLOCKED` | validation, plan, audit, disabled policy record; no gate decision |
| Policy ENFORCE returns ALLOW, integrity passes, and gate allows | `ALLOWED` | all layer fields plus enforced policy record |
| Policy ENFORCE denies before gate | `BLOCKED`, `INVALID`, or `ERROR` | validation, plan, audit, policy record |
| Policy ENFORCE allows but gate blocks | `BLOCKED` | validation, plan, audit, policy record, blocked gate decision |
| Unexpected non-`AegisError` exception | `ERROR` | as many as were computed before the exception |

---

## Error Propagation Policy

`run_pipeline` does **not** catch `AegisError` subclasses.  The caller (CLI, scenario runner,
future adapter) is responsible for handling typed Aegis errors.  This keeps the pipeline core
free from error-swallowing and preserves the audit trail semantics.

Only `except Exception` in a narrow recovery path may produce `PipelineOutcome.ERROR`.  This
is documented here and intentionally mirrors the scenario runner's harness boundary policy:
it exists so callers get a typed result instead of an unhandled exception for unforeseen
failures.

---

## Invariants

- `outcome == ALLOWED` implies `gate_decision is not None and gate_decision.status == "allowed"`
- `outcome == ALLOWED` implies policy admission is enforced, allowed, integrity-passed, and bound to the same audited plan as the gate decision
- `outcome == BLOCKED` implies a blocked gate decision or denied enforced policy admission
- `outcome == INVALID` implies `plan is None and audited_plan is None and gate_decision is None`
    unless the invalid state is produced by policy admission after audit
- `outcome == ERROR` implies no AegisError subclass was involved
- Same `raw_intent` + same `context` → same `PipelineResult`, always.
- `run_pipeline` does not mutate `raw_intent` or `context`.
- Policy `ALLOW` is necessary but not sufficient for final approval.
- Disabled policy admission is not a policy `ALLOW` result and cannot produce final approval.
- Admission records with stale, mismatched, forged, malformed, skipped, or contradictory bindings cannot produce final approval.

---

## Release Gate

```
outcome == ALLOWED for valid, supported intents only when enforced policy admission allows and gate integrity also allows
disabled_policy_admission_allowed_count = 0
outcome == INVALID for all invalid or unsupported intents
gate_integrity_mismatch_count = 0 (via scenario runner)
deterministic replay passes
```
