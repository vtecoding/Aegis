# Pipeline Orchestrator v1 Specification

## Summary

Pipeline Orchestrator v1 is the single deterministic public API that composes all five Phase 1
Aegis layers in their canonical order and returns a typed `PipelineResult`.  It is not an
executor, simulator, or robot adapter.  Its purpose is to provide a clean, importable integration
boundary for demos, CLI wrappers, future simulator adapters, and eventually robot-action layers.

---

## Goals

- Compose the Phase 1 pipeline in a single deterministic function:
  `RawIntent + ExecutionContext → validate_intent → plan_validated_intent → build_audited_plan → gate_audited_plan → PipelineResult`
- Return a typed, immutable `PipelineResult` that captures the outcome at every layer.
- Propagate all `AegisError` subclasses without swallowing them.
- Be fully deterministic: same inputs always produce the same `PipelineResult`.
- Provide the public entry point `run_pipeline(raw_intent, context) -> PipelineResult`.

---

## Non-Goals

- No scenario fixtures — that is the scenario runner's job.
- No simulation, no robot adapter, no execution of commands.
- No ROS 2, no hardware interfaces, no network or filesystem I/O.
- No LLM SDK dependencies.
- No retry logic, no timeouts, no async I/O.
- No mutable state across invocations.
- No CLI entry point in v1.

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

**Outcome derivation rules:**
- `ALLOWED` — `gate_decision.status == GateDecisionStatus.ALLOWED`
- `BLOCKED` — `gate_decision.status == GateDecisionStatus.BLOCKED`
- `INVALID` — `validation_result is not None` and `not validation_result.is_valid`
- `ERROR` — an unexpected non-`AegisError` exception was raised

`AegisError` subclasses (`ValidationError`, `PlanningError`, `AuditError`, `GateError`) are
**not** caught — they propagate to the caller.  Only unexpected exceptions produce `ERROR`.

---

## API

### `src/aegis/pipeline/__init__.py`

```python
def run_pipeline(raw_intent: RawIntent, context: ExecutionContext) -> PipelineResult:
    """Run raw intent through the full Phase 1 Aegis pipeline.

    Composes validate_intent → plan_validated_intent → build_audited_plan →
    gate_audited_plan deterministically.

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
| Validation passed, planning/auditing/gate all succeed, gate allows | `ALLOWED` | all four |
| Validation passed, gate blocks | `BLOCKED` | all four |
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
- `outcome == BLOCKED` implies `gate_decision is not None and gate_decision.status == "blocked"`
- `outcome == INVALID` implies `plan is None and audited_plan is None and gate_decision is None`
- `outcome == ERROR` implies no AegisError subclass was involved
- Same `raw_intent` + same `context` → same `PipelineResult`, always.
- `run_pipeline` does not mutate `raw_intent` or `context`.

---

## Release Gate

```
outcome == ALLOWED for all valid, supported intents
outcome == INVALID for all invalid or unsupported intents
gate_integrity_mismatch_count = 0 (via scenario runner)
deterministic replay passes
```
