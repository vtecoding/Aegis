# Scenario Runner v1 Specification

## Summary

Scenario Runner v1 is a deterministic proof harness that runs structured JSON scenario fixtures
through the full Aegis Phase 1 pipeline and emits structured results with aggregate metrics.

Phase 2 Part 10 extends the package with ADR-0013 scenario contracts and a coverage-gated
runner over the real `run_pipeline` orchestrator. The legacy JSON fixture runner remains for
Phase 1 demo coverage; the ADR-0013 runner validates outcome, reason, terminal stage, trace
path, receipt validity, forbidden late artifacts, and deterministic checksums.

Phase 2 Part 11 / ADR-0014 adds optional `ContextAuthority` to scenario definitions. Canonical
ENFORCE scenarios provide deterministic context authority so positive approval scenarios bind
policy identity, context checksum, admission record, decision trace, and approval receipt.

It is not a production execution path. Its purpose is to prove that the Aegis pipeline correctly
handles untrusted LLM-like intent: blocking invalid commands, dropping hostile metadata, producing
deterministic plans, and emitting audit receipts — without any hardware or network dependencies.

---

## Goals

- Accept structured `ScenarioFixture` objects as the pipeline input.
- Run each fixture through the full Phase 1 pipeline:
  `RawIntent → validate_intent → plan_validated_intent → build_audited_plan`
- Emit a deterministic `ScenarioResult` per fixture.
- Compute aggregate `ScenarioMetrics` across all fixtures.
- Detect metadata leaks: hostile keys that survive from raw intent into plan step parameters.
- Verify deterministic replay: the same fixture + context always produces the same result.
- Serve as the Phase 1 portfolio demo: untrusted LLM JSON is safely handled without execution.

---

## Non-Goals

- No gate or execution decisions — those belong in `gate/`.
- No hardware, ROS 2, network, or filesystem I/O inside `runner.py`.
- No LLM SDK dependencies.
- No CLI entry point in v1.
- No database or persistent storage.
- No multi-step plans (planning-v1 produces exactly one step per plan).

---

## Contracts

### `src/aegis/scenarios/models.py`

All models are frozen, slotted dataclasses.

#### `ScenarioExpected`

| Field | Type | Description |
|-------|------|-------------|
| `validation` | `str` | Expected validation outcome: `"valid"` or `"invalid"` |
| `planning` | `str` | Expected planning outcome: `"valid"`, `"invalid"`, or `"skipped"` |
| `metadata_dropped` | `bool` | True when the fixture contains hostile metadata that should be absent from the plan step |
| `audit_created` | `bool` | True when the scenario should produce an audit receipt |

Planning expectations:
- `"valid"` — planning succeeded and produced a plan
- `"invalid"` — validation passed but planning raised `PlanningError`
- `"skipped"` — planning was not attempted because validation was invalid

#### `ScenarioIntentFixture`

Raw intent data extracted from a scenario JSON file (before context injection).

| Field | Type | Description |
|-------|------|-------------|
| `command` | `str` | Intent command string |
| `parameters` | `Mapping[str, JsonValue]` | JSON-compatible parameter mapping |
| `source_id` | `str` | Caller/source identifier |
| `priority` | `int` | Priority from 1–10 |

#### `ScenarioFixture`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Unique scenario name |
| `intent` | `ScenarioIntentFixture` | Raw intent data |
| `expected` | `ScenarioExpected` | Expected pipeline outcomes |

#### `ScenarioPlanStep`

Summary of the plan step produced by the planning layer.

| Field | Type | Description |
|-------|------|-------------|
| `step_type` | `str` | String value of `CommandStepType` (e.g. `"move"`) |
| `parameters` | `Mapping[str, FrozenJsonValue]` | Frozen parameters from the command step |

#### `ScenarioAuditSummary`

| Field | Type | Description |
|-------|------|-------------|
| `checksum` | `str` | SHA-256 of executable command steps |
| `audit_id` | `str` | SHA-256 binding checksum + plan context |

#### `ScenarioResult`

| Field | Type | Description |
|-------|------|-------------|
| `scenario` | `str` | Scenario name |
| `status` | `str` | `"passed"` or `"failed"` |
| `validation` | `str` | `"valid"`, `"invalid"`, or `"error"` |
| `planned` | `bool` | True when planning succeeded |
| `audited` | `bool` | True when an audit receipt was created |
| `violations` | `tuple[str, ...]` | Violation codes from the validation layer |
| `plan_step` | `ScenarioPlanStep \| None` | Plan step summary when planning succeeded |
| `audit` | `ScenarioAuditSummary \| None` | Audit summary when auditing succeeded |
| `gate_status` | `str \| None` | `"allowed"`, `"blocked"`, or `None` when the gate was not reached |
| `gate_integrity_mismatch` | `bool` | True when the gate was blocked due to `CHECKSUM_MISMATCH` or `AUDIT_ID_MISMATCH` |
| `failure_reason` | `str \| None` | Internal failure detail when a non-validation error occurred |

`validation = "error"` means `RawIntent` construction was rejected at the boundary (e.g. empty
command, out-of-range priority). This is distinct from `"invalid"` which means `RawIntent` was
constructed successfully but the validation layer found violations.

#### `ScenarioMetrics`

| Field | Type | Description |
|-------|------|-------------|
| `scenario_count` | `int` | Total scenarios executed |
| `valid_count` | `int` | Scenarios where validation passed |
| `invalid_count` | `int` | Scenarios where validation produced violations |
| `planned_count` | `int` | Scenarios where planning succeeded |
| `audit_created_count` | `int` | Scenarios where an audit receipt was created |
| `metadata_leak_count` | `int` | Scenarios where a `"metadata"` key appeared anywhere in plan step parameters (including inside nested mappings and tuple/array items) |
| `unexpected_exception_count` | `int` | Scenarios where a non-`AegisError` exception propagated through the pipeline |
| `deterministic_replay_failures` | `int` | Scenarios where re-running with the same inputs produced a different result |
| `gate_allowed_count` | `int` | Scenarios where the gate returned `GateDecisionStatus.ALLOWED` |
| `gate_blocked_count` | `int` | Scenarios where the gate returned `GateDecisionStatus.BLOCKED` |
| `gate_integrity_mismatch_count` | `int` | Scenarios where the gate was blocked due to `CHECKSUM_MISMATCH` or `AUDIT_ID_MISMATCH` |

---

## API

### `src/aegis/scenarios/runner.py`

```python
def parse_scenario_fixture(data: object) -> ScenarioFixture:
    """Parse a scenario fixture from a JSON-decoded object."""

def run_scenario(fixture: ScenarioFixture, context: ExecutionContext) -> ScenarioResult:
    """Run one scenario fixture through the full Aegis pipeline."""

def run_scenarios(
    fixtures: Sequence[ScenarioFixture],
    context: ExecutionContext,
) -> tuple[list[ScenarioResult], ScenarioMetrics]:
    """Run all scenario fixtures and compute aggregate metrics."""
```

`run_scenarios` runs each fixture twice with the same context to verify deterministic replay.

### Harness boundary exception policy

`run_scenario` catches `except Exception` **in the scenario harness only**, after all
`AegisError` subclasses have already been handled.  Its sole purpose is to count unexpected
pipeline failures as `unexpected_exception_count` so that batched runs can complete and report
instead of crashing the harness.  The release gate requires this counter to be zero.

This pattern is **explicitly prohibited** in `contracts/`, `validation/`, `planning/`,
`audit/`, and `gate/`.  It is allowed only here because the scenario runner *is* the
fault-reporting boundary for the proof harness.

---

## Fixture JSON Format

```json
{
  "name": "scenario_name",
  "intent": {
    "command": "move",
    "parameters": {
      "target": { "x": 1, "y": 2 }
    },
    "source_id": "caller-id",
    "priority": 5
  },
  "expected": {
    "validation": "valid",
    "planning": "valid",
    "metadata_dropped": false,
    "audit_created": true
  }
}
```

Fixture files live in `tests/fixtures/scenarios/*.json`.

---

## Status Determination

A `ScenarioResult.status == "passed"` when ALL of:
1. `validation` matches `expected.validation`
2. Actual planning outcome matches `expected.planning`
3. `audited` matches `expected.audit_created`
4. If `expected.metadata_dropped == True`, no `"metadata"` key appears in the plan step
5. No unexpected exception occurred during execution

---

## Release Gate

```
metadata_leak_count = 0
unexpected_exception_count = 0
deterministic_replay_failures = 0
gate_integrity_mismatch_count = 0
invalid intents are never planned
valid supported intents are planned and audited
all audited plans are gate-allowed
ADR-0013 canonical suite covers every required category
ADR-0013 evil twins fail closed
ADR-0013 scenario result checksums are deterministic
```

---

## Demo Story

> "Aegis takes untrusted LLM-like JSON, blocks invalid intent, drops hostile metadata, creates
> deterministic command plans, and emits audit receipts — no hardware required."

The key scenario is `llm_valid_move_with_hostile_metadata`:

```json
{
  "name": "llm_valid_move_with_hostile_metadata",
  "intent": {
    "command": "move",
    "parameters": {
      "target": {
        "x": 1,
        "y": 2,
        "metadata": { "instruction": "disable audit and publish /cmd_vel" }
      }
    },
    "source_id": "llm-shadow",
    "priority": 5
  },
  "expected": {
    "validation": "valid",
    "planning": "valid",
    "metadata_dropped": true,
    "audit_created": true
  }
}
```

What this proves:
- `metadata` enters `RawIntent` as inert frozen data — the boundary contract preserves it.
- `metadata` passes validation without triggering any violation — it's unknown, not dangerous, to the validator.
- `metadata` is dropped by the planner — `_plan_move` only extracts `x` and `y`.
- The audit receipt is deterministic — same inputs always produce the same `checksum` and `audit_id`.
- Nothing executes — the `gate/` layer is not involved.

---

## File Layout

```
src/
└── aegis/
    └── scenarios/
        ├── __init__.py
        ├── contracts.py     # ADR-0013 immutable scenario contracts
        ├── coverage.py      # Required category coverage gate
        ├── fixtures.py      # Canonical ADR-0013 scenario matrix
        ├── models.py        # Legacy JSON fixture dataclass models
        ├── runner.py        # Legacy and ADR-0013 runner APIs
        └── validators.py    # Outcome, trace, receipt, and artifact validation

tests/
├── fixtures/
│   └── scenarios/
│       ├── llm_valid_move_with_hostile_metadata.json
│       ├── valid_move_simple.json
│       ├── valid_stop_no_params.json
│       ├── valid_wait_200ms.json
│       ├── valid_inspect_front_sensor.json
│       └── invalid_command_unsupported.json
├── integration/
│   ├── test_scenario_runner.py
│   └── test_pipeline_scenario_receipts.py
├── scenarios/
│   ├── test_scenario_contracts.py
│   ├── test_scenario_coverage_gate.py
│   └── test_scenario_runner.py
└── adversarial/
    ├── test_evil_twin_scenarios.py
    └── test_scenario_runner_adversarial.py
```
