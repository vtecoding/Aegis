# Planning v1 Specification

## Summary

Planning v1 converts a successful `ValidationResult` for a valid `RawIntent` into a deterministic, immutable `CommandPlan` with one abstract command step and a stable SHA-256 `plan_id`.

## Goals

- Add typed planning contracts for command steps and command plans.
- Convert already-validated `RawIntent` objects into deterministic command steps.
- Derive `plan_id` from explicit input only.
- Preserve the original intent reference for audit and replay.
- Reject invalid, contradictory, or corrupted validation results before planning.
- Keep planning pure, deterministic, immutable, and side-effect-free.
- Prove behavior with contract, unit, invariant, and adversarial tests.

## Non-Goals

- No audit builder.
- No execution gate.
- No simulator.
- No physical safety evaluation.
- No hazards, bounds, or obstacle checks.
- No ROS or robotics middleware.
- No LLM SDKs.
- No filesystem, network, database, hardware, or async behavior.
- No command execution.

## Contracts

### CommandStepType

`CommandStepType` is a `StrEnum` with exactly these planning-v1 values:

| Name | Value |
|------|-------|
| `MOVE` | `move` |
| `STOP` | `stop` |
| `INSPECT` | `inspect` |
| `WAIT` | `wait` |

### CommandStep

`CommandStep` is a frozen, slotted dataclass with:

- `step_type: CommandStepType`
- `parameters: Mapping[str, FrozenJsonValue]`
- `sequence: int`

Rules:

- `step_type` must be a `CommandStepType`.
- `sequence` must be an integer greater than or equal to zero.
- `parameters` must be recursively frozen JSON-compatible data.
- No arbitrary executable metadata is represented on the contract.

### CommandPlan

`CommandPlan` is a frozen, slotted dataclass with:

- `plan_id: str`
- `intent: RawIntent`
- `steps: tuple[CommandStep, ...]`

Rules:

- `plan_id` must be non-empty.
- `intent` is the original validated `RawIntent` reference.
- `steps` must be non-empty and stored as a tuple.
- Step sequence values must be exactly `0..len(steps)-1`.

## API

```python
from aegis.planning.command_planner import plan_validated_intent

plan = plan_validated_intent(validation_result)
```

`plan_validated_intent(validation: ValidationResult) -> CommandPlan` accepts only a validation result that is already valid and has no violations. It does not call validation internally and does not accept raw invalid intents directly.

Failure behavior:

- Invalid validation results raise `PlanningError`.
- Validation results with violations raise `PlanningError`.
- Unsupported commands marked valid raise `PlanningError` as contract-corruption defense.
- Malformed valid-looking command parameters raise `PlanningError`.

All planning errors use JSON-compatible context.

## Command Mappings

Planning v1 emits exactly one command step per valid intent.

| Intent command | Step type | Step parameters |
|----------------|-----------|-----------------|
| `stop` | `CommandStepType.STOP` | `{}` |
| `wait` | `CommandStepType.WAIT` | `{"duration_ms": duration_ms}` |
| `inspect` | `CommandStepType.INSPECT` | `{"target": target}` |
| `move` | `CommandStepType.MOVE` | `{"target": {"x": x, "y": y}}` |

For `move`, nested metadata under `target` is deliberately dropped. Only `x` and `y` are preserved in the command step so arbitrary caller metadata cannot become executable-shaped plan data.

## Plan ID Hashing

`stable_plan_id(intent: RawIntent, steps: tuple[CommandStep, ...]) -> str` returns a lowercase SHA-256 hex digest over deterministic canonical JSON.

The hash payload includes:

- intent `command`
- intent `parameters`
- `source_id`
- `priority`
- `context.request_id`
- `context.submitted_at` serialized as UTC ISO text
- `context.policy_version`
- `context.run_id`
- command steps, including step type, parameters, and sequence

The hash payload never includes memory addresses, object reprs, Python `hash()` values, UUIDs, current time, environment data, filesystem state, network state, database state, or hardware state.

## Determinism Rules

- Planning depends only on the explicit `ValidationResult` input.
- Plan IDs depend only on explicit intent, context, and command step data.
- Planning does not generate timestamps, UUIDs, randomness, or process-derived values.
- Planning performs no filesystem, network, database, hardware, or async behavior.
- Planning does not mutate the validation result, intent, or caller-owned input data.
- Repeated planning of the same validation result produces equal command plans and equal plan IDs.
- Mapping key order does not affect plan IDs.

## Failure Modes

- Invalid validation results are rejected before command mapping.
- Contradictory validation results with violations are rejected before command mapping.
- Unsupported commands marked as valid are rejected as contract corruption.
- Valid-looking command parameters that do not match the command mapping are rejected as contract corruption.
- Extra `move.target` metadata is dropped instead of carried into command steps.
- Hostile strings are preserved only as inert JSON-compatible data where validation permits them.

## Test Matrix

| Area | Test file | Coverage |
|------|-----------|----------|
| Planning contracts | `tests/contracts/test_planning_contract.py` | step types, sequence rules, parameter freezing, plan shape, immutability |
| Plan hashing | `tests/unit/test_planning_plan_hasher.py` | deterministic IDs, key-order invariance, context sensitivity, SHA-256 shape, no Python `hash()` |
| Command planner | `tests/unit/test_planning_command_planner.py` | command mappings, metadata dropping, invalid/corrupt validation rejection, mutation isolation |
| Invariants | `tests/invariants/test_invariant_planning_determinism.py` | repeated planning equality, plan ID stability, key-order invariance, one-step v1 output |
| Adversarial | `tests/adversarial/test_planning_adversarial_inputs.py` | hostile inspect strings, hostile move metadata, large targets, unsupported and corrupted validation state |

## Known Limitations

- Planning-v1 does not execute commands.
- Planning-v1 does not audit plans.
- Planning-v1 does not evaluate hazards, bounds, obstacles, or physical safety.
- Planning-v1 emits one command step per valid intent.
- Planning-v1 is abstract and not ROS-compatible yet.
