# Validation v1 Specification

## Summary

Validation v1 evaluates `RawIntent` contracts against the Phase 1 command vocabulary,
parameter shape rules, priority semantics, and explicit JSON limits. It returns only
deterministic `ValidationResult` objects.

## Goals

- Validate `RawIntent` schema limits and semantic command parameters.
- Keep validation pure, deterministic, immutable, and side-effect-free.
- Reject unsupported commands with stable violation metadata.
- Reject malformed command parameters without raising semantic failures.
- Enforce explicit maximum parameter depth, key count, and string length.
- Preserve contracts-v1 determinism and mutation isolation invariants.

## Non-Goals

- No planning, path compilation, movement simulation, audit building, or execution.
- No ROS, motor, coordinate-frame, hardware, network, database, filesystem, async, or LLM behavior.
- No fuzzy command matching and no automatic repair of invalid intent.

## API

```python
from aegis.validation.schema_validator import validate_schema
from aegis.validation.semantic_validator import validate_intent, validate_semantics
```

`validate_schema(intent: RawIntent) -> ValidationResult` reports boundary shape and limit
violations only.

`validate_semantics(intent: RawIntent) -> ValidationResult` reports command vocabulary and
command-specific parameter violations only.

`validate_intent(intent: RawIntent) -> ValidationResult` combines schema validation followed
by semantic validation. Schema violations are ordered before semantic violations.

## Allowed Commands

Validation v1 allows exactly these abstract commands:

| Command | Parameters |
|---------|------------|
| `stop` | Must be empty. |
| `wait` | Requires integer `duration_ms`, `1 <= duration_ms <= 60_000`, bool rejected. |
| `inspect` | Requires non-empty string `target`. |
| `move` | Requires object `target` with finite numeric `x` and `y`, bool rejected. |

The `move` command remains abstract. It does not model robot kinematics, path planning,
bounds, hazards, obstacles, motors, ROS, or physical safety.

## Parameter Rules

- Top-level unexpected parameters are rejected for supported commands.
- `target` for `move` may carry additional nested metadata, but only `x` and `y` are
  interpreted by validation v1.
- `MAX_PARAMETER_DEPTH = 16`; the top-level `parameters` mapping counts as depth 1, and
  nested JSON arrays or objects increment depth.
- `MAX_PARAMETER_KEYS = 128`; object keys are counted across the full parameter tree.
- `MAX_STRING_LENGTH = 10_000`; command, source/context strings, parameter keys, and
  parameter string values are bounded.
- `MIN_PRIORITY = 1` and `MAX_PRIORITY = 10`; bool priority is rejected at the `RawIntent`
  boundary and reported by schema validation if an invalid stored object reaches validation.

## Violation Codes

| Code | Layer | Meaning |
|------|-------|---------|
| `unsupported_command` | validation | Command is outside the v1 vocabulary. |
| `unexpected_parameters` | validation | Command received unsupported top-level parameters. |
| `missing_parameter` | validation | Required command parameter is absent. |
| `invalid_parameter_type` | validation | Parameter has the wrong JSON type. |
| `invalid_parameter_value` | validation | Parameter type is correct but value is out of range or empty. |
| `parameter_depth_exceeded` | validation | Parameter JSON exceeds maximum depth. |
| `parameter_key_limit_exceeded` | validation | Parameter JSON exceeds maximum total key count. |
| `string_length_exceeded` | validation | A string exceeds the maximum length. |
| `bool_not_allowed_for_integer` | validation | Bool was supplied where a strict integer is required. |
| `bool_not_allowed_for_number` | validation | Bool was supplied where a strict number is required. |
| `missing_command` | validation | Command string is empty if an invalid object reaches validation. |
| `missing_source` | validation | Source identifier is empty if an invalid object reaches validation. |
| `priority_out_of_range` | validation | Priority is outside the explicit allowed range. |

Every violation includes `field`, `reason`, `code`, and `layer`. Codes are stable
lowercase strings.

## Determinism Rules

- Validation functions depend only on the explicit `RawIntent` input.
- Validation functions do not generate timestamps, IDs, randomness, environment values, or I/O.
- Validation functions do not mutate caller-owned data or frozen contract data.
- Repeated validation of the same `RawIntent` produces equal `ValidationResult` objects.
- Violation order is deterministic: schema violations first, semantic violations second,
  with stable field/code ordering inside each group.

## Failure Modes

- `bool` priority passing as integer is rejected at the contract boundary.
- `bool` `duration_ms` values are rejected as integer misuse.
- `bool` `move.target.x` or `move.target.y` values are rejected as numeric misuse.
- Deep nested JSON is rejected by the validation depth limit.
- Wide JSON objects are rejected by the validation key-count limit.
- Prompt-injection-like and shell-injection-like strings are treated as inert data and rejected
  as unsupported commands when used as commands.
- Semantic validation failures return structured violations instead of exceptions.

## Test Matrix

| Area | Test file | Coverage |
|------|-----------|----------|
| Schema unit | `tests/unit/test_validation_schema_validator.py` | valid intent, bool priority, depth, key count, string length, ordering |
| Semantic unit | `tests/unit/test_validation_semantic_validator.py` | command vocabulary and command-specific parameter rules |
| Invariants | `tests/invariants/test_invariant_validation_determinism.py` | determinism, mutation isolation, ordering stability, fixture validity |
| Adversarial | `tests/adversarial/test_validation_adversarial_inputs.py` | injection-like strings, oversized/deep/wide JSON, bool misuse, Unicode |
| Contracts | `tests/contracts/test_intent_contract.py` | bool priority rejected at `RawIntent` construction |

## Known Limitations

- Validation v1 does not compile commands.
- Validation v1 does not plan motion.
- Validation v1 does not evaluate hazards, bounds, obstacles, or physical safety.
- Validation v1 does not execute, publish, audit, or persist anything.