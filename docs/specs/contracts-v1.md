# Contracts v1 Specification

## Summary

Contracts v1 defines the first deterministic contract spine for Aegis Phase 1: execution context, JSON boundary typing, raw intent input, validation result metadata, and typed Aegis errors.

## Goals

- Require caller injection for request IDs, timestamps, policy versions, and optional run IDs.
- Keep contract objects immutable, deterministic, typed, and side-effect-free.
- Restrict JSON boundary data to strings, integers, finite floats, booleans, nulls, arrays, and string-keyed objects.
- Freeze raw intent parameters and error context so caller mutation cannot alter stored contract evidence.
- Represent validation failures with stable, inspectable violation metadata.
- Provide a typed Aegis error hierarchy with layer, message, and JSON-compatible context.

## Non-Goals

- No full DIG pipeline execution.
- No command planner.
- No semantic validator.
- No audit record builder.
- No execution gate behavior.
- No CLI or simulation behavior.
- No networking, filesystem reads, database clients, hardware interfaces, ROS 2, or LLM dependencies.

## Contracts

### ExecutionContext

`ExecutionContext` is the explicit metadata boundary for deterministic runs.

- `request_id`: non-empty caller-provided string, stripped before storage.
- `submitted_at`: caller-provided timezone-aware UTC `datetime`.
- `policy_version`: non-empty caller-provided string, stripped before storage.
- `run_id`: optional non-empty caller-provided string, stripped before storage when present.

The contract rejects naive timestamps and non-UTC aware timestamps. It never generates fallback IDs or timestamps.

### JSON Boundary Types

`JsonValue` covers JSON-compatible boundary data only: strings, integers, finite floats, booleans, nulls, lists, and string-keyed dictionaries.

`is_json_value` rejects non-finite floats, tuples, sets, bytes, arbitrary objects, datetime objects, decimal objects, paths, and dictionaries with non-string keys.

`FrozenJsonValue` is the stored immutable representation used by contracts that retain JSON data. Lists become tuples. Dictionaries become read-only mappings with deterministic key order.

### RawIntent

`RawIntent` is the boundary-level intent contract.

- `command`: non-empty string, stripped before storage.
- `parameters`: caller-provided JSON-compatible mapping, recursively frozen before storage.
- `source_id`: non-empty string, stripped before storage.
- `priority`: integer from 1 through 10 inclusive.
- `context`: caller-provided `ExecutionContext`.

Raw intent does not validate command semantics or command-specific parameter schemas. It only preserves and freezes explicit boundary data.

### Violation

`Violation` stores stable validation failure metadata.

- `field`: non-empty stripped string.
- `reason`: non-empty stripped string.
- `code`: non-empty stripped string.
- `layer`: non-empty stripped string.

### ValidationResult

`ValidationResult` stores the result of validating a `RawIntent`.

- `is_valid=True` requires zero violations.
- `is_valid=False` requires at least one violation.
- Incoming violation iterables are stored as tuples.

This prevents contradictory states such as valid results with violations or invalid results without failure evidence.

### Aegis Errors

The typed error hierarchy is:

- `AegisError`
- `ValidationError`
- `PlanningError`
- `AuditError`
- `GateError`
- `ConfigurationError`

Every error includes a non-empty stripped `message`, a non-empty stripped `layer`, and recursively frozen JSON-compatible `context`. `str(error)` is stable and includes the layer and message.

## Determinism Rules

- Contract constructors never generate timestamps.
- Contract constructors never generate UUIDs or other IDs.
- Contract constructors never read randomness, environment variables, files, networks, databases, or hardware.
- All non-deterministic metadata must be injected through explicit constructor arguments.
- Caller-owned JSON data is copied into immutable stored representations.
- Repeated construction with the same explicit inputs must produce equal contract objects and stable error strings.

## Failure Modes

- Naive timestamps are rejected to prevent replay drift.
- Non-UTC aware timestamps are rejected to prevent implicit normalization.
- Empty IDs and metadata fields are rejected after stripping whitespace.
- Caller mutation is blocked by recursive freezing of retained JSON values.
- `Any` is not used in internal contracts; boundary values are represented as `object` until narrowed by JSON checks.
- Contradictory validation results are rejected at construction time.
- Error context mutation cannot hide original failure evidence.
- NaN and infinity are rejected as JSON-compatible floats.

## Test Matrix

| Area | Test file | Coverage |
|------|-----------|----------|
| ExecutionContext | `tests/contracts/test_context_contract.py` | UTC requirement, canonical strings, immutability, equality |
| JSON boundary | `tests/contracts/test_json_types_contract.py` | accepted JSON values and rejected non-JSON values |
| RawIntent | `tests/contracts/test_intent_contract.py` | required fields, priority range, JSON parameters, mutation protection |
| Validation | `tests/contracts/test_validation_contract.py` | violation metadata, validity consistency, tuple storage, immutability |
| Errors | `tests/contracts/test_errors_contract.py` | hierarchy construction, required fields, context freezing, stable strings |
| Determinism | `tests/invariants/test_invariant_contract_determinism.py` | repeated construction equality and mutation isolation |
| Adversarial boundary | `tests/adversarial/test_raw_intent_adversarial_values.py` | hostile strings, Unicode, nested JSON, large strings, non-finite floats |

## Known Limitations

- These are contracts only; no validation layer behavior is implemented yet.
- `RawIntent` is still boundary-level and does not narrow command-specific schemas yet.
- No planner, audit builder, or execution gate exists yet.
- No robotics or LLM integration exists.