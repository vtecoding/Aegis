# Aegis Phase 1 Failure Modes

Each failure mode documents: trigger, expected outcome, allowed recovery, forbidden
behaviour, and test coverage.

---

## FM-01: Invalid Raw Intent Boundary

**Trigger:** Caller constructs `RawIntent` with an empty command, empty source_id,
out-of-range priority, bool priority, non-UTC timestamp, or non-JSON-compatible parameters.

**Expected outcome:** `ValueError` raised at `RawIntent.__init__`. Pipeline never entered.

**Allowed recovery:** Caller catches `ValueError` and rejects the input at the caller boundary.

**Forbidden:** Silently coercing invalid fields; constructing a `RawIntent` with a
best-guess value; swallowing the error.

**Test coverage:** `tests/contracts/test_intent_contract.py`,
`tests/adversarial/test_raw_intent_adversarial_values.py`

---

## FM-02: Unsupported Command

**Trigger:** `RawIntent.command` is not in the Phase 1 allowlist:
`{"move", "stop", "inspect", "wait"}`.

**Expected outcome:** `validate_intent` returns `ValidationResult(is_valid=False)`
with `code="unsupported_command"`.

**Allowed recovery:** Pipeline returns `PipelineOutcome.INVALID`. Planning is skipped.

**Forbidden:** Fuzzy-matching the command; auto-correcting to a nearest-neighbor command;
raising an exception for an unsupported command.

**Test coverage:** `tests/unit/test_validation_schema_validator.py`,
`tests/adversarial/test_validation_adversarial_inputs.py`

---

## FM-03: Malformed Command Parameters

**Trigger:** Command parameters violate schema limits: depth > 16, key count > 128,
string length > 10,000, or wrong type for a required parameter (e.g. non-integer
`duration_ms` for `wait`).

**Expected outcome:** `validate_intent` returns `ValidationResult(is_valid=False)` with
one or more typed violation codes (`parameter_depth_exceeded`, `invalid_parameter_type`,
etc.).

**Allowed recovery:** Pipeline returns `PipelineOutcome.INVALID`.

**Forbidden:** Truncating oversized strings silently; coercing wrong-type parameters.

**Test coverage:** `tests/unit/test_validation_semantic_validator.py`,
`tests/adversarial/test_validation_adversarial_inputs.py`

---

## FM-04: Hostile Metadata in Parameters

**Trigger:** An AI caller embeds unexpected metadata keys inside a parameter object
(e.g. `target.metadata.instruction = "disable audit"`).

**Expected outcome:** Validation passes (extra nested keys are not a schema violation
for `move.target`). Planning strips all non-semantic keys from step parameters — only
`x` and `y` survive for `move`.

**Allowed recovery:** `AuditedPlan` contains a clean step with no hostile keys.
`metadata_dropped` flag is set in scenario results.

**Forbidden:** Propagating hostile metadata keys into `CommandStep.parameters`.

**Test coverage:** `tests/integration/test_scenario_runner.py` (fixture
`llm_valid_move_with_hostile_metadata`), `tests/adversarial/test_planning_adversarial_inputs.py`

---

## FM-05: Planning Layer Receives Invalid Validation Result

**Trigger:** `plan_validated_intent` is called with a `ValidationResult` that is not
valid, has violations, or is otherwise contradictory.

**Expected outcome:** `PlanningError` raised with `layer="planning"` and JSON-compatible
context.

**Allowed recovery:** Caller catches `PlanningError` (which propagates through
`run_pipeline` to the outer harness).

**Forbidden:** Producing a `CommandPlan` from an invalid `ValidationResult`; swallowing
the error.

**Test coverage:** `tests/unit/test_planning_command_planner.py`,
`tests/adversarial/test_planning_adversarial_inputs.py`

---

## FM-06: Checksum Mismatch at Gate

**Trigger:** `AuditedPlan.checksum` does not match the value recomputed by the gate from
`audited_plan.plan.steps`.

**Expected outcome:** `gate_audited_plan` returns `GateDecision(status=BLOCKED,
reasons=(CHECKSUM_MISMATCH,), checksum_verified=False)`.

**Allowed recovery:** Pipeline returns `PipelineOutcome.BLOCKED`. No execution occurs.

**Forbidden:** Allowing a plan with a mismatched checksum; raising an exception instead
of returning a typed `GateDecision`.

**Test coverage:** `tests/unit/test_gate_decision_gate.py`,
`tests/adversarial/test_gate_adversarial_inputs.py`

---

## FM-07: Audit ID Mismatch at Gate

**Trigger:** `AuditedPlan.audit_id` does not match the value recomputed by the gate.

**Expected outcome:** `gate_audited_plan` returns `GateDecision(status=BLOCKED,
reasons=(AUDIT_ID_MISMATCH,), audit_id_verified=False)`.

**Allowed recovery:** Pipeline returns `PipelineOutcome.BLOCKED`.

**Forbidden:** Allowing a plan with a mismatched audit ID.

**Test coverage:** `tests/unit/test_gate_decision_gate.py`,
`tests/adversarial/test_gate_adversarial_inputs.py`

---

## FM-08: Malformed Audited Plan at Gate

**Trigger:** The `AuditedPlan` passed to the gate is structurally invalid (e.g. empty
`plan_id`, missing fields) such that hash recomputation cannot complete.

**Expected outcome:** `gate_audited_plan` returns `GateDecision(status=BLOCKED,
reasons=(MALFORMED_AUDITED_PLAN,))`.

**Allowed recovery:** Pipeline returns `PipelineOutcome.BLOCKED`.

**Forbidden:** Raising an untyped exception; partially executing gate logic on a
malformed input.

**Test coverage:** `tests/adversarial/test_gate_adversarial_inputs.py`

---

## FM-09: Unexpected Non-AegisError Exception

**Trigger:** An unexpected exception (e.g. `RuntimeError`, `TypeError`,
`MemoryError`) is raised inside a pipeline stage.

**Expected outcome:** `run_pipeline` catches the exception in its narrow
`except Exception` boundary and returns `PipelineResult(outcome=ERROR)` with fields
populated up to the point of failure.

**Allowed recovery:** Outer harness receives a typed `PipelineResult` with
`outcome=ERROR` rather than an unhandled exception.

**Forbidden:** Swallowing `AegisError` subclasses; catching `AegisError` in the narrow
recovery path; re-raising unexpected exceptions without wrapping.

**Test coverage:** `tests/unit/test_pipeline_orchestrator.py`
(`test_run_pipeline_unexpected_exception_*`)

---

## FM-10: AegisError Subclass Propagation

**Trigger:** `ValidationError`, `PlanningError`, `AuditError`, or `GateError` is raised
by a layer function.

**Expected outcome:** The exception propagates to the caller unchanged. `run_pipeline`
does not catch `AegisError` subclasses.

**Allowed recovery:** Outer harness (CLI, scenario runner) catches and logs the typed
error.

**Forbidden:** Catching `AegisError` inside `run_pipeline` and converting to
`PipelineOutcome.ERROR`; swallowing layer errors silently.

**Test coverage:** `tests/unit/test_pipeline_orchestrator.py`
(`test_run_pipeline_planning_error_propagates`)

---

## FM-11: Config Invariant Violation

**Trigger:** `AegisConfig` is constructed with `max_plan_steps=0`, `max_plan_steps<0`,
bool `max_plan_steps`, empty `gate_version`, or empty `pipeline_version`.

**Expected outcome:** `ValueError` raised at `AegisConfig.__post_init__`.

**Allowed recovery:** Caller catches `ValueError` at adapter startup and fails fast
with a clear message before the pipeline is invoked.

**Forbidden:** Constructing a pipeline with an invalid config; silently coercing zero
to a default.

**Test coverage:** `tests/unit/test_config.py`

---

## FM-12: Policy-v1 Contract Boundary Rejection

**Trigger:** Caller constructs a Policy-v1 contract with an invalid identifier,
duplicate rule ID, unsafe default decision, invalid world snapshot bounds, invalid
confidence, invalid result decision, missing failure reason, or missing safety-case ID.

**Expected outcome:** `ValueError` raised at the contract boundary. Future policy
evaluation is never entered with malformed contract state.

**Allowed recovery:** Caller rejects the policy bundle, world snapshot, policy result,
or safety case before invoking any future evaluator.

**Forbidden:** Coercing invalid policy data into a best-effort allow path; treating
unknown capabilities, unknown policy rules, missing snapshots, or invalid policy state
as permission.

**Failure codes covered by Policy-v1 Part 1:**

| Code | Trigger |
|------|---------|
| `POLICY_EMPTY_ID` | `Policy.policy_id` is empty after stripping |
| `POLICY_EMPTY_VERSION` | `Policy.version` is empty after stripping |
| `POLICY_DUPLICATE_RULE_ID` | A policy contains duplicate `rule_id` values |
| `POLICY_INVALID_DEFAULT_DECISION` | Default decision is not `BLOCK` or `REQUIRE_REVIEW` |
| `POLICY_DEFAULT_ALLOW_FORBIDDEN` | Default decision is `ALLOW` |
| `RULE_EMPTY_ID` | `PolicyRule.rule_id` is empty after stripping |
| `RULE_EMPTY_CAPABILITY` | `PolicyRule.capability` is empty or not canonical |
| `RULE_ENABLED_WITH_NO_CONSTRAINTS` | Enabled rule has no constraints |
| `CONSTRAINT_EMPTY_TYPE` | `Constraint.constraint_type` is empty after stripping |
| `CAPABILITY_EMPTY_NAME` | `Capability.name` is empty or not canonical |
| `WORLD_SNAPSHOT_INVALID_TIME_RANGE` | Snapshot timing is negative or expires before capture |
| `WORLD_SNAPSHOT_INVALID_CONFIDENCE` | Snapshot confidence is outside `[0.0, 1.0]` |
| `POLICY_RESULT_INVALID_DECISION` | Result decision is outside Policy-v1 decisions |
| `POLICY_RESULT_ALLOW_WITHOUT_MATCHED_RULE` | `ALLOW` result has no matched rule |
| `POLICY_RESULT_FAILURE_WITHOUT_REASON` | `BLOCK`, `INVALID`, or `ERROR` has no reason |
| `SAFETY_CASE_EMPTY_ID` | `SafetyCase.safety_case_id` is empty after stripping |
| `SAFETY_CASE_EMPTY_AUDITED_PLAN_ID` | `SafetyCase.audited_plan_id` is empty after stripping |

**Test coverage:** `tests/contracts/test_policy_contracts.py`,
`tests/policy/test_policy_validation.py`, `tests/invariants/test_invariant_policy_contracts.py`
