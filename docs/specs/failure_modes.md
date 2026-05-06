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

---

## FM-13: Policy-v1 Evaluator Fail-Closed Decisions

**Trigger:** The pure Policy-v1 evaluator receives a valid policy/capability pair where
no enabled rule matches, a matching rule contains failed constraints, required evidence is
missing or stale, supplied context is malformed, or a constraint type is unknown.

**Expected outcome:** `evaluate_policy` returns `PolicyEvaluationResult` with `BLOCK`,
`REQUIRE_REVIEW`, or `INVALID`. It never allows through missing evidence, stale evidence,
unknown constraints, hostile metadata, malformed context, or no matching rule.

**Allowed recovery:** Caller may present `REQUIRE_REVIEW` to a human workflow or reject
`BLOCK`/`INVALID` before future gate wiring. The evaluator itself performs no side effects.

**Forbidden:** Falling back to `ALLOW`; wildcard, regex, fuzzy, semantic, or LLM-based
capability matching; reading current time, environment, files, network, sensors, or runtime
robot state.

| Code | Trigger | Expected decision / reason | Required test coverage | Forbidden behaviour |
|------|---------|----------------------------|------------------------|---------------------|
| `POLICY_NO_MATCHING_RULE` | No enabled rule matches `Capability.name` exactly | `BLOCK` or `REQUIRE_REVIEW`; includes default reason | `test_policy_evaluator.py`, `test_invariant_policy_evaluator.py` | No-rule `ALLOW` |
| `POLICY_DEFAULT_BLOCK` | No match and policy default is `BLOCK` | `BLOCK` | `test_policy_evaluator.py` | Treating default as advisory |
| `POLICY_DEFAULT_REQUIRE_REVIEW` | No match and policy default is `REQUIRE_REVIEW` | `REQUIRE_REVIEW` | `test_policy_evaluator.py` | Escalating to `ALLOW` |
| `POLICY_UNKNOWN_CONSTRAINT_TYPE` | Constraint type has no built-in evaluator | `BLOCK` if required, `REQUIRE_REVIEW` if optional | `test_policy_evaluator.py`, `test_policy_evaluator_adversarial.py` | Dynamic plugin lookup or allow-all fallback |
| `POLICY_REQUIRED_CONSTRAINT_FAILED` | Any required matching constraint fails | `BLOCK` | `test_policy_evaluator.py`, invariants | One passing rule bypassing stricter rule |
| `POLICY_OPTIONAL_CONSTRAINT_FAILED` | Optional constraint fails with no required failure | `REQUIRE_REVIEW` | `test_policy_evaluator.py`, invariants | Silent optional failure |
| `POLICY_EVALUATION_CONTEXT_INVALID` | Context contains unsupported values such as callables | `INVALID` | `test_policy_evaluator_adversarial.py` | Executing or ignoring malformed context |
| `WORLD_SNAPSHOT_REQUIRED` | Required snapshot evidence is absent | `BLOCK` or `REQUIRE_REVIEW` by constraint required flag | `test_policy_evaluator_constraints.py` | Missing snapshot `ALLOW` |
| `WORLD_SNAPSHOT_EXPIRED` | `requested_at_ms > expires_at_ms` | `BLOCK` unless optional review | constraints, adversarial, invariants | Reading current time to compensate |
| `WORLD_SNAPSHOT_NOT_YET_VALID` | `requested_at_ms < captured_at_ms` | `BLOCK` unless optional review | constraints, invariants | Accepting premature evidence |
| `REQUEST_TIME_REQUIRED` | Freshness constraint lacks caller-supplied request time | `BLOCK` unless optional review | constraints | Calling `time.time()` or `datetime.now()` |
| `WORLD_SNAPSHOT_CONFIDENCE_TOO_LOW` | Snapshot confidence below required threshold | `BLOCK` unless optional review | constraints, adversarial, invariants | Low-confidence `ALLOW` |
| `VELOCITY_REQUIRED` | Capability lacks `velocity_mps` evidence | `BLOCK` unless optional review | constraints | Inferring a default velocity |
| `VELOCITY_LIMIT_EXCEEDED` | `velocity_mps > max_mps` | `BLOCK` unless optional review | constraints, adversarial, invariants | Allowing over-limit velocity |
| `TARGET_ZONE_EVIDENCE_REQUIRED` | Deny-zone constraint lacks target zone evidence | `BLOCK` unless optional review | constraints | Treating unknown zone as safe |
| `TARGET_ZONE_DENIED` | Target is inside a denied zone | `BLOCK` unless optional review | constraints, adversarial | Ignoring denied-zone evidence |
| `HUMAN_DISTANCE_REQUIRED` | Human proximity evidence is absent | `BLOCK` unless optional review | constraints | Missing distance `ALLOW` |
| `HUMAN_TOO_CLOSE` | Nearest human distance below minimum | `BLOCK` unless optional review | constraints, adversarial | Allowing unsafe supplied proximity |
| `AUTHORISATION_REQUIRED` | Required authorisation parameter is absent | `BLOCK` unless optional review | constraints | Empty authorisation wildcard |
| `AUTHORISATION_MISSING` | Context lacks exact required authorisation | `BLOCK` unless optional review | constraints, adversarial | Substring matching |
| `DUAL_AUTHORISATION_REQUIRED` | Dual-authorisation constraint is malformed | `BLOCK` unless optional review | constraints | Treating malformed rule as allow |
| `DUAL_AUTHORISATION_MISSING` | Context lacks exact `dual_authorised is True` | `BLOCK` unless optional review | constraints | Truthy coercion |
| `EMERGENCY_STOP_ALLOWED` | Explicit `system.emergency_stop` passes override constraint | `ALLOW` only if all other required constraints pass | `test_policy_evaluator.py` | Applying override to movement commands |
| `EMERGENCY_STOP_CONSTRAINT_MISMATCH` | Override constraint applied to any other capability | `BLOCK` unless optional review | `test_policy_evaluator.py` | Arbitrary emergency bypass |

---

## FM-14: SafetyCase Evidence or Hash Failure

**Trigger:** SafetyCase construction receives an empty audited plan ID, an `ALLOW` result
without passed constraint evidence, unsupported evidence values, or evidence that cannot be
canonicalised deterministically.

**Expected outcome:** `build_safety_case` raises `ValueError`; no SafetyCase is produced.

**Allowed recovery:** Caller rejects the incomplete explanation package before future gate
wiring.

**Forbidden:** Generating UUIDs or timestamps; using Python object `repr()` for custom
objects; treating a SafetyCase as execution permission.

| Code | Trigger | Expected decision / reason | Required test coverage | Forbidden behaviour |
|------|---------|----------------------------|------------------------|---------------------|
| `SAFETY_CASE_EVIDENCE_REQUIRED` | ALLOW result lacks meaningful passed constraint evidence | `ValueError` before SafetyCase construction | `test_policy_evaluator_safety_case.py` | Empty-evidence ALLOW case |
| `SAFETY_CASE_HASH_UNSTABLE` | Evidence contains unsupported or non-canonical objects | `ValueError` before hash use | `test_policy_evaluator_safety_case.py` | Memory-address-dependent hashing |
