"""Scenario Runner v1: runs structured fixtures through the Aegis pipeline."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from aegis.audit import build_audited_plan
from aegis.contracts.approval_receipt import ApprovalReceipt
from aegis.contracts.context import ExecutionContext
from aegis.contracts.decision_trace import DecisionTrace
from aegis.contracts.gate import GateBlockReason, GateDecisionStatus
from aegis.contracts.intent import RawIntent
from aegis.contracts.json_types import FrozenJsonValue, JsonValue
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.contracts.world_snapshot_freshness import DEFAULT_FRESHNESS_POLICY
from aegis.errors import PlanningError
from aegis.gate import gate_audited_plan
from aegis.pipeline import run_pipeline
from aegis.planning import plan_validated_intent
from aegis.scenarios.contracts import (
    EvilTwinMutation,
    ScenarioDefinition,
    ScenarioRunResult,
    ScenarioSuiteResult,
    scenario_suite_checksum,
)
from aegis.scenarios.coverage import evaluate_scenario_coverage
from aegis.scenarios.fixtures import canonical_scenario_definitions
from aegis.scenarios.models import (
    ScenarioAuditSummary,
    ScenarioExpected,
    ScenarioFixture,
    ScenarioIntentFixture,
    ScenarioMetrics,
    ScenarioPlanStep,
    ScenarioResult,
)
from aegis.scenarios.validators import validate_scenario_result
from aegis.validation import validate_intent


def parse_scenario_fixture(data: object) -> ScenarioFixture:
    """Parse a scenario fixture from a JSON-decoded object.

    Validates all required fields and types before constructing a
    ``ScenarioFixture``.  Does not validate intent semantics — that is the
    job of the validation layer at run time.

    Args:
        data: JSON-decoded value, typically the result of ``json.loads``.

    Returns:
        A validated ``ScenarioFixture`` ready for ``run_scenario``.

    Raises:
        ValueError: If the fixture data is missing required fields or has
            invalid field types.
    """
    if not isinstance(data, dict):
        raise ValueError("fixture must be a JSON object")

    # Raw JSON boundary: json.loads always produces str-keyed dicts.
    raw = cast(dict[str, object], data)

    name = raw.get("name")
    intent_raw = raw.get("intent")
    expected_raw = raw.get("expected")

    if not isinstance(name, str) or name.strip() == "":
        raise ValueError("fixture.name must be a non-empty string")
    if not isinstance(intent_raw, dict):
        raise ValueError("fixture.intent must be a JSON object")
    if not isinstance(expected_raw, dict):
        raise ValueError("fixture.expected must be a JSON object")

    intent_dict = cast(dict[str, object], intent_raw)
    expected_dict = cast(dict[str, object], expected_raw)

    command = intent_dict.get("command")
    parameters_raw = intent_dict.get("parameters")
    source_id = intent_dict.get("source_id")
    priority_raw = intent_dict.get("priority")

    if not isinstance(command, str):
        raise ValueError("fixture.intent.command must be a string")
    if not isinstance(parameters_raw, dict):
        raise ValueError("fixture.intent.parameters must be a JSON object")
    if not isinstance(source_id, str):
        raise ValueError("fixture.intent.source_id must be a string")
    if isinstance(priority_raw, bool) or not isinstance(priority_raw, int):
        raise ValueError("fixture.intent.priority must be an integer")

    validation = expected_dict.get("validation")
    planning = expected_dict.get("planning")
    metadata_dropped = expected_dict.get("metadata_dropped")
    audit_created = expected_dict.get("audit_created")

    if not isinstance(validation, str):
        raise ValueError("fixture.expected.validation must be a string")
    if not isinstance(planning, str):
        raise ValueError("fixture.expected.planning must be a string")
    if not isinstance(metadata_dropped, bool):
        raise ValueError("fixture.expected.metadata_dropped must be a bool")
    if not isinstance(audit_created, bool):
        raise ValueError("fixture.expected.audit_created must be a bool")

    # parameters_raw is a dict from json.loads — cast to the JsonValue mapping boundary.
    # RawIntent will validate JSON compatibility and freeze values via freeze_json_mapping.
    parameters = cast(Mapping[str, JsonValue], parameters_raw)

    return ScenarioFixture(
        name=name,
        intent=ScenarioIntentFixture(
            command=command,
            parameters=parameters,
            source_id=source_id,
            priority=priority_raw,
        ),
        expected=ScenarioExpected(
            validation=validation,
            planning=planning,
            metadata_dropped=metadata_dropped,
            audit_created=audit_created,
        ),
    )


def run_scenario(fixture: ScenarioFixture, context: ExecutionContext) -> ScenarioResult:
    """Run one scenario fixture through the full Aegis pipeline.

    Builds a ``RawIntent`` from the fixture and the injected context, runs
    validation, then (if valid) planning and auditing.  Compares actual
    outcomes against fixture expectations to determine pass/fail status.

    This function is deterministic: the same ``fixture`` and ``context``
    always produce the same ``ScenarioResult``.

    Args:
        fixture: Scenario fixture describing the intent and expected outcomes.
        context: Caller-injected execution context for deterministic runs.

    Returns:
        A ``ScenarioResult`` containing outcomes, diagnostics, and status.
    """
    # Step 1: Construct RawIntent — boundary rejection is captured as "error".
    try:
        intent = RawIntent(
            command=fixture.intent.command,
            parameters=fixture.intent.parameters,
            source_id=fixture.intent.source_id,
            priority=fixture.intent.priority,
            context=context,
        )
    except (ValueError, TypeError) as exc:
        return ScenarioResult(
            scenario=fixture.name,
            status="failed",
            validation="error",
            planned=False,
            audited=False,
            violations=(),
            plan_step=None,
            audit=None,
            gate_status=None,
            gate_integrity_mismatch=False,
            failure_reason=f"intent_construction_failed: {exc}",
        )

    # Step 2: Validate — always runs; violations list may be empty.
    validation_result = validate_intent(intent)
    validation_str = "valid" if validation_result.is_valid else "invalid"
    violation_codes = tuple(v.code for v in validation_result.violations)

    # Step 3: Plan, audit, and gate — only when validation passed.
    plan_step: ScenarioPlanStep | None = None
    audit_summary: ScenarioAuditSummary | None = None
    gate_decision_status: str | None = None
    gate_integrity_mismatch = False
    failure_reason: str | None = None
    planned = False
    audited = False

    if validation_result.is_valid:
        try:
            plan = plan_validated_intent(validation_result)
            planned = True
            step = plan.steps[0]
            plan_step = ScenarioPlanStep(
                step_type=step.step_type.value,
                parameters=step.parameters,
            )
            audited_plan = build_audited_plan(plan)
            audited = True
            audit_summary = ScenarioAuditSummary(
                checksum=audited_plan.checksum,
                audit_id=audited_plan.audit_id,
            )
            decision = gate_audited_plan(audited_plan)
            gate_decision_status = decision.status.value
            gate_integrity_mismatch = any(
                r in (GateBlockReason.CHECKSUM_MISMATCH, GateBlockReason.AUDIT_ID_MISMATCH)
                for r in decision.reasons
            )
        except PlanningError as exc:
            failure_reason = f"planning_failed: {exc.message}"
        except Exception as exc:  # noqa: BLE001
            # SCENARIO HARNESS BOUNDARY ONLY:
            # This proof harness converts unexpected pipeline failures into a metric so
            # scenario batches can report `unexpected_exception_count`.
            # Do not copy this pattern into contracts/validation/planning/audit/gate.
            failure_reason = f"unexpected_exception: {exc!r}"

    # Derive the actual planning outcome for expectation matching.
    if not validation_result.is_valid:
        actual_planning = "skipped"
    elif planned:
        actual_planning = "valid"
    else:
        actual_planning = "invalid"

    # Evaluate expectations.
    validation_match = validation_str == fixture.expected.validation
    planning_match = actual_planning == fixture.expected.planning
    audit_match = audited == fixture.expected.audit_created
    metadata_leaked = plan_step is not None and _has_metadata_key(plan_step.parameters)
    metadata_match = not (fixture.expected.metadata_dropped and metadata_leaked)
    has_unexpected_exception = failure_reason is not None and failure_reason.startswith(
        "unexpected_exception"
    )

    status = (
        "passed"
        if (
            validation_match
            and planning_match
            and audit_match
            and metadata_match
            and not has_unexpected_exception
        )
        else "failed"
    )

    return ScenarioResult(
        scenario=fixture.name,
        status=status,
        validation=validation_str,
        planned=planned,
        audited=audited,
        violations=violation_codes,
        plan_step=plan_step,
        audit=audit_summary,
        gate_status=gate_decision_status,
        gate_integrity_mismatch=gate_integrity_mismatch,
        failure_reason=failure_reason,
    )


def run_scenarios(
    fixtures: Sequence[ScenarioFixture],
    context: ExecutionContext,
) -> tuple[list[ScenarioResult], ScenarioMetrics]:
    """Run all scenario fixtures and compute aggregate metrics.

    Each fixture is run twice with the same context to verify deterministic
    replay.  A ``deterministic_replay_failures`` increment is recorded when
    the two ``ScenarioResult`` objects differ.

    Args:
        fixtures: Ordered sequence of scenario fixtures.
        context: Caller-injected execution context for all runs.

    Returns:
        A tuple of ``(results, metrics)`` where ``results`` contains one
        ``ScenarioResult`` per fixture (in input order) and ``metrics``
        contains aggregate counts across the entire run.
    """
    results: list[ScenarioResult] = []
    scenario_count = 0
    valid_count = 0
    invalid_count = 0
    planned_count = 0
    audit_created_count = 0
    metadata_leak_count = 0
    unexpected_exception_count = 0
    deterministic_replay_failures = 0
    gate_allowed_count = 0
    gate_blocked_count = 0
    gate_integrity_mismatch_count = 0

    for fixture in fixtures:
        result = run_scenario(fixture, context)
        replay = run_scenario(fixture, context)

        if result != replay:
            deterministic_replay_failures += 1

        results.append(result)
        scenario_count += 1

        if result.validation == "valid":
            valid_count += 1
        elif result.validation == "invalid":
            invalid_count += 1

        if result.planned:
            planned_count += 1

        if result.audited:
            audit_created_count += 1

        if result.plan_step is not None and _has_metadata_key(result.plan_step.parameters):
            metadata_leak_count += 1

        if result.failure_reason is not None and result.failure_reason.startswith(
            "unexpected_exception"
        ):
            unexpected_exception_count += 1

        if result.gate_status == GateDecisionStatus.ALLOWED:
            gate_allowed_count += 1
        elif result.gate_status == GateDecisionStatus.BLOCKED:
            gate_blocked_count += 1

        if result.gate_integrity_mismatch:
            gate_integrity_mismatch_count += 1

    return results, ScenarioMetrics(
        scenario_count=scenario_count,
        valid_count=valid_count,
        invalid_count=invalid_count,
        planned_count=planned_count,
        audit_created_count=audit_created_count,
        metadata_leak_count=metadata_leak_count,
        unexpected_exception_count=unexpected_exception_count,
        deterministic_replay_failures=deterministic_replay_failures,
        gate_allowed_count=gate_allowed_count,
        gate_blocked_count=gate_blocked_count,
        gate_integrity_mismatch_count=gate_integrity_mismatch_count,
    )


def _contains_metadata(value: FrozenJsonValue) -> bool:
    """Return True when ``value`` contains a mapping key named ``"metadata"`` at any depth.

    Handles nested mappings and nested tuples (frozen JSON arrays) recursively.
    Scalar values (str, int, float, bool, None) never contain metadata keys.
    """
    if isinstance(value, Mapping):
        return _has_metadata_key(cast(Mapping[str, FrozenJsonValue], value))
    if isinstance(value, tuple):
        return any(_contains_metadata(item) for item in value)
    return False


def _has_metadata_key(params: Mapping[str, FrozenJsonValue]) -> bool:
    """Return True when a key named ``"metadata"`` appears anywhere in ``params``.

    Recurses fully into nested mappings and nested tuples (frozen JSON arrays),
    including tuples inside tuples, so that metadata buried at any depth in the
    frozen JSON structure is detected.
    """
    for key, value in params.items():
        if key == "metadata":
            return True
        if _contains_metadata(value):
            return True
    return False


def run_pipeline_scenario(scenario: ScenarioDefinition) -> ScenarioRunResult:
    """Run one ADR-0013 scenario through the real orchestrated pipeline.

    Args:
        scenario: Immutable scenario definition.

    Returns:
        A checksum-bound scenario result validated against outcome, reason,
        trace path, and approval receipt integrity.
    """
    pipeline_result = run_pipeline(
        scenario.intent,
        scenario.intent.context,
        policy_admission=_policy_admission_for_scenario(scenario),
        evaluation_time_ms=scenario.evaluation_time_ms,
        freshness_policy=scenario.freshness_policy or DEFAULT_FRESHNESS_POLICY,
        world_snapshot_evidence=scenario.world_snapshot_evidence,
        world_snapshot_trust_policy=scenario.trust_policy_config,
        attestation_verifier=scenario.verifier,
        runtime_trust_domain=scenario.runtime_trust_domain,
    )
    return _validate_with_evil_twin(scenario, pipeline_result)


def run_scenario_suite(
    suite_id: str,
    scenarios: Sequence[ScenarioDefinition],
) -> ScenarioSuiteResult:
    """Run a deterministic scenario suite and evaluate required category coverage."""
    scenario_tuple = tuple(scenarios)
    _reject_duplicate_scenario_ids(scenario_tuple)
    results = tuple(run_pipeline_scenario(scenario) for scenario in scenario_tuple)
    coverage = evaluate_scenario_coverage(scenario_tuple)
    passed_count = sum(1 for result in results if result.passed)
    failed_count = len(results) - passed_count
    passed = coverage.passed and failed_count == 0
    checksum = scenario_suite_checksum(
        suite_id=suite_id,
        passed=passed,
        results=results,
        coverage=coverage,
    )
    return ScenarioSuiteResult(
        suite_id=suite_id,
        passed=passed,
        total=len(results),
        passed_count=passed_count,
        failed_count=failed_count,
        results=results,
        coverage=coverage,
        suite_checksum=checksum,
    )


def run_canonical_scenario_suite() -> ScenarioSuiteResult:
    """Run the closed ADR-0013 canonical scenario matrix."""
    return run_scenario_suite("adr-0013-canonical", canonical_scenario_definitions())


def _policy_admission_for_scenario(scenario: ScenarioDefinition) -> PolicyAdmissionInput:
    if scenario.policy is None and scenario.capability is None:
        return PolicyAdmissionInput(PolicyAdmissionMode.DISABLED)
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=scenario.policy,
        capability=scenario.capability,
        world_snapshot=scenario.world_snapshot,
        context=_policy_context(scenario),
        evidence={
            "scenario_id": scenario.scenario_id,
            "scenario_category": scenario.category.value,
        },
    )


def _policy_context(scenario: ScenarioDefinition) -> dict[str, object]:
    context: dict[str, object] = {"scenario_id": scenario.scenario_id}
    if scenario.evaluation_time_ms is not None:
        context["requested_at_ms"] = scenario.evaluation_time_ms
    return context


def _validate_with_evil_twin(
    scenario: ScenarioDefinition,
    pipeline_result: PipelineResult,
) -> ScenarioRunResult:
    trace = pipeline_result.decision_trace
    receipt = pipeline_result.approval_receipt
    forced_outcome: PipelineOutcome | None = None
    forced_reason: str | None = None
    forced_terminal_stage: str | None = None

    if scenario.evil_twin_mutation is not EvilTwinMutation.NONE:
        trace, receipt, forced_outcome, forced_reason, forced_terminal_stage = _apply_evil_twin(
            scenario.evil_twin_mutation,
            pipeline_result,
            trace,
            receipt,
        )

    return validate_scenario_result(
        scenario,
        pipeline_result,
        decision_trace=trace,
        approval_receipt=receipt,
        forced_outcome=forced_outcome,
        forced_reason=forced_reason,
        forced_terminal_stage=forced_terminal_stage,
    )


def _apply_evil_twin(
    mutation: EvilTwinMutation,
    pipeline_result: PipelineResult,
    trace: DecisionTrace | None,
    receipt: ApprovalReceipt | None,
) -> tuple[DecisionTrace | None, ApprovalReceipt | None, PipelineOutcome, str, str]:
    if mutation is EvilTwinMutation.DIRECT_GATE_ONLY:
        if pipeline_result.audited_plan is not None:
            gate_audited_plan(pipeline_result.audited_plan)
        return trace, receipt, PipelineOutcome.BLOCKED, "DIRECT_GATE_BYPASS_REJECTED", "direct_gate"

    if receipt is not None:
        match mutation:
            case EvilTwinMutation.SAFETY_CASE_FORGED:
                object.__setattr__(receipt, "safety_case_checksum", "forged-safety-case")
            case EvilTwinMutation.ADMISSION_MISMATCH:
                object.__setattr__(receipt, "policy_admission_checksum", "forged-admission")
            case EvilTwinMutation.RECEIPT_FIELD_FORGED:
                object.__setattr__(receipt, "approval_receipt_checksum", "forged-receipt")
            case EvilTwinMutation.REPLAYED_RECEIPT:
                object.__setattr__(receipt, "pipeline_result_id", "replayed-pipeline-result")
            case EvilTwinMutation.PARTIAL_RECEIPT_OVERCLAIM:
                object.__setattr__(receipt, "policy_result_checksum", "forged-policy-result")
            case (
                EvilTwinMutation.NONE
                | EvilTwinMutation.DIRECT_GATE_ONLY
                | EvilTwinMutation.TRACE_CHECKSUM_MISMATCH
                | EvilTwinMutation.CONFUSABLE_STAGE_NAME
            ):
                pass
    if trace is not None:
        match mutation:
            case EvilTwinMutation.TRACE_CHECKSUM_MISMATCH:
                object.__setattr__(trace, "trace_checksum", "0" * 64)
            case EvilTwinMutation.CONFUSABLE_STAGE_NAME:
                object.__setattr__(trace.steps[0], "stage_name", "raw_intent ")
            case (
                EvilTwinMutation.NONE
                | EvilTwinMutation.DIRECT_GATE_ONLY
                | EvilTwinMutation.SAFETY_CASE_FORGED
                | EvilTwinMutation.ADMISSION_MISMATCH
                | EvilTwinMutation.RECEIPT_FIELD_FORGED
                | EvilTwinMutation.REPLAYED_RECEIPT
                | EvilTwinMutation.PARTIAL_RECEIPT_OVERCLAIM
            ):
                pass
    return (
        trace,
        receipt,
        PipelineOutcome.ERROR,
        "APPROVAL_RECEIPT_INTEGRITY_FAILED",
        "receipt_validation",
    )


def _reject_duplicate_scenario_ids(scenarios: tuple[ScenarioDefinition, ...]) -> None:
    seen: set[str] = set()
    duplicates: list[str] = []
    for scenario in scenarios:
        if scenario.scenario_id in seen:
            duplicates.append(scenario.scenario_id)
        seen.add(scenario.scenario_id)
    if duplicates:
        raise ValueError(f"duplicate scenario_id values: {','.join(sorted(duplicates))}")
