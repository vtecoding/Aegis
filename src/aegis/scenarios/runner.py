"""Scenario Runner v1: runs structured fixtures through the Aegis pipeline."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from aegis.audit import build_audited_plan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.json_types import FrozenJsonValue, JsonValue
from aegis.errors import PlanningError
from aegis.planning import plan_validated_intent
from aegis.scenarios.models import (
    ScenarioAuditSummary,
    ScenarioExpected,
    ScenarioFixture,
    ScenarioIntentFixture,
    ScenarioMetrics,
    ScenarioPlanStep,
    ScenarioResult,
)
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
            failure_reason=f"intent_construction_failed: {exc}",
        )

    # Step 2: Validate — always runs; violations list may be empty.
    validation_result = validate_intent(intent)
    validation_str = "valid" if validation_result.is_valid else "invalid"
    violation_codes = tuple(v.code for v in validation_result.violations)

    # Step 3: Plan and audit — only when validation passed.
    plan_step: ScenarioPlanStep | None = None
    audit_summary: ScenarioAuditSummary | None = None
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
        except PlanningError as exc:
            failure_reason = f"planning_failed: {exc.message}"
        except Exception as exc:  # noqa: BLE001
            # Captured to prevent harness crashes; counted in unexpected_exception_count.
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

    return results, ScenarioMetrics(
        scenario_count=scenario_count,
        valid_count=valid_count,
        invalid_count=invalid_count,
        planned_count=planned_count,
        audit_created_count=audit_created_count,
        metadata_leak_count=metadata_leak_count,
        unexpected_exception_count=unexpected_exception_count,
        deterministic_replay_failures=deterministic_replay_failures,
    )


def _has_metadata_key(params: Mapping[str, FrozenJsonValue]) -> bool:
    """Return True when a key named ``"metadata"`` appears anywhere in ``params``.

    Recurses into nested mappings so that metadata buried at any depth is
    detected.  Only mapping keys are inspected; tuple (list) values are not
    recursed because metadata injection targets object keys, not array elements.
    """
    for key, value in params.items():
        if key == "metadata":
            return True
        if isinstance(value, Mapping) and _has_metadata_key(
            cast(Mapping[str, FrozenJsonValue], value)
        ):
            return True
    return False
