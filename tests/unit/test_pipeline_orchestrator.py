"""Unit tests: run_pipeline orchestrates the full Phase 1 pipeline correctly."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.aegis_errors import PlanningError
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.aegis_policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline


def make_context() -> ExecutionContext:
    return ExecutionContext("unit-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def make_valid_intent(context: ExecutionContext) -> RawIntent:
    return RawIntent(
        command="stop",
        parameters={},
        source_id="unit-test",
        priority=5,
        context=context,
    )


def make_invalid_intent(context: ExecutionContext) -> RawIntent:
    return RawIntent(
        command="launch_missiles",
        parameters={},
        source_id="unit-test",
        priority=5,
        context=context,
    )


def make_allowing_admission() -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=Policy(
            "policy-unit",
            "v1",
            [
                PolicyRule(
                    "rule-1",
                    "locomotion.translation",
                    [Constraint("max_velocity", {"max_mps": 1.0})],
                )
            ],
        ),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=fresh_world_snapshot(),
        context=fresh_policy_context(),
    )


def trusted_kwargs(admission: PolicyAdmissionInput) -> dict[str, object]:
    assert admission.world_snapshot is not None
    return trusted_pipeline_kwargs(admission.world_snapshot)


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_run_pipeline_valid_stop_without_policy_returns_blocked() -> None:
    context = make_context()
    intent = make_valid_intent(context)
    result = run_pipeline(intent, context)

    assert isinstance(result, PipelineResult)
    assert result.outcome == PipelineOutcome.BLOCKED
    assert result.validation_result is not None
    assert result.validation_result.is_valid
    assert result.plan is not None
    assert result.audited_plan is not None
    assert result.gate_decision is None


def test_run_pipeline_valid_move_returns_allowed() -> None:
    context = make_context()
    intent = RawIntent(
        command="move",
        parameters={"target": {"x": 1, "y": 2}},
        source_id="unit-test",
        priority=3,
        context=context,
    )
    admission = make_allowing_admission()
    result = run_pipeline(
        intent,
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_kwargs(admission),
    )
    assert result.outcome == PipelineOutcome.ALLOWED


def test_run_pipeline_invalid_command_returns_invalid() -> None:
    context = make_context()
    intent = make_invalid_intent(context)
    result = run_pipeline(intent, context)

    assert result.outcome == PipelineOutcome.INVALID
    assert result.validation_result is not None
    assert not result.validation_result.is_valid
    assert result.plan is None
    assert result.audited_plan is None
    assert result.gate_decision is None


def test_run_pipeline_invalid_never_reaches_gate() -> None:
    context = make_context()
    intent = make_invalid_intent(context)
    result = run_pipeline(intent, context)

    assert result.gate_decision is None


# ---------------------------------------------------------------------------
# All four supported commands produce ALLOWED
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command, parameters",
    [
        ("stop", {}),
        ("wait", {"duration_ms": 200}),
        ("inspect", {"target": "front_sensor"}),
        ("move", {"target": {"x": 0, "y": 0}}),
    ],
)
def test_run_pipeline_all_valid_commands_return_allowed(command: str, parameters: dict) -> None:
    context = make_context()
    intent = RawIntent(
        command=command,
        parameters=parameters,
        source_id="unit-test",
        priority=5,
        context=context,
    )
    admission = make_allowing_admission()
    result = run_pipeline(
        intent,
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_kwargs(admission),
    )
    assert result.outcome == PipelineOutcome.ALLOWED


# ---------------------------------------------------------------------------
# AegisError propagation (planning errors should propagate, not be swallowed)
# ---------------------------------------------------------------------------


def test_run_pipeline_planning_error_propagates() -> None:
    context = make_context()
    intent = make_valid_intent(context)

    with patch("aegis.pipeline.aegis_orchestrator.plan_validated_intent") as mock_plan:
        mock_plan.side_effect = PlanningError(
            message="forced planning failure",
            layer="planning",
            context={},
        )
        with pytest.raises(PlanningError):
            run_pipeline(intent, context)


# ---------------------------------------------------------------------------
# Unexpected exception produces ERROR outcome
# ---------------------------------------------------------------------------


def test_run_pipeline_unexpected_exception_in_validate_returns_error() -> None:
    context = make_context()
    intent = make_valid_intent(context)

    with patch("aegis.pipeline.aegis_orchestrator.validate_intent") as mock_validate:
        mock_validate.side_effect = RuntimeError("simulated framework failure")
        result = run_pipeline(intent, context)

    assert result.outcome == PipelineOutcome.ERROR
    assert result.validation_result is None
    assert result.plan is None
    assert result.audited_plan is None
    assert result.gate_decision is None


def test_run_pipeline_unexpected_exception_in_plan_returns_error() -> None:
    context = make_context()
    intent = make_valid_intent(context)

    with patch("aegis.pipeline.aegis_orchestrator.plan_validated_intent") as mock_plan:
        mock_plan.side_effect = RuntimeError("simulated planning framework failure")
        result = run_pipeline(intent, context)

    assert result.outcome == PipelineOutcome.ERROR
    assert result.validation_result is not None
    assert result.plan is None
    assert result.audited_plan is None
    assert result.gate_decision is None


def test_run_pipeline_unexpected_exception_in_audit_returns_error() -> None:
    context = make_context()
    intent = make_valid_intent(context)

    with patch("aegis.pipeline.aegis_orchestrator.build_audited_plan") as mock_audit:
        mock_audit.side_effect = RuntimeError("simulated audit framework failure")
        result = run_pipeline(intent, context)

    assert result.outcome == PipelineOutcome.ERROR
    assert result.validation_result is not None
    assert result.plan is not None
    assert result.audited_plan is None
    assert result.gate_decision is None


def test_run_pipeline_unexpected_exception_in_gate_returns_error() -> None:
    context = make_context()
    intent = make_valid_intent(context)

    with patch("aegis.pipeline.aegis_orchestrator.gate_audited_plan") as mock_gate:
        mock_gate.side_effect = RuntimeError("simulated gate framework failure")
        admission = make_allowing_admission()
        result = run_pipeline(
            intent,
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **trusted_kwargs(admission),
        )

    assert result.outcome == PipelineOutcome.ERROR
    assert result.validation_result is not None
    assert result.plan is not None
    assert result.audited_plan is not None
    assert result.gate_decision is None


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_run_pipeline_same_inputs_produce_identical_results() -> None:
    context = make_context()
    intent = make_valid_intent(context)

    result_a = run_pipeline(intent, context)
    result_b = run_pipeline(intent, context)

    assert result_a == result_b


def test_run_pipeline_does_not_mutate_raw_intent() -> None:
    context = make_context()
    intent = RawIntent(
        command="move",
        parameters={"target": {"x": 5, "y": 10}},
        source_id="unit-test",
        priority=7,
        context=context,
    )
    original_command = intent.command
    original_params = dict(intent.parameters)

    run_pipeline(intent, context)

    assert intent.command == original_command
    assert dict(intent.parameters) == original_params
