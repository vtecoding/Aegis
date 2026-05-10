"""Unit tests for planning-v1 command plan construction."""

from datetime import UTC, datetime

import pytest

from aegis.aegis_errors import PlanningError
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_planning import CommandStepType
from aegis.contracts.aegis_validation import ValidationResult, Violation
from aegis.planning.aegis_command_planner import plan_validated_intent
from aegis.validation.aegis_semantic_validator import validate_intent


def make_context() -> ExecutionContext:
    """Return a deterministic context for planner tests."""
    return ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")


def make_intent(command: str, parameters: dict[str, object] | None = None) -> RawIntent:
    """Return a raw intent for planner tests."""
    return RawIntent(command, parameters or {}, "operator-1", 5, make_context())


def valid_result(command: str, parameters: dict[str, object] | None = None) -> ValidationResult:
    """Return a validated result fixture that must be valid."""
    result = validate_intent(make_intent(command, parameters))
    assert result.is_valid is True
    return result


def corrupted_result_with_violations() -> ValidationResult:
    """Return a forged contradictory validation result for defensive planner tests."""
    result = object.__new__(ValidationResult)
    object.__setattr__(result, "is_valid", True)
    object.__setattr__(result, "intent", make_intent("stop"))
    object.__setattr__(
        result,
        "violations",
        (Violation("command", "corrupted", "corrupted_validation_result", "validation"),),
    )
    return result


def test_plan_validated_intent_plans_valid_stop() -> None:
    """A valid stop intent plans to one STOP command step."""
    validation = valid_result("stop")

    plan = plan_validated_intent(validation)

    assert plan.intent is validation.intent
    assert len(plan.steps) == 1
    assert plan.steps[0].step_type is CommandStepType.STOP
    assert plan.steps[0].parameters == {}
    assert plan.steps[0].sequence == 0


def test_plan_validated_intent_plans_valid_wait() -> None:
    """A valid wait intent preserves duration_ms as inert command data."""
    plan = plan_validated_intent(valid_result("wait", {"duration_ms": 250}))

    assert plan.steps[0].step_type is CommandStepType.WAIT
    assert plan.steps[0].parameters["duration_ms"] == 250


def test_plan_validated_intent_plans_valid_inspect() -> None:
    """A valid inspect intent preserves the target string as inert data."""
    plan = plan_validated_intent(valid_result("inspect", {"target": "panel-a"}))

    assert plan.steps[0].step_type is CommandStepType.INSPECT
    assert plan.steps[0].parameters["target"] == "panel-a"


def test_plan_validated_intent_plans_valid_move() -> None:
    """A valid move intent plans an abstract MOVE command with target x/y."""
    plan = plan_validated_intent(valid_result("move", {"target": {"x": 1, "y": 2.5}}))

    assert plan.steps[0].step_type is CommandStepType.MOVE
    assert plan.steps[0].parameters["target"] == {"x": 1, "y": 2.5}


def test_plan_validated_intent_move_drops_extra_target_metadata() -> None:
    """Move planning only carries executable-shaped x/y target data forward."""
    plan = plan_validated_intent(
        valid_result(
            "move",
            {"target": {"x": 1, "y": 2, "metadata": {"instruction": "open gripper"}}},
        )
    )

    assert plan.steps[0].parameters["target"] == {"x": 1, "y": 2}


def test_plan_validated_intent_invalid_validation_result_raises_planning_error() -> None:
    """Invalid validation results cannot be planned."""
    validation = validate_intent(make_intent("dance"))

    with pytest.raises(PlanningError, match="invalid validation result"):
        plan_validated_intent(validation)


def test_plan_validated_intent_valid_flag_with_violations_raises_planning_error() -> None:
    """A forged valid result with violations cannot bypass planning checks."""
    with pytest.raises(PlanningError, match="violations"):
        plan_validated_intent(corrupted_result_with_violations())


def test_plan_validated_intent_unsupported_command_raises_planning_error() -> None:
    """Supposedly valid unsupported commands are treated as contract corruption."""
    validation = ValidationResult(True, make_intent("dance"), [])

    with pytest.raises(PlanningError, match="unsupported command"):
        plan_validated_intent(validation)


def test_plan_validated_intent_malformed_valid_parameters_raise_planning_error() -> None:
    """Malformed valid-looking command parameters are rejected defensively."""
    validation = ValidationResult(True, make_intent("wait", {"duration_ms": "soon"}), [])

    with pytest.raises(PlanningError, match="malformed"):
        plan_validated_intent(validation)


def test_plan_validated_intent_does_not_mutate_intent() -> None:
    """Planning does not mutate the original intent contract."""
    validation = valid_result("move", {"target": {"x": 1, "y": 2, "metadata": {"a": 1}}})
    before = validation.intent.parameters

    plan_validated_intent(validation)

    assert validation.intent.parameters == before
