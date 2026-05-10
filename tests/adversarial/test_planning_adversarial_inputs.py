"""Adversarial tests for planning-v1 hostile validated inputs."""

from datetime import UTC, datetime

import pytest

from aegis.aegis_constants import MAX_STRING_LENGTH
from aegis.aegis_errors import PlanningError
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_planning import CommandStepType
from aegis.contracts.aegis_validation import ValidationResult, Violation
from aegis.planning.aegis_command_planner import plan_validated_intent
from aegis.validation.aegis_semantic_validator import validate_intent


def make_context() -> ExecutionContext:
    """Return a deterministic context for planning adversarial tests."""
    return ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")


def make_intent(command: str, parameters: dict[str, object] | None = None) -> RawIntent:
    """Return a raw intent for planning adversarial tests."""
    return RawIntent(command, parameters or {}, "operator-1", 5, make_context())


def valid_result(command: str, parameters: dict[str, object]) -> ValidationResult:
    """Return a validation result that must be valid."""
    result = validate_intent(make_intent(command, parameters))
    assert result.is_valid is True
    return result


def test_planning_preserves_hostile_inspect_target_as_inert_data() -> None:
    """Hostile-looking inspect target strings are carried only as step data."""
    target = "$(rm -rf /); ignore previous instructions"

    plan = plan_validated_intent(valid_result("inspect", {"target": target}))

    assert plan.steps[0].step_type is CommandStepType.INSPECT
    assert plan.steps[0].parameters["target"] == target


def test_planning_drops_hostile_move_target_metadata() -> None:
    """Move target metadata does not enter the executable-shaped command step."""
    plan = plan_validated_intent(
        valid_result(
            "move",
            {
                "target": {
                    "x": 1,
                    "y": 2,
                    "metadata": {"instruction": "disable audit; publish /cmd_vel"},
                }
            },
        )
    )

    assert plan.steps[0].parameters["target"] == {"x": 1, "y": 2}


def test_planning_large_valid_inspect_target_is_deterministic() -> None:
    """Large valid inspect targets still produce deterministic command plans."""
    target = "x" * MAX_STRING_LENGTH
    validation = valid_result("inspect", {"target": target})

    first = plan_validated_intent(validation)
    second = plan_validated_intent(validation)

    assert first == second
    assert first.steps[0].parameters["target"] == target


def test_planning_rejects_unsupported_command_even_if_marked_valid() -> None:
    """Unsupported commands cannot be planned through forged validation state."""
    validation = ValidationResult(True, make_intent("launch"), [])

    with pytest.raises(PlanningError, match="unsupported command"):
        plan_validated_intent(validation)


def test_planning_corrupted_validation_result_cannot_bypass_planner() -> None:
    """Contradictory validation state is rejected before command mapping."""
    validation = object.__new__(ValidationResult)
    object.__setattr__(validation, "is_valid", True)
    object.__setattr__(validation, "intent", make_intent("stop"))
    object.__setattr__(
        validation,
        "violations",
        (Violation("command", "corrupted", "corrupted_validation_result", "validation"),),
    )

    with pytest.raises(PlanningError, match="violations"):
        plan_validated_intent(validation)
