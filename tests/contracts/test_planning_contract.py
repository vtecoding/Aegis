"""Contract tests for planning-v1 command plan contracts."""

from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.planning import CommandPlan, CommandStep, CommandStepType


def make_context() -> ExecutionContext:
    """Return a deterministic context for planning contract tests."""
    return ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")


def make_intent() -> RawIntent:
    """Return a valid raw intent for planning contract tests."""
    return RawIntent("stop", {}, "operator-1", 5, make_context())


def make_step(sequence: int = 0) -> CommandStep:
    """Return a valid command step for planning contract tests."""
    return CommandStep(CommandStepType.STOP, {}, sequence)


def test_command_step_accepts_valid_step() -> None:
    """CommandStep accepts a valid step type, parameter mapping, and sequence."""
    step = CommandStep(CommandStepType.WAIT, {"duration_ms": 1_000}, 0)

    assert step.step_type is CommandStepType.WAIT
    assert step.parameters["duration_ms"] == 1_000
    assert step.sequence == 0


def test_command_step_rejects_negative_sequence() -> None:
    """CommandStep sequences must be zero or greater."""
    with pytest.raises(ValueError, match="sequence"):
        CommandStep(CommandStepType.STOP, {}, -1)


@pytest.mark.parametrize("sequence", [True, "0"])
def test_command_step_rejects_non_integer_sequence(sequence: object) -> None:
    """CommandStep sequence values must be real integers, not bools or strings."""
    with pytest.raises(ValueError, match="sequence"):
        CommandStep(CommandStepType.STOP, {}, sequence)


def test_command_step_freezes_parameters() -> None:
    """CommandStep recursively freezes JSON-compatible parameters."""
    step = CommandStep(
        CommandStepType.INSPECT,
        {"target": "panel-a", "metadata": {"items": [1, {"status": "before"}]}},
        0,
    )

    metadata = step.parameters["metadata"]
    assert isinstance(metadata, Mapping)
    items = metadata["items"]
    assert isinstance(items, tuple)

    with pytest.raises(TypeError):
        step.parameters["target"] = "panel-b"


def test_command_step_rejects_non_enum_step_type() -> None:
    """CommandStep rejects raw strings as step types."""
    with pytest.raises(ValueError, match="step_type"):
        CommandStep("move", {}, 0)


def test_command_plan_accepts_valid_plan() -> None:
    """CommandPlan accepts a non-empty ID, original intent, and ordered steps."""
    step = make_step()
    plan = CommandPlan("plan-123", make_intent(), [step])

    assert plan.plan_id == "plan-123"
    assert plan.steps == (step,)


def test_command_plan_rejects_empty_plan_id() -> None:
    """CommandPlan requires a non-empty plan_id."""
    with pytest.raises(ValueError, match="plan_id"):
        CommandPlan("", make_intent(), [make_step()])


def test_command_plan_rejects_empty_steps() -> None:
    """CommandPlan requires at least one command step."""
    with pytest.raises(ValueError, match="steps"):
        CommandPlan("plan-123", make_intent(), [])


def test_command_plan_rejects_non_contiguous_sequences() -> None:
    """CommandPlan requires step sequences to be exactly 0..len(steps)-1."""
    with pytest.raises(ValueError, match="sequence"):
        CommandPlan("plan-123", make_intent(), [make_step(sequence=1)])


def test_command_plan_is_immutable() -> None:
    """CommandPlan fields cannot be reassigned after construction."""
    plan = CommandPlan("plan-123", make_intent(), [make_step()])

    with pytest.raises(FrozenInstanceError):
        plan.plan_id = "changed"
