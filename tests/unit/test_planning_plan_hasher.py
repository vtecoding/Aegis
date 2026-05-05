"""Unit tests for deterministic planning-v1 plan hashing."""

import inspect
import re
from datetime import UTC, datetime

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.planning import CommandStep, CommandStepType
from aegis.planning import plan_hasher
from aegis.planning.plan_hasher import stable_plan_id


def make_context(request_id: str = "request-123") -> ExecutionContext:
    """Return a deterministic context for plan hasher tests."""
    return ExecutionContext(request_id, datetime(2026, 5, 4, tzinfo=UTC), "policy-v1", "run-1")


def make_intent(
    command: str = "inspect",
    parameters: dict[str, object] | None = None,
    request_id: str = "request-123",
) -> RawIntent:
    """Return a raw intent for plan hasher tests."""
    return RawIntent(
        command,
        parameters or {"target": "panel-a"},
        "operator-1",
        5,
        make_context(request_id),
    )


def make_step(parameters: dict[str, object] | None = None) -> CommandStep:
    """Return a command step for plan hasher tests."""
    return CommandStep(CommandStepType.INSPECT, parameters or {"target": "panel-a"}, 0)


def test_stable_plan_id_same_intent_and_steps_produces_same_id() -> None:
    """Identical explicit inputs produce identical plan IDs."""
    intent = make_intent()
    steps = (make_step(),)

    assert stable_plan_id(intent, steps) == stable_plan_id(intent, steps)


def test_stable_plan_id_changes_when_command_changes() -> None:
    """The intent command participates in plan ID hashing."""
    first = make_intent("inspect", {"target": "panel-a"})
    second = make_intent("wait", {"target": "panel-a"})
    steps = (make_step(),)

    assert stable_plan_id(first, steps) != stable_plan_id(second, steps)


def test_stable_plan_id_changes_when_parameters_change() -> None:
    """Intent parameters participate in plan ID hashing."""
    first = make_intent("inspect", {"target": "panel-a"})
    second = make_intent("inspect", {"target": "panel-b"})
    steps = (make_step(),)

    assert stable_plan_id(first, steps) != stable_plan_id(second, steps)


def test_stable_plan_id_changes_when_context_request_id_changes() -> None:
    """Execution context request_id participates in plan ID hashing."""
    first = make_intent(request_id="request-123")
    second = make_intent(request_id="request-456")
    steps = (make_step(),)

    assert stable_plan_id(first, steps) != stable_plan_id(second, steps)


def test_stable_plan_id_is_stable_for_reordered_mapping_keys() -> None:
    """Canonical JSON serialization makes mapping key order irrelevant."""
    first_intent = make_intent("inspect", {"target": "panel-a", "extra": {"b": 2, "a": 1}})
    second_intent = make_intent("inspect", {"extra": {"a": 1, "b": 2}, "target": "panel-a"})
    first_steps = (make_step({"target": "panel-a", "metadata": {"b": 2, "a": 1}}),)
    second_steps = (make_step({"metadata": {"a": 1, "b": 2}, "target": "panel-a"}),)

    assert stable_plan_id(first_intent, first_steps) == stable_plan_id(second_intent, second_steps)


def test_stable_plan_id_is_lowercase_sha256_hex() -> None:
    """Plan IDs are lowercase 64-character SHA-256 hex strings."""
    plan_id = stable_plan_id(make_intent(), (make_step(),))

    assert re.fullmatch(r"[0-9a-f]{64}", plan_id) is not None


def test_stable_plan_id_does_not_use_python_hash() -> None:
    """Plan hashing must not use Python's process-seeded hash function."""
    source = inspect.getsource(plan_hasher)

    assert re.search(r"(?<![A-Za-z_])hash\(", source) is None
