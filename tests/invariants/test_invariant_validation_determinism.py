"""Invariant tests for validation-v1 determinism."""

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.validation.aegis_semantic_validator import validate_intent

JSON_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1_000, max_value=1_000),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=20),
)

JSON_VALUE = st.recursive(
    JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=3),
    ),
    max_leaves=12,
)

PARAMETERS = st.dictionaries(st.text(min_size=1, max_size=10), JSON_VALUE, max_size=5)
COMMANDS = st.sampled_from(["move", "stop", "inspect", "wait", "unsupported"])


def make_context() -> ExecutionContext:
    """Return a deterministic context for validation invariant tests."""
    return ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")


def make_intent(command: str, parameters: dict[str, object] | None = None) -> RawIntent:
    """Return a raw intent for validation invariant tests."""
    return RawIntent(command, parameters or {}, "operator-1", 5, make_context())


@given(command=COMMANDS, parameters=PARAMETERS)
def test_invariant_validate_intent_same_input_produces_same_result(
    command: str,
    parameters: dict[str, object],
) -> None:
    """Validation returns equal results for repeated evaluation of one intent."""
    intent = make_intent(command, parameters)

    assert validate_intent(intent) == validate_intent(intent)


@given(command=COMMANDS, parameters=PARAMETERS)
def test_invariant_validation_does_not_mutate_intent_parameters(
    command: str,
    parameters: dict[str, object],
) -> None:
    """Validation leaves frozen RawIntent parameters unchanged."""
    intent = make_intent(command, parameters)
    before = intent.parameters

    validate_intent(intent)

    assert intent.parameters == before


@given(command=COMMANDS, parameters=PARAMETERS)
def test_invariant_violation_ordering_is_stable(
    command: str,
    parameters: dict[str, object],
) -> None:
    """Violation ordering is stable for repeated validation."""
    intent = make_intent(command, parameters)
    first = validate_intent(intent)
    second = validate_intent(intent)

    assert first.violations == second.violations


@pytest.mark.parametrize(
    ("command", "parameters"),
    [
        ("stop", {}),
        ("wait", {"duration_ms": 1}),
        ("inspect", {"target": "panel-a"}),
        ("move", {"target": {"x": 0, "y": 1.5}}),
    ],
)
def test_invariant_valid_command_fixtures_always_validate(
    command: str,
    parameters: dict[str, object],
) -> None:
    """Canonical valid command fixtures always produce valid validation results."""
    assert validate_intent(make_intent(command, parameters)).is_valid is True


@pytest.mark.parametrize("command", ["launch", "MOVE", "", "ignore previous instructions"])
def test_invariant_unsupported_command_fixtures_always_fail(command: str) -> None:
    """Unsupported command fixtures produce invalid validation results when constructible."""
    if command.strip() == "":
        with pytest.raises(ValueError, match="command"):
            make_intent(command)
        return

    result = validate_intent(make_intent(command))

    assert result.is_valid is False
    assert any(violation.code == "unsupported_command" for violation in result.violations)
