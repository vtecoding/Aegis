"""Contract tests for RawIntent."""

from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent


def make_context() -> ExecutionContext:
    """Return a valid deterministic execution context for intent tests."""
    return ExecutionContext(
        request_id="request-123",
        submitted_at=datetime(2026, 5, 4, tzinfo=UTC),
        policy_version="policy-v1",
    )


def test_raw_intent_accepts_valid_raw_intent() -> None:
    """RawIntent accepts valid boundary data."""
    intent = RawIntent(
        command="inspect_area",
        parameters={"zone": "A", "limits": [1, 2, 3]},
        source_id="operator-1",
        priority=5,
        context=make_context(),
    )

    assert intent.command == "inspect_area"
    assert intent.source_id == "operator-1"
    assert intent.priority == 5
    assert intent.context == make_context()


def test_raw_intent_canonicalizes_whitespace_command() -> None:
    """Whitespace-padded commands are stripped and stored canonically."""
    intent = RawIntent(" inspect_area ", {}, "operator-1", 5, make_context())

    assert intent.command == "inspect_area"


def test_raw_intent_canonicalizes_whitespace_source_id() -> None:
    """Whitespace-padded source identifiers are stripped and stored canonically."""
    intent = RawIntent("inspect_area", {}, " operator-1 ", 5, make_context())

    assert intent.source_id == "operator-1"


@pytest.mark.parametrize("command", ["", "   ", "\t\n"])
def test_raw_intent_rejects_empty_command(command: str) -> None:
    """command must be non-empty after stripping whitespace."""
    with pytest.raises(ValueError, match="command"):
        RawIntent(command, {}, "operator-1", 5, make_context())


@pytest.mark.parametrize("source_id", ["", "   ", "\t\n"])
def test_raw_intent_rejects_empty_source_id(source_id: str) -> None:
    """source_id must be non-empty after stripping whitespace."""
    with pytest.raises(ValueError, match="source_id"):
        RawIntent("inspect_area", {}, source_id, 5, make_context())


def test_raw_intent_rejects_priority_below_one() -> None:
    """priority cannot be lower than 1."""
    with pytest.raises(ValueError, match="priority"):
        RawIntent("inspect_area", {}, "operator-1", 0, make_context())


def test_raw_intent_rejects_priority_above_ten() -> None:
    """priority cannot be higher than 10."""
    with pytest.raises(ValueError, match="priority"):
        RawIntent("inspect_area", {}, "operator-1", 11, make_context())


def test_raw_intent_rejects_bool_priority() -> None:
    """bool is not accepted as an integer priority."""
    with pytest.raises(ValueError, match="bool"):
        RawIntent("inspect_area", {}, "operator-1", True, make_context())


def test_raw_intent_rejects_non_json_parameters() -> None:
    """parameters must be a JSON-compatible object."""
    with pytest.raises(ValueError, match="JSON-compatible"):
        RawIntent("inspect_area", {"bad": object()}, "operator-1", 5, make_context())


def test_raw_intent_protects_against_caller_parameter_mutation() -> None:
    """Caller mutations after construction do not alter stored parameters."""
    parameters = {"nested": {"items": [1, {"status": "before"}]}}

    intent = RawIntent("inspect_area", parameters, "operator-1", 5, make_context())
    parameters["nested"]["items"][1]["status"] = "after"

    nested = intent.parameters["nested"]
    assert isinstance(nested, Mapping)
    items = nested["items"]
    assert isinstance(items, tuple)
    item = items[1]
    assert isinstance(item, Mapping)
    assert item["status"] == "before"


def test_raw_intent_stores_parameters_immutably() -> None:
    """Stored parameter mappings are read-only."""
    intent = RawIntent("inspect_area", {"zone": "A"}, "operator-1", 5, make_context())

    with pytest.raises(TypeError):
        intent.parameters["zone"] = "B"


def test_raw_intent_is_immutable() -> None:
    """RawIntent fields cannot be reassigned after construction."""
    intent = RawIntent("inspect_area", {}, "operator-1", 5, make_context())

    with pytest.raises(FrozenInstanceError):
        intent.command = "move"
