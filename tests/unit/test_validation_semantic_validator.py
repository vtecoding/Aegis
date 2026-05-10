"""Unit tests for validation semantic checks."""

from datetime import UTC, datetime

from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.validation.aegis_semantic_validator import validate_intent, validate_semantics


def make_context() -> ExecutionContext:
    """Return a deterministic context for semantic validator tests."""
    return ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")


def make_intent(command: str, parameters: dict[str, object] | None = None) -> RawIntent:
    """Return a raw intent for semantic validator tests."""
    return RawIntent(command, parameters or {}, "operator-1", 5, make_context())


def semantic_codes(command: str, parameters: dict[str, object] | None = None) -> tuple[str, ...]:
    """Return semantic violation codes for an intent."""
    result = validate_semantics(make_intent(command, parameters))
    return tuple(violation.code for violation in result.violations)


def test_validate_semantics_accepts_valid_stop() -> None:
    """stop accepts empty parameters."""
    result = validate_semantics(make_intent("stop"))

    assert result.is_valid is True


def test_validate_semantics_rejects_stop_with_parameters() -> None:
    """stop does not accept command parameters."""
    assert semantic_codes("stop", {"target": "zone-a"}) == ("unexpected_parameters",)


def test_validate_semantics_accepts_valid_wait() -> None:
    """wait accepts a positive bounded integer duration."""
    result = validate_semantics(make_intent("wait", {"duration_ms": 1_000}))

    assert result.is_valid is True


def test_validate_semantics_rejects_wait_missing_duration_ms() -> None:
    """wait requires duration_ms."""
    assert semantic_codes("wait") == ("missing_parameter",)


def test_validate_semantics_rejects_wait_duration_bool() -> None:
    """duration_ms must not be bool."""
    assert semantic_codes("wait", {"duration_ms": True}) == ("bool_not_allowed_for_integer",)


def test_validate_semantics_rejects_wait_duration_not_positive() -> None:
    """duration_ms must be greater than zero."""
    assert semantic_codes("wait", {"duration_ms": 0}) == ("invalid_parameter_value",)


def test_validate_semantics_rejects_wait_duration_above_limit() -> None:
    """duration_ms must be within the explicit wait limit."""
    assert semantic_codes("wait", {"duration_ms": 60_001}) == ("invalid_parameter_value",)


def test_validate_semantics_accepts_valid_inspect() -> None:
    """inspect accepts a non-empty string target."""
    result = validate_semantics(make_intent("inspect", {"target": "panel-a"}))

    assert result.is_valid is True


def test_validate_semantics_rejects_inspect_missing_target() -> None:
    """inspect requires target."""
    assert semantic_codes("inspect") == ("missing_parameter",)


def test_validate_semantics_rejects_inspect_empty_target() -> None:
    """inspect target must be non-empty after trimming."""
    assert semantic_codes("inspect", {"target": "   "}) == ("invalid_parameter_value",)


def test_validate_semantics_accepts_valid_move() -> None:
    """move accepts an abstract target object with finite x and y numbers."""
    result = validate_semantics(make_intent("move", {"target": {"x": 1, "y": 2.5}}))

    assert result.is_valid is True


def test_validate_semantics_rejects_move_missing_target() -> None:
    """move requires target."""
    assert semantic_codes("move") == ("missing_parameter",)


def test_validate_semantics_rejects_move_target_not_object() -> None:
    """move target must be a JSON object."""
    assert semantic_codes("move", {"target": "zone-a"}) == ("invalid_parameter_type",)


def test_validate_semantics_rejects_move_missing_x_and_y() -> None:
    """move target requires x and y fields."""
    assert semantic_codes("move", {"target": {}}) == ("missing_parameter", "missing_parameter")


def test_validate_semantics_rejects_move_x_and_y_bool() -> None:
    """move target x and y must not be bool."""
    assert semantic_codes("move", {"target": {"x": True, "y": False}}) == (
        "bool_not_allowed_for_number",
        "bool_not_allowed_for_number",
    )


def test_validate_semantics_rejects_unsupported_command() -> None:
    """Unsupported commands are semantic violations."""
    assert semantic_codes("dance", {}) == ("unsupported_command",)


def test_validate_intent_orders_schema_violations_before_semantic_violations() -> None:
    """Combined validation reports schema failures before semantic failures."""
    intent = make_intent("dance", {"payload": "x" * 10_001})
    result = validate_intent(intent)

    assert tuple(violation.code for violation in result.violations) == (
        "string_length_exceeded",
        "unsupported_command",
    )


def test_validate_intent_same_input_produces_same_result() -> None:
    """Combined validation is deterministic for the same intent."""
    intent = make_intent("wait", {"duration_ms": 100})

    assert validate_intent(intent) == validate_intent(intent)


def test_validate_intent_does_not_mutate_raw_intent() -> None:
    """Combined validation does not mutate caller-owned contract data."""
    intent = make_intent("move", {"target": {"x": 1, "y": 2}})
    before = intent.parameters

    validate_intent(intent)

    assert intent.parameters == before


def test_validate_semantics_rejects_wait_duration_non_integer_type() -> None:
    """duration_ms must be an integer; floats are not accepted."""
    assert semantic_codes("wait", {"duration_ms": 1000.5}) == ("invalid_parameter_type",)


def test_validate_semantics_rejects_inspect_target_non_string() -> None:
    """inspect target must be a string; integers are not accepted."""
    assert semantic_codes("inspect", {"target": 42}) == ("invalid_parameter_type",)


def test_validate_semantics_rejects_move_coordinate_non_numeric() -> None:
    """move target x and y must be numeric; strings are not accepted."""
    assert semantic_codes("move", {"target": {"x": "left", "y": 1}}) == ("invalid_parameter_type",)
