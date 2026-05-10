"""Unit tests for validation schema checks."""

from datetime import UTC, datetime
from types import MappingProxyType

from aegis.aegis_constants import MAX_PARAMETER_DEPTH, MAX_PARAMETER_KEYS, MAX_STRING_LENGTH
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_json_types import FrozenJsonValue
from aegis.validation.aegis_schema_validator import validate_schema

# NOTE: Line numbers below reference schema_validator.py in the installed package.
# Lines guarded by RawIntent-constructor invariants are defensive only and are
# NOT tested via normal construction — they use the corrupted-object bypass
# documented in make_invalid_priority_intent above.


def make_context() -> ExecutionContext:
    """Return a deterministic context for schema validator tests."""
    return ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")


def make_intent(
    command: str = "stop",
    parameters: dict[str, object] | None = None,
    priority: int = 5,
) -> RawIntent:
    """Return a raw intent for schema validator tests."""
    return RawIntent(command, parameters or {}, "operator-1", priority, make_context())


def make_invalid_priority_intent(priority: int) -> RawIntent:
    """Return a RawIntent-shaped object with an invalid stored priority.

    CONTRACT-CORRUPTION DEFENSE TEST HELPER.
    This bypasses RawIntent.__init__ via object.__new__ to simulate a corrupted
    object that has evaded normal construction.  Under normal API usage
    RawIntent's constructor rejects bool priority before any validator is ever
    called, so the path exercised by this helper is unreachable through the
    public API.  The tests that use this helper verify that the schema validator
    still fails closed even when it receives an internally corrupted object.
    """
    intent = object.__new__(RawIntent)
    object.__setattr__(intent, "command", "stop")
    object.__setattr__(intent, "parameters", MappingProxyType({}))
    object.__setattr__(intent, "source_id", "operator-1")
    object.__setattr__(intent, "priority", priority)
    object.__setattr__(intent, "context", make_context())
    return intent


def nested_parameters(depth: int) -> dict[str, object]:
    """Return JSON parameters nested beyond a chosen container depth."""
    value: object = "leaf"
    for index in range(depth):
        value = {f"level_{index}": value}
    return {"root": value}


def violation_codes(intent: RawIntent) -> tuple[str, ...]:
    """Return schema violation codes for an intent."""
    return tuple(violation.code for violation in validate_schema(intent).violations)


def test_validate_schema_accepts_valid_raw_intent() -> None:
    """A valid RawIntent has no schema violations."""
    result = validate_schema(make_intent())

    assert result.is_valid is True
    assert result.violations == ()


def test_validate_schema_defense_rejects_corrupted_bool_priority() -> None:
    """CONTRACT-CORRUPTION DEFENSE: schema fails closed on bool priority in a corrupted object.

    Under normal API usage RawIntent.__init__ rejects bool priority at the
    boundary and the schema validator is never called with such an object.
    This test verifies defense-in-depth: the validator independently detects and
    rejects the violation even when called with a RawIntent-shaped corrupted
    object that bypassed construction.
    """
    intent = make_invalid_priority_intent(True)

    result = validate_schema(intent)

    assert result.is_valid is False
    assert violation_codes(intent) == ("bool_not_allowed_for_integer",)


def test_validate_schema_reports_max_depth_exceeded() -> None:
    """Parameters deeper than the explicit limit are rejected."""
    intent = make_intent(parameters=nested_parameters(MAX_PARAMETER_DEPTH + 1))

    assert "parameter_depth_exceeded" in violation_codes(intent)


def test_validate_schema_reports_max_key_count_exceeded() -> None:
    """Parameters with too many object keys are rejected."""
    parameters = {f"key_{index}": index for index in range(MAX_PARAMETER_KEYS + 1)}
    intent = make_intent(parameters=parameters)

    assert violation_codes(intent) == ("parameter_key_limit_exceeded",)


def test_validate_schema_reports_max_string_length_exceeded() -> None:
    """Parameter strings longer than the explicit limit are rejected."""
    intent = make_intent(parameters={"payload": "x" * (MAX_STRING_LENGTH + 1)})
    result = validate_schema(intent)

    assert result.is_valid is False
    assert result.violations[0].field == "parameters.payload"
    assert result.violations[0].code == "string_length_exceeded"


def test_validate_schema_reports_context_string_length_exceeded() -> None:
    """Context strings longer than the explicit limit are rejected."""
    context = ExecutionContext(
        "x" * (MAX_STRING_LENGTH + 1),
        datetime(2026, 5, 4, tzinfo=UTC),
        "policy-v1",
    )
    intent = RawIntent("stop", {}, "operator-1", 5, context)
    result = validate_schema(intent)

    assert result.is_valid is False
    assert result.violations[0].field == "context.request_id"
    assert result.violations[0].code == "string_length_exceeded"


def test_validate_schema_reports_context_policy_version_string_length_exceeded() -> None:
    """policy_version longer than the explicit limit is rejected."""
    context = ExecutionContext(
        "request-123",
        datetime(2026, 5, 4, tzinfo=UTC),
        "p" * (MAX_STRING_LENGTH + 1),
    )
    intent = RawIntent("stop", {}, "operator-1", 5, context)
    result = validate_schema(intent)

    assert result.is_valid is False
    assert any(v.field == "context.policy_version" for v in result.violations)
    assert any(v.code == "string_length_exceeded" for v in result.violations)


def test_validate_schema_reports_context_run_id_string_length_exceeded() -> None:
    """run_id longer than the explicit limit is rejected."""
    context = ExecutionContext(
        "request-123",
        datetime(2026, 5, 4, tzinfo=UTC),
        "policy-v1",
        run_id="r" * (MAX_STRING_LENGTH + 1),
    )
    intent = RawIntent("stop", {}, "operator-1", 5, context)
    result = validate_schema(intent)

    assert result.is_valid is False
    assert any(v.field == "context.run_id" for v in result.violations)
    assert any(v.code == "string_length_exceeded" for v in result.violations)


def test_validate_schema_reports_oversized_parameter_key() -> None:
    """An object key inside parameters that exceeds the string limit is rejected."""
    oversized_key = "k" * (MAX_STRING_LENGTH + 1)
    intent = make_intent(parameters={"nested": {oversized_key: "value"}})
    result = validate_schema(intent)

    assert result.is_valid is False
    assert any(v.code == "string_length_exceeded" for v in result.violations)


def test_validate_schema_uses_deterministic_violation_ordering() -> None:
    """Schema violations are emitted in a stable order.

    Uses a corrupted-object bypass (see make_invalid_priority_intent) to inject
    a bool priority alongside oversized parameters to verify ordering stability.
    """
    parameters: dict[str, FrozenJsonValue] = {
        "payload": "x" * (MAX_STRING_LENGTH + 1),
        **{f"key_{index}": index for index in range(MAX_PARAMETER_KEYS)},
    }
    intent = make_invalid_priority_intent(True)
    object.__setattr__(intent, "parameters", MappingProxyType(parameters))

    assert violation_codes(intent) == (
        "bool_not_allowed_for_integer",
        "parameter_key_limit_exceeded",
        "string_length_exceeded",
    )
