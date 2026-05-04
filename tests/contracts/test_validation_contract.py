"""Contract tests for validation result contracts."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.validation import ValidationResult, Violation


def make_intent() -> RawIntent:
    """Return a valid raw intent for validation contract tests."""
    context = ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")
    return RawIntent("inspect_area", {}, "operator-1", 5, context)


def make_violation() -> Violation:
    """Return a valid violation for validation contract tests."""
    return Violation(
        field="command",
        reason="command is not allowed",
        code="COMMAND_NOT_ALLOWED",
        layer="validation",
    )


def test_validation_result_accepts_valid_result_with_no_violations() -> None:
    """Valid results must carry an empty violation tuple."""
    result = ValidationResult(is_valid=True, intent=make_intent(), violations=[])

    assert result.is_valid is True
    assert result.violations == ()


def test_validation_result_accepts_invalid_result_with_violations() -> None:
    """Invalid results must carry at least one violation."""
    violation = make_violation()

    result = ValidationResult(is_valid=False, intent=make_intent(), violations=[violation])

    assert result.is_valid is False
    assert result.violations == (violation,)


def test_validation_result_rejects_valid_result_with_violations() -> None:
    """A valid result cannot also report violations."""
    with pytest.raises(ValueError, match="valid results"):
        ValidationResult(is_valid=True, intent=make_intent(), violations=[make_violation()])


def test_validation_result_rejects_invalid_result_without_violations() -> None:
    """An invalid result must include failure evidence."""
    with pytest.raises(ValueError, match="invalid results"):
        ValidationResult(is_valid=False, intent=make_intent(), violations=[])


@pytest.mark.parametrize(
    ("field", "reason", "code", "layer", "match"),
    [
        ("", "reason", "CODE", "validation", "field"),
        ("field", "", "CODE", "validation", "reason"),
        ("field", "reason", "", "validation", "code"),
        ("field", "reason", "CODE", "", "layer"),
    ],
)
def test_violation_fields_reject_empty_strings(
    field: str,
    reason: str,
    code: str,
    layer: str,
    match: str,
) -> None:
    """Violation metadata fields must be non-empty after stripping."""
    with pytest.raises(ValueError, match=match):
        Violation(field=field, reason=reason, code=code, layer=layer)


def test_violation_canonicalizes_whitespace_fields() -> None:
    """Violation metadata is stored in stripped canonical form."""
    violation = Violation(" command ", " reason ", " CODE ", " validation ")

    assert violation == Violation("command", "reason", "CODE", "validation")


def test_validation_result_stores_violations_as_tuple() -> None:
    """Incoming violation iterables are converted to tuples."""
    result = ValidationResult(False, make_intent(), [make_violation()])

    assert isinstance(result.violations, tuple)


def test_validation_result_is_immutable() -> None:
    """ValidationResult fields cannot be reassigned after construction."""
    result = ValidationResult(True, make_intent(), [])

    with pytest.raises(FrozenInstanceError):
        result.is_valid = False


def test_violation_is_immutable() -> None:
    """Violation fields cannot be reassigned after construction."""
    violation = make_violation()

    with pytest.raises(FrozenInstanceError):
        violation.reason = "changed"
