"""Contract tests for the typed Aegis error hierarchy."""

from collections.abc import Mapping

import pytest

from aegis.aegis_errors import (
    AegisError,
    AuditError,
    ConfigurationError,
    GateError,
    PlanningError,
    PolicyAdmissionIntegrityError,
    ValidationError,
)


@pytest.mark.parametrize(
    "error_type",
    [
        AegisError,
        ValidationError,
        PlanningError,
        AuditError,
        GateError,
        ConfigurationError,
        PolicyAdmissionIntegrityError,
    ],
)
def test_each_error_subclass_can_be_constructed(error_type: type[AegisError]) -> None:
    """Every Aegis error type accepts explicit message, layer, and context."""
    error = error_type("failed", "validation", {"field": "command"})

    assert error.message == "failed"
    assert error.layer == "validation"
    assert error.context["field"] == "command"


@pytest.mark.parametrize("message", ["", "   ", "\t\n"])
def test_aegis_error_rejects_empty_message(message: str) -> None:
    """message must be non-empty after stripping whitespace."""
    with pytest.raises(ValueError, match="message"):
        AegisError(message, "validation", {})


@pytest.mark.parametrize("layer", ["", "   ", "\t\n"])
def test_aegis_error_rejects_empty_layer(layer: str) -> None:
    """layer must be non-empty after stripping whitespace."""
    with pytest.raises(ValueError, match="layer"):
        AegisError("failed", layer, {})


def test_aegis_error_rejects_non_json_context() -> None:
    """Error context must be a JSON-compatible object mapping."""
    with pytest.raises(ValueError, match="JSON-compatible"):
        AegisError("failed", "validation", {"bad": object()})


def test_aegis_error_protects_against_caller_context_mutation() -> None:
    """Caller mutations after construction do not alter stored error context."""
    context = {"detail": {"items": [1, {"status": "before"}]}}

    error = ValidationError("failed", "validation", context)
    context["detail"]["items"][1]["status"] = "after"

    detail = error.context["detail"]
    assert isinstance(detail, Mapping)
    items = detail["items"]
    assert isinstance(items, tuple)
    item = items[1]
    assert isinstance(item, Mapping)
    assert item["status"] == "before"


def test_aegis_error_context_is_read_only() -> None:
    """Stored error context mappings are immutable."""
    error = AegisError("failed", "validation", {"field": "command"})

    with pytest.raises(TypeError):
        error.context["field"] = "source_id"


def test_aegis_error_str_is_stable_and_includes_layer_and_message() -> None:
    """str(error) includes stable layer and message evidence."""
    first = ValidationError("failed", "validation", {"field": "command"})
    second = ValidationError("failed", "validation", {"field": "command"})

    assert str(first) == str(second)
    assert "validation" in str(first)
    assert "failed" in str(first)
