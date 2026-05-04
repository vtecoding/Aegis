"""Contract tests for JSON boundary types."""

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest

from aegis.contracts.json_types import (
    JsonValue,
    freeze_json_mapping,
    freeze_json_value,
    is_json_value,
)


@pytest.mark.parametrize("value", ["text", 1, 1.5, True, False, None])
def test_is_json_value_accepts_valid_json_scalars(value: object) -> None:
    """JSON scalars include strings, numbers, booleans, and null."""
    assert is_json_value(value) is True


def test_is_json_value_accepts_nested_lists_and_dicts() -> None:
    """Nested JSON arrays and objects are accepted when every value is compatible."""
    value = {"outer": [1, {"inner": "value", "enabled": True}, None]}

    assert is_json_value(value) is True


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_is_json_value_rejects_non_finite_floats(value: float) -> None:
    """NaN and infinity are not valid JSON numeric values."""
    assert is_json_value(value) is False


def test_is_json_value_rejects_non_string_dict_keys() -> None:
    """JSON object keys must be strings."""
    assert is_json_value({1: "value"}) is False


@pytest.mark.parametrize(
    "value",
    [
        ("tuple",),
        {"set-value"},
        b"bytes",
        object(),
        datetime(2026, 5, 4, tzinfo=UTC),
        Decimal("1.0"),
        Path("example.json"),
    ],
)
def test_is_json_value_rejects_non_json_values(value: object) -> None:
    """Non-JSON Python objects are rejected at the boundary."""
    assert is_json_value(value) is False


def test_freeze_json_value_rejects_invalid_value() -> None:
    """freeze_json_value rejects values that are not JSON-compatible."""
    with pytest.raises(ValueError, match="JSON-compatible"):
        freeze_json_value(cast(JsonValue, object()))


def test_freeze_json_mapping_rejects_non_string_key() -> None:
    """freeze_json_mapping rejects non-string keys at runtime."""
    values = cast(dict[str, JsonValue], {1: "value"})

    with pytest.raises(ValueError, match="keys must be strings"):
        freeze_json_mapping(values)
