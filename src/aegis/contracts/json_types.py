"""JSON-compatible boundary types for Aegis contracts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from math import isfinite
from types import MappingProxyType
from typing import TypeGuard, cast

from aegis.governance.resource_bounds import validate_resource_bounds

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type FrozenJsonValue = JsonScalar | tuple[FrozenJsonValue, ...] | Mapping[str, FrozenJsonValue]


def is_json_value(value: object) -> TypeGuard[JsonValue]:
    """Return whether a value can be represented as JSON data.

    Args:
        value: Candidate value from an untrusted boundary.

    Returns:
        True when the value is composed only of JSON-compatible scalar,
        list, and object values. Non-finite floats are rejected.
    """
    if value is None:
        return True
    if isinstance(value, (bool, str, int)):
        return True
    if isinstance(value, float):
        return isfinite(value)
    if isinstance(value, list):
        items = cast(list[object], value)
        return all(is_json_value(item) for item in items)
    if isinstance(value, dict):
        items = cast(dict[object, object], value)
        return all(isinstance(key, str) and is_json_value(item) for key, item in items.items())
    return False


def freeze_json_value(value: JsonValue) -> FrozenJsonValue:
    """Return an immutable representation of a JSON-compatible value.

    Args:
        value: JSON-compatible value to freeze.

    Returns:
        A recursively frozen value. JSON lists become tuples. JSON objects
        become read-only mappings with deterministic key order.

    Raises:
        ValueError: If a value cannot be represented as JSON data.
    """
    if not is_json_value(value):
        raise ValueError("value must be JSON-compatible")
    validate_resource_bounds(value, label="JSON value")
    if isinstance(value, list):
        return tuple(freeze_json_value(item) for item in value)
    if isinstance(value, dict):
        return freeze_json_mapping(value)
    return value


def freeze_json_mapping(values: Mapping[str, JsonValue]) -> Mapping[str, FrozenJsonValue]:
    """Return an immutable JSON object mapping.

    Args:
        values: Candidate mapping with string keys and JSON-compatible values.

    Returns:
        A read-only mapping whose values are recursively frozen.

    Raises:
        ValueError: If any key is not a string or any value is not
            JSON-compatible.
    """
    return _freeze_json_items(values.items())


def _freeze_json_items(items: Iterable[tuple[object, object]]) -> Mapping[str, FrozenJsonValue]:
    """Return an immutable JSON object mapping from untrusted item pairs."""
    frozen_values: dict[str, FrozenJsonValue] = {}
    for key, value in items:
        if not isinstance(key, str):
            raise ValueError("JSON object keys must be strings")
        if not is_json_value(value):
            raise ValueError(f"value for JSON object key {key!r} must be JSON-compatible")
        validate_resource_bounds(value, label=f"JSON object key {key!r}")
        frozen_values[key] = freeze_json_value(value)

    validate_resource_bounds(frozen_values, label="JSON mapping")
    return MappingProxyType({key: frozen_values[key] for key in sorted(frozen_values)})
